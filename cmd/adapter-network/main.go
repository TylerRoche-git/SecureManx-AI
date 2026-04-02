// Command adapter-network is the network telemetry adapter for security-brain.
// It ingests network flow records (newline-delimited JSON) from a file, stdin,
// or HTTP POST and detects east-west anomalies such as beaconing, data
// exfiltration, port scanning, and lateral movement.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// flowRecord represents a single network flow observation.
type flowRecord struct {
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Bytes     int64  `json:"bytes"`
	Direction string `json:"direction"`
}

// networkAnalyzer maintains state for sliding-window flow analysis.
type networkAnalyzer struct {
	bus                 *transport.EventBus
	windowSize          time.Duration
	flows               map[string][]flowRecord // keyed by src_ip
	mu                  sync.Mutex
	beaconThreshold     int   // min flows to same dest to flag beaconing
	exfilBytesThreshold int64 // bytes threshold for exfiltration alert
	scanPortThreshold   int   // distinct ports to flag scanning
	lateralIPThreshold  int   // distinct dest IPs for lateral movement
}

func main() {
	slog.Info("adapter-network starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	natsURL := envOrDefault("NATS_URL", "nats://localhost:4222")

	client, err := transport.NewNATSClient(natsURL)
	if err != nil {
		slog.Error("failed to connect to NATS", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	bus := transport.NewEventBus(client)

	windowMinutes := envOrDefault("WINDOW_MINUTES", "5")
	windowDur := 5 * time.Minute
	if parsed, parseErr := time.ParseDuration(windowMinutes + "m"); parseErr == nil {
		windowDur = parsed
	}

	analyzer := &networkAnalyzer{
		bus:                 bus,
		windowSize:          windowDur,
		flows:               make(map[string][]flowRecord),
		beaconThreshold:     intEnvOrDefault("BEACON_THRESHOLD", 5),
		exfilBytesThreshold: int64EnvOrDefault("EXFIL_BYTES_THRESHOLD", 10_000_000), // 10 MB
		scanPortThreshold:   intEnvOrDefault("SCAN_PORT_THRESHOLD", 20),
		lateralIPThreshold:  intEnvOrDefault("LATERAL_IP_THRESHOLD", 10),
	}

	mode := envOrDefault("NETWORK_MODE", "file")
	slog.Info("adapter-network mode selected", "mode", mode)

	var wg sync.WaitGroup

	// Start the HTTP server for programmatic flow ingestion in all modes.
	addr := envOrDefault("NETWORK_HTTP_ADDR", ":8091")
	mux := http.NewServeMux()
	mux.HandleFunc("/flows", analyzer.handleFlows(ctx))
	mux.HandleFunc("/healthz", handleHealthz)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("adapter-network HTTP server starting", "addr", addr)
		if httpErr := server.ListenAndServe(); httpErr != nil && httpErr != http.ErrServerClosed {
			slog.Error("http server error", "error", httpErr)
		}
	}()

	switch mode {
	case "file":
		filePath := envOrDefault("FLOW_FILE", "")
		if filePath == "" || filePath == "-" {
			slog.Info("reading flow records from stdin")
			wg.Add(1)
			go func() {
				defer wg.Done()
				analyzer.ingestFromReader(ctx, os.Stdin)
			}()
		} else {
			slog.Info("reading flow records from file", "path", filePath)
			wg.Add(1)
			go func() {
				defer wg.Done()
				analyzer.ingestFromFile(ctx, filePath)
			}()
		}
	default:
		slog.Info("adapter-network running in HTTP-only mode, POST flows to /flows")
	}

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if shutErr := server.Shutdown(shutdownCtx); shutErr != nil {
		slog.Error("http server shutdown error", "error", shutErr)
	}

	wg.Wait()
	slog.Info("adapter-network stopped")
}

// ---------------------------------------------------------------------------
// HTTP handler for /flows
// ---------------------------------------------------------------------------

func (a *networkAnalyzer) handleFlows(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20)) // 5 MB max
		if err != nil {
			slog.Error("failed to read flows body", "error", err)
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Accept either a JSON array of flow records or newline-delimited JSON.
		var records []flowRecord
		if len(body) > 0 && body[0] == '[' {
			if jsonErr := json.Unmarshal(body, &records); jsonErr != nil {
				slog.Error("failed to parse flow records array", "error", jsonErr)
				http.Error(w, "invalid JSON array", http.StatusBadRequest)
				return
			}
		} else {
			lines := strings.Split(strings.TrimSpace(string(body)), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var rec flowRecord
				if jsonErr := json.Unmarshal([]byte(line), &rec); jsonErr != nil {
					slog.Warn("skipping malformed flow line", "error", jsonErr)
					continue
				}
				records = append(records, rec)
			}
		}

		ingested := 0
		for _, rec := range records {
			a.processFlow(ctx, rec)
			ingested++
		}

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"ingested":%d}`, ingested)
	}
}

// ---------------------------------------------------------------------------
// File/stdin ingestion
// ---------------------------------------------------------------------------

func (a *networkAnalyzer) ingestFromFile(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		slog.Error("failed to open flow file", "path", path, "error", err)
		return
	}
	defer f.Close()
	a.ingestFromReader(ctx, f)
}

func (a *networkAnalyzer) ingestFromReader(ctx context.Context, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), 1<<20) // up to 1 MB lines
	lineNum := 0

	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec flowRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			slog.Warn("skipping malformed flow record", "line", lineNum, "error", err)
			continue
		}
		a.processFlow(ctx, rec)
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		slog.Error("error reading flow records", "error", err)
	}
	slog.Info("finished reading flow records", "total_lines", lineNum)
}

// ---------------------------------------------------------------------------
// Core analysis logic
// ---------------------------------------------------------------------------

// processFlow ingests a single flow record, adds it to the window,
// prunes stale entries, and runs all detection heuristics.
func (a *networkAnalyzer) processFlow(ctx context.Context, rec flowRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.flows[rec.SrcIP] = append(a.flows[rec.SrcIP], rec)

	// Prune flows outside the sliding window.
	a.pruneFlows(rec.SrcIP)

	srcFlows := a.flows[rec.SrcIP]

	a.detectBeaconing(ctx, rec.SrcIP, srcFlows)
	a.detectExfiltration(ctx, rec.SrcIP, srcFlows)
	a.detectPortScan(ctx, rec.SrcIP, srcFlows)
	a.detectLateralMovement(ctx, rec.SrcIP, srcFlows)
}

// pruneFlows removes flow records older than the sliding window for a given source IP.
func (a *networkAnalyzer) pruneFlows(srcIP string) {
	flows := a.flows[srcIP]
	if len(flows) == 0 {
		return
	}

	cutoff := time.Now().Add(-a.windowSize)
	kept := flows[:0]
	for _, f := range flows {
		t := parseTimestamp(f.Timestamp)
		if !t.Before(cutoff) {
			kept = append(kept, f)
		}
	}
	a.flows[srcIP] = kept
}

// detectBeaconing looks for regular-interval connections from a source IP
// to the same destination. Low jitter in inter-flow timing indicates
// automated beaconing (C2 callback pattern).
func (a *networkAnalyzer) detectBeaconing(ctx context.Context, srcIP string, flows []flowRecord) {
	// Group flows by destination IP.
	destFlows := make(map[string][]time.Time)
	for _, f := range flows {
		t := parseTimestamp(f.Timestamp)
		if !t.IsZero() {
			destFlows[f.DstIP] = append(destFlows[f.DstIP], t)
		}
	}

	for dstIP, timestamps := range destFlows {
		if len(timestamps) < a.beaconThreshold {
			continue
		}

		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i].Before(timestamps[j]) })

		// Compute inter-flow intervals.
		var intervals []float64
		for i := 1; i < len(timestamps); i++ {
			intervals = append(intervals, timestamps[i].Sub(timestamps[i-1]).Seconds())
		}

		if len(intervals) < 2 {
			continue
		}

		mean, stddev := meanAndStddev(intervals)
		if mean <= 0 {
			continue
		}

		// Coefficient of variation (CV): stddev/mean. Low CV = regular interval.
		cv := stddev / mean
		if cv < 0.3 { // threshold: less than 30% variation = beaconing
			confidence := mapCVToConfidence(cv)
			event := newNetworkEvent()
			event.SignalClass = "beaconing"
			event.Severity = eventschema.SeverityHigh
			event.Confidence = confidence
			event.Observables["src_ip"] = srcIP
			event.Observables["dst_ip"] = dstIP
			event.Observables["flow_count"] = len(timestamps)
			event.Observables["mean_interval_sec"] = fmt.Sprintf("%.2f", mean)
			event.Observables["stddev_interval_sec"] = fmt.Sprintf("%.2f", stddev)
			event.Observables["coefficient_of_variation"] = fmt.Sprintf("%.4f", cv)
			event.EvidenceRefs = append(event.EvidenceRefs,
				fmt.Sprintf("network:beacon:%s->%s", srcIP, dstIP),
			)
			event.SuggestedActions = append(event.SuggestedActions,
				fmt.Sprintf("Investigate regular-interval traffic from %s to %s", srcIP, dstIP),
				"Check for C2 callback patterns",
			)
			emitEvent(ctx, a.bus, event)
		}
	}
}

// detectExfiltration flags large outbound byte counts to external (non-RFC1918) IPs.
func (a *networkAnalyzer) detectExfiltration(ctx context.Context, srcIP string, flows []flowRecord) {
	// Aggregate bytes per external destination.
	destBytes := make(map[string]int64)
	for _, f := range flows {
		if isExternalIP(f.DstIP) && (f.Direction == "outbound" || f.Direction == "egress" || f.Direction == "") {
			destBytes[f.DstIP] += f.Bytes
		}
	}

	for dstIP, totalBytes := range destBytes {
		if totalBytes >= a.exfilBytesThreshold {
			confidence := 0.6
			// Scale confidence by how far over threshold.
			ratio := float64(totalBytes) / float64(a.exfilBytesThreshold)
			if ratio > 5 {
				confidence = 0.9
			} else if ratio > 2 {
				confidence = 0.75
			}

			event := newNetworkEvent()
			event.SignalClass = "data-exfiltration"
			event.Severity = eventschema.SeverityCritical
			event.Confidence = confidence
			event.Observables["src_ip"] = srcIP
			event.Observables["dst_ip"] = dstIP
			event.Observables["total_bytes"] = totalBytes
			event.Observables["threshold_bytes"] = a.exfilBytesThreshold
			event.EvidenceRefs = append(event.EvidenceRefs,
				fmt.Sprintf("network:exfil:%s->%s:%dB", srcIP, dstIP, totalBytes),
			)
			event.SuggestedActions = append(event.SuggestedActions,
				fmt.Sprintf("Block or investigate large data transfer from %s to external %s (%d bytes)", srcIP, dstIP, totalBytes),
			)
			emitEvent(ctx, a.bus, event)
		}
	}
}

// detectPortScan flags a source IP connecting to many distinct destination ports
// in a short time window, which is characteristic of port scanning.
func (a *networkAnalyzer) detectPortScan(ctx context.Context, srcIP string, flows []flowRecord) {
	// Collect distinct destination ports per destination IP.
	dstPorts := make(map[string]map[int]bool)
	for _, f := range flows {
		if _, ok := dstPorts[f.DstIP]; !ok {
			dstPorts[f.DstIP] = make(map[int]bool)
		}
		dstPorts[f.DstIP][f.DstPort] = true
	}

	// Also check total distinct ports across all destinations.
	allPorts := make(map[int]bool)
	for _, f := range flows {
		allPorts[f.DstPort] = true
	}

	if len(allPorts) >= a.scanPortThreshold {
		confidence := 0.6
		if len(allPorts) >= a.scanPortThreshold*3 {
			confidence = 0.9
		} else if len(allPorts) >= a.scanPortThreshold*2 {
			confidence = 0.75
		}

		event := newNetworkEvent()
		event.SignalClass = "port-scan"
		event.Severity = eventschema.SeverityHigh
		event.Confidence = confidence
		event.Observables["src_ip"] = srcIP
		event.Observables["distinct_ports"] = len(allPorts)
		event.Observables["threshold"] = a.scanPortThreshold
		event.Observables["distinct_destinations"] = len(dstPorts)
		event.EvidenceRefs = append(event.EvidenceRefs,
			fmt.Sprintf("network:portscan:%s:%d_ports", srcIP, len(allPorts)),
		)
		event.SuggestedActions = append(event.SuggestedActions,
			fmt.Sprintf("Investigate port scanning activity from %s (%d distinct ports)", srcIP, len(allPorts)),
		)
		emitEvent(ctx, a.bus, event)
	}
}

// detectLateralMovement flags a source IP connecting to many distinct internal
// destination IPs, which suggests lateral movement within the network.
func (a *networkAnalyzer) detectLateralMovement(ctx context.Context, srcIP string, flows []flowRecord) {
	internalDests := make(map[string]bool)
	for _, f := range flows {
		if !isExternalIP(f.DstIP) && f.DstIP != srcIP {
			internalDests[f.DstIP] = true
		}
	}

	if len(internalDests) >= a.lateralIPThreshold {
		confidence := 0.5
		ratio := float64(len(internalDests)) / float64(a.lateralIPThreshold)
		if ratio > 3 {
			confidence = 0.85
		} else if ratio > 1.5 {
			confidence = 0.7
		}

		event := newNetworkEvent()
		event.SignalClass = "lateral-movement"
		event.Severity = eventschema.SeverityCritical
		event.Confidence = confidence
		event.Observables["src_ip"] = srcIP
		event.Observables["distinct_internal_dests"] = len(internalDests)
		event.Observables["threshold"] = a.lateralIPThreshold
		event.BlastRadiusHint = eventschema.BlastNamespace
		event.EvidenceRefs = append(event.EvidenceRefs,
			fmt.Sprintf("network:lateral:%s:%d_dests", srcIP, len(internalDests)),
		)
		event.SuggestedActions = append(event.SuggestedActions,
			fmt.Sprintf("Investigate lateral movement from %s to %d internal hosts", srcIP, len(internalDests)),
			"Consider network segmentation enforcement",
		)
		emitEvent(ctx, a.bus, event)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newNetworkEvent() eventschema.Event {
	event := eventschema.NewEvent()
	event.SourceType = eventschema.SourceNetwork
	event.SourceVendor = eventschema.VendorHubble
	event.AssetType = eventschema.AssetInternalService
	event.BlastRadiusHint = eventschema.BlastService
	return event
}

func emitEvent(ctx context.Context, bus *transport.EventBus, event eventschema.Event) {
	if err := bus.Emit(ctx, event); err != nil {
		slog.Error("failed to emit network event",
			"event_id", event.EventID,
			"signal_class", event.SignalClass,
			"error", err,
		)
		return
	}
	slog.Info("event emitted from network analyzer",
		"event_id", event.EventID,
		"signal_class", event.SignalClass,
		"severity", event.Severity,
		"confidence", event.Confidence,
	)
}

// parseTimestamp attempts to parse a timestamp string in multiple common formats.
func parseTimestamp(s string) time.Time {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		time.DateTime,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// isExternalIP returns true if the IP is not in RFC1918/RFC6598 private ranges.
func isExternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []struct {
		network string
	}{
		{"10.0.0.0/8"},
		{"172.16.0.0/12"},
		{"192.168.0.0/16"},
		{"100.64.0.0/10"},  // RFC6598 CGN
		{"127.0.0.0/8"},    // loopback
		{"169.254.0.0/16"}, // link-local
		{"fc00::/7"},       // IPv6 ULA
		{"::1/128"},        // IPv6 loopback
		{"fe80::/10"},      // IPv6 link-local
	}

	for _, pr := range privateRanges {
		_, cidr, err := net.ParseCIDR(pr.network)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return false
		}
	}
	return true
}

// meanAndStddev computes the mean and population standard deviation of a float slice.
func meanAndStddev(vals []float64) (float64, float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))

	variance := 0.0
	for _, v := range vals {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(vals))
	return mean, math.Sqrt(variance)
}

// mapCVToConfidence converts a coefficient of variation to a confidence score.
// Lower CV (more regular) = higher confidence of beaconing.
func mapCVToConfidence(cv float64) float64 {
	if cv < 0.05 {
		return 0.95 // extremely regular
	}
	if cv < 0.1 {
		return 0.85
	}
	if cv < 0.2 {
		return 0.7
	}
	return 0.55 // borderline
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// intEnvOrDefault parses an integer from the named environment variable,
// falling back to the default value on error or if unset.
func intEnvOrDefault(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return fallback
	}
	return n
}

// int64EnvOrDefault parses an int64 from the named environment variable,
// falling back to the default value on error or if unset.
func int64EnvOrDefault(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var n int64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return fallback
	}
	return n
}
