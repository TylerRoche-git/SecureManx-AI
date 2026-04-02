// Command adapter-identity is the identity sensor adapter for security-brain.
// It consumes Kubernetes audit log events (via webhook or file) and detects
// identity anomalies such as unusual secret access, privilege escalation,
// token creation, pod exec, and policy bypass.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// k8sAuditEvent represents a Kubernetes audit log event.
type k8sAuditEvent struct {
	Kind       string            `json:"kind"`
	APIVersion string            `json:"apiVersion"`
	Level      string            `json:"level"`
	AuditID    string            `json:"auditID"`
	Stage      string            `json:"stage"`
	Verb       string            `json:"verb"`
	User       k8sUser           `json:"user"`
	SourceIPs  []string          `json:"sourceIPs"`
	ObjectRef  k8sObjectRef      `json:"objectRef"`
	Response   k8sResponseStatus `json:"responseStatus"`
	RequestURI string            `json:"requestURI"`
	Timestamp  string            `json:"stageTimestamp"`
}

type k8sUser struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

type k8sObjectRef struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	APIGroup    string `json:"apiGroup"`
	APIVersion  string `json:"apiVersion"`
	Subresource string `json:"subresource"`
}

type k8sResponseStatus struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// k8sAuditEventList represents a Kubernetes EventList that may be sent in
// webhook mode, wrapping multiple audit events.
type k8sAuditEventList struct {
	Kind       string          `json:"kind"`
	APIVersion string          `json:"apiVersion"`
	Items      []k8sAuditEvent `json:"items"`
}

// identityAnalyzer maintains state for identity anomaly detection.
type identityAnalyzer struct {
	bus         *transport.EventBus
	knownAccess map[string]map[string]bool // SA -> set of "namespace/resource/name" previously accessed
	mu          sync.Mutex
}

func main() {
	slog.Info("adapter-identity starting")

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

	analyzer := &identityAnalyzer{
		bus:         bus,
		knownAccess: make(map[string]map[string]bool),
	}

	addr := envOrDefault("IDENTITY_WEBHOOK_ADDR", ":8092")
	mux := http.NewServeMux()
	mux.HandleFunc("/audit", analyzer.handleAudit(ctx))
	mux.HandleFunc("/healthz", handleHealthz)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("adapter-identity webhook server starting", "addr", addr)
		if httpErr := server.ListenAndServe(); httpErr != nil && httpErr != http.ErrServerClosed {
			slog.Error("webhook server error", "error", httpErr)
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if shutErr := server.Shutdown(shutdownCtx); shutErr != nil {
		slog.Error("webhook server shutdown error", "error", shutErr)
	}

	wg.Wait()
	slog.Info("adapter-identity stopped")
}

// ---------------------------------------------------------------------------
// HTTP handler for /audit
// ---------------------------------------------------------------------------

func (a *identityAnalyzer) handleAudit(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20)) // 5 MB max
		if err != nil {
			slog.Error("failed to read audit body", "error", err)
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Attempt to parse as an EventList first (K8s webhook sends lists).
		var eventList k8sAuditEventList
		if err := json.Unmarshal(body, &eventList); err == nil && eventList.Kind == "EventList" && len(eventList.Items) > 0 {
			processed := 0
			for _, auditEvent := range eventList.Items {
				events := a.analyze(auditEvent)
				for _, event := range events {
					if emitErr := a.bus.Emit(ctx, event); emitErr != nil {
						slog.Error("failed to emit identity event",
							"event_id", event.EventID,
							"error", emitErr,
						)
					}
					slog.Info("event emitted from identity analyzer",
						"event_id", event.EventID,
						"signal_class", event.SignalClass,
						"severity", event.Severity,
					)
				}
				processed++
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"processed":%d}`, processed)
			return
		}

		// Attempt to parse as a single Event.
		var auditEvent k8sAuditEvent
		if err := json.Unmarshal(body, &auditEvent); err != nil {
			slog.Error("failed to parse k8s audit event JSON", "error", err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		events := a.analyze(auditEvent)
		for _, event := range events {
			if emitErr := a.bus.Emit(ctx, event); emitErr != nil {
				slog.Error("failed to emit identity event",
					"event_id", event.EventID,
					"error", emitErr,
				)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			slog.Info("event emitted from identity analyzer",
				"event_id", event.EventID,
				"signal_class", event.SignalClass,
				"severity", event.Severity,
			)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"processed":1}`)
	}
}

// ---------------------------------------------------------------------------
// Detection rules
// ---------------------------------------------------------------------------

// analyze runs all detection rules against a single K8s audit event and
// returns any security events that should be emitted.
func (a *identityAnalyzer) analyze(audit k8sAuditEvent) []eventschema.Event {
	var events []eventschema.Event

	if e, ok := a.detectUnusualSecretAccess(audit); ok {
		events = append(events, e)
	}
	if e, ok := a.detectPrivilegeEscalation(audit); ok {
		events = append(events, e)
	}
	if e, ok := a.detectTokenCreation(audit); ok {
		events = append(events, e)
	}
	if e, ok := a.detectPodExec(audit); ok {
		events = append(events, e)
	}
	if e, ok := a.detectPolicyBypass(audit); ok {
		events = append(events, e)
	}

	return events
}

// detectUnusualSecretAccess flags when a service account accesses a secret
// it has never accessed before (tracked in the knownAccess map).
func (a *identityAnalyzer) detectUnusualSecretAccess(audit k8sAuditEvent) (eventschema.Event, bool) {
	if audit.ObjectRef.Resource != "secrets" {
		return eventschema.Event{}, false
	}
	if audit.Verb != "get" && audit.Verb != "list" && audit.Verb != "watch" {
		return eventschema.Event{}, false
	}
	// Only flag service accounts, not human users.
	if !strings.HasPrefix(audit.User.Username, "system:serviceaccount:") {
		return eventschema.Event{}, false
	}
	// Only flag successful requests.
	if audit.Response.Code < 200 || audit.Response.Code >= 300 {
		return eventschema.Event{}, false
	}

	sa := audit.User.Username
	resourceKey := fmt.Sprintf("%s/%s/%s", audit.ObjectRef.Namespace, audit.ObjectRef.Resource, audit.ObjectRef.Name)

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.knownAccess[sa] == nil {
		a.knownAccess[sa] = make(map[string]bool)
	}

	if a.knownAccess[sa][resourceKey] {
		// Already known access pattern; not anomalous.
		return eventschema.Event{}, false
	}

	// Record this access for future reference.
	a.knownAccess[sa][resourceKey] = true

	// First-time access to this secret by this SA: flag it.
	event := newIdentityEvent()
	event.SignalClass = "unusual-secret-access"
	event.Severity = eventschema.SeverityHigh
	event.Confidence = 0.6
	event.IdentityID = sa
	event.Observables["service_account"] = sa
	event.Observables["verb"] = audit.Verb
	event.Observables["namespace"] = audit.ObjectRef.Namespace
	event.Observables["secret_name"] = audit.ObjectRef.Name
	event.Observables["resource_key"] = resourceKey
	populateAuditObservables(&event, audit)
	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("k8s:audit:%s", audit.AuditID),
	)
	event.SuggestedActions = append(event.SuggestedActions,
		fmt.Sprintf("Verify that %s is authorized to access secret %s/%s", sa, audit.ObjectRef.Namespace, audit.ObjectRef.Name),
		"Review RBAC bindings for this service account",
	)

	return event, true
}

// detectPrivilegeEscalation flags create/update operations on ClusterRoleBindings,
// ClusterRoles, RoleBindings, and Roles which could indicate privilege escalation.
func (a *identityAnalyzer) detectPrivilegeEscalation(audit k8sAuditEvent) (eventschema.Event, bool) {
	privResources := map[string]bool{
		"clusterrolebindings": true,
		"clusterroles":        true,
		"rolebindings":        true,
		"roles":               true,
	}
	if !privResources[audit.ObjectRef.Resource] {
		return eventschema.Event{}, false
	}
	if audit.Verb != "create" && audit.Verb != "update" && audit.Verb != "patch" {
		return eventschema.Event{}, false
	}
	if audit.Response.Code < 200 || audit.Response.Code >= 300 {
		return eventschema.Event{}, false
	}

	event := newIdentityEvent()
	event.SignalClass = "privilege-escalation"
	event.Severity = eventschema.SeverityCritical
	event.Confidence = 0.7
	event.IdentityID = audit.User.Username
	event.Observables["user"] = audit.User.Username
	event.Observables["verb"] = audit.Verb
	event.Observables["resource"] = audit.ObjectRef.Resource
	event.Observables["name"] = audit.ObjectRef.Name
	event.Observables["namespace"] = audit.ObjectRef.Namespace
	populateAuditObservables(&event, audit)
	event.BlastRadiusHint = eventschema.BlastCluster
	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("k8s:audit:%s", audit.AuditID),
	)
	event.SuggestedActions = append(event.SuggestedActions,
		fmt.Sprintf("Review %s of %s/%s by %s", audit.Verb, audit.ObjectRef.Resource, audit.ObjectRef.Name, audit.User.Username),
		"Verify this RBAC change is authorized and expected",
	)

	return event, true
}

// detectTokenCreation flags creation of token requests or service-account-token
// secrets, which can be used to generate long-lived credentials.
func (a *identityAnalyzer) detectTokenCreation(audit k8sAuditEvent) (eventschema.Event, bool) {
	isTokenRequest := audit.ObjectRef.Resource == "serviceaccounts" && audit.ObjectRef.Subresource == "token"
	isTokenSecret := audit.ObjectRef.Resource == "secrets" && audit.Verb == "create"

	if !isTokenRequest && !isTokenSecret {
		return eventschema.Event{}, false
	}
	if audit.Verb != "create" {
		return eventschema.Event{}, false
	}
	if audit.Response.Code < 200 || audit.Response.Code >= 300 {
		return eventschema.Event{}, false
	}

	event := newIdentityEvent()
	event.SignalClass = "token-creation"
	event.Severity = eventschema.SeverityHigh
	event.Confidence = 0.6
	event.IdentityID = audit.User.Username
	event.Observables["user"] = audit.User.Username
	event.Observables["verb"] = audit.Verb
	event.Observables["resource"] = audit.ObjectRef.Resource
	event.Observables["subresource"] = audit.ObjectRef.Subresource
	event.Observables["name"] = audit.ObjectRef.Name
	event.Observables["namespace"] = audit.ObjectRef.Namespace
	populateAuditObservables(&event, audit)
	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("k8s:audit:%s", audit.AuditID),
	)
	event.SuggestedActions = append(event.SuggestedActions,
		fmt.Sprintf("Investigate token creation by %s for %s/%s", audit.User.Username, audit.ObjectRef.Namespace, audit.ObjectRef.Name),
		"Verify this is not an attempt to create persistent credentials",
	)

	return event, true
}

// detectPodExec flags exec or attach operations on pods, which provide
// direct shell access to running containers.
func (a *identityAnalyzer) detectPodExec(audit k8sAuditEvent) (eventschema.Event, bool) {
	if audit.ObjectRef.Resource != "pods" {
		return eventschema.Event{}, false
	}
	if audit.ObjectRef.Subresource != "exec" && audit.ObjectRef.Subresource != "attach" {
		return eventschema.Event{}, false
	}
	if audit.Verb != "create" {
		return eventschema.Event{}, false
	}

	event := newIdentityEvent()
	event.SignalClass = "pod-exec"
	event.Severity = eventschema.SeverityHigh
	event.Confidence = 0.7
	event.IdentityID = audit.User.Username
	event.WorkloadID = audit.ObjectRef.Name
	event.Observables["user"] = audit.User.Username
	event.Observables["verb"] = audit.Verb
	event.Observables["subresource"] = audit.ObjectRef.Subresource
	event.Observables["pod_name"] = audit.ObjectRef.Name
	event.Observables["namespace"] = audit.ObjectRef.Namespace
	populateAuditObservables(&event, audit)
	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("k8s:audit:%s", audit.AuditID),
	)
	event.SuggestedActions = append(event.SuggestedActions,
		fmt.Sprintf("Investigate pod %s by %s into %s/%s", audit.ObjectRef.Subresource, audit.User.Username, audit.ObjectRef.Namespace, audit.ObjectRef.Name),
		"Verify this interactive session is authorized",
	)

	return event, true
}

// detectPolicyBypass flags deletion of security policies (NetworkPolicies,
// PodSecurityPolicies, ResourceQuotas) which could weaken cluster security.
func (a *identityAnalyzer) detectPolicyBypass(audit k8sAuditEvent) (eventschema.Event, bool) {
	policyResources := map[string]bool{
		"networkpolicies":     true,
		"podsecuritypolicies": true,
		"resourcequotas":      true,
	}
	if !policyResources[audit.ObjectRef.Resource] {
		return eventschema.Event{}, false
	}
	if audit.Verb != "delete" {
		return eventschema.Event{}, false
	}
	if audit.Response.Code < 200 || audit.Response.Code >= 300 {
		return eventschema.Event{}, false
	}

	event := newIdentityEvent()
	event.SignalClass = "policy-bypass"
	event.Severity = eventschema.SeverityCritical
	event.Confidence = 0.8
	event.IdentityID = audit.User.Username
	event.Observables["user"] = audit.User.Username
	event.Observables["verb"] = audit.Verb
	event.Observables["resource"] = audit.ObjectRef.Resource
	event.Observables["name"] = audit.ObjectRef.Name
	event.Observables["namespace"] = audit.ObjectRef.Namespace
	populateAuditObservables(&event, audit)
	event.BlastRadiusHint = eventschema.BlastNamespace
	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("k8s:audit:%s", audit.AuditID),
	)
	event.SuggestedActions = append(event.SuggestedActions,
		fmt.Sprintf("Investigate deletion of %s/%s by %s", audit.ObjectRef.Resource, audit.ObjectRef.Name, audit.User.Username),
		"Consider restoring the security policy immediately",
	)

	return event, true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newIdentityEvent creates a new Event pre-filled with identity source metadata.
func newIdentityEvent() eventschema.Event {
	event := eventschema.NewEvent()
	event.SourceType = eventschema.SourceIdentity
	event.SourceVendor = eventschema.VendorK8sAudit
	event.AssetType = eventschema.AssetInternalService
	event.BlastRadiusHint = eventschema.BlastService
	return event
}

// populateAuditObservables fills common audit fields into event observables.
func populateAuditObservables(event *eventschema.Event, audit k8sAuditEvent) {
	if len(audit.SourceIPs) > 0 {
		event.Observables["source_ips"] = strings.Join(audit.SourceIPs, ",")
	}
	if audit.AuditID != "" {
		event.Observables["audit_id"] = audit.AuditID
	}
	if len(audit.User.Groups) > 0 {
		event.Observables["user_groups"] = strings.Join(audit.User.Groups, ",")
	}
	event.Observables["response_code"] = audit.Response.Code
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
