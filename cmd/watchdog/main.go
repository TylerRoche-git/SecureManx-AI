// Command watchdog is an external integrity monitor for the security-brain
// control plane. It runs as a separate process with a deliberately minimal
// attack surface: no NATS connection, no database, no API. Its sole purpose
// is to detect a compromised or unresponsive control plane and take corrective
// action (kill the process, alert operators).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/security-brain/security-brain/internal/sentinel"
)

func main() {
	slog.Info("watchdog starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Configuration from environment variables.
	controlPlaneBinary := envOrDefault("CONTROL_PLANE_BINARY", "/usr/local/bin/control-plane")
	controlPlaneHealthURL := envOrDefault("CONTROL_PLANE_HEALTH_URL", "http://localhost:8080/healthz")
	controlPlanePIDFile := envOrDefault("CONTROL_PLANE_PID_FILE", "/var/run/security-brain/control-plane.pid")
	checkInterval := 15 * time.Second
	maxMissedHeartbeats := 3

	slog.Info("watchdog configuration",
		"binary", controlPlaneBinary,
		"health_url", controlPlaneHealthURL,
		"pid_file", controlPlanePIDFile,
		"check_interval", checkInterval,
		"max_missed_heartbeats", maxMissedHeartbeats,
	)

	// Compute initial expected hash of the control plane binary.
	expectedHash, err := sentinel.HashFile(controlPlaneBinary)
	if err != nil {
		slog.Warn("watchdog: failed to hash control plane binary, binary integrity checks will be skipped until the binary is available",
			"path", controlPlaneBinary, "error", err)
	} else {
		slog.Info("watchdog: control plane binary hash recorded",
			"path", controlPlaneBinary, "sha256", expectedHash)
	}

	missedHeartbeats := 0

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("watchdog stopped")
			return
		case <-ticker.C:
			// Check 1: Is the control plane alive?
			alive := checkHealth(controlPlaneHealthURL)
			if !alive {
				missedHeartbeats++
				slog.Warn("watchdog: control plane health check failed",
					"missed", missedHeartbeats,
					"max", maxMissedHeartbeats,
				)
			} else {
				if missedHeartbeats > 0 {
					slog.Info("watchdog: control plane health recovered",
						"previously_missed", missedHeartbeats)
				}
				missedHeartbeats = 0
			}

			// Check 2: Is the binary unmodified?
			if expectedHash != "" {
				currentHash, hashErr := sentinel.HashFile(controlPlaneBinary)
				if hashErr != nil {
					slog.Warn("watchdog: failed to re-hash control plane binary",
						"path", controlPlaneBinary, "error", hashErr)
				} else if currentHash != expectedHash {
					slog.Error("CRITICAL: control plane binary has been modified",
						"path", controlPlaneBinary,
						"expected", expectedHash,
						"actual", currentHash,
					)
					killControlPlane(controlPlanePIDFile)
					alertOperator("control plane binary tampered: expected " + expectedHash + " got " + currentHash)
				}
			}

			// Check 3: Too many missed heartbeats?
			if missedHeartbeats >= maxMissedHeartbeats {
				slog.Error("CRITICAL: control plane unresponsive, killing",
					"missed_heartbeats", missedHeartbeats,
					"threshold", maxMissedHeartbeats,
				)
				killControlPlane(controlPlanePIDFile)
				alertOperator(fmt.Sprintf("control plane unresponsive after %d missed heartbeats", missedHeartbeats))
			}
		}
	}
}

// checkHealth performs an HTTP GET against the control plane's health endpoint.
// It returns true only if the response status is 200 OK.
func checkHealth(url string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		slog.Debug("watchdog: health check request failed", "url", url, "error", err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// killControlPlane reads the PID from the given file and sends termination
// signals to the control plane process. It first sends SIGTERM (or taskkill
// on Windows) and, if the process is still alive after 5 seconds, escalates
// to SIGKILL (or forceful taskkill).
func killControlPlane(pidFile string) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		slog.Error("watchdog: failed to read PID file, cannot kill control plane",
			"pid_file", pidFile, "error", err)
		return
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		slog.Error("watchdog: invalid PID in file",
			"pid_file", pidFile, "content", pidStr, "error", err)
		return
	}

	slog.Warn("watchdog: sending termination signal to control plane", "pid", pid)

	if runtime.GOOS == "windows" {
		killControlPlaneWindows(pid)
	} else {
		killControlPlaneUnix(pid)
	}
}

// killControlPlaneUnix sends SIGTERM followed by SIGKILL after a grace period.
func killControlPlaneUnix(pid int) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		slog.Error("watchdog: failed to find process", "pid", pid, "error", err)
		return
	}

	// Attempt graceful shutdown with SIGTERM.
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		slog.Error("watchdog: SIGTERM failed, process may already be dead",
			"pid", pid, "error", err)
		return
	}
	slog.Info("watchdog: SIGTERM sent, waiting for graceful shutdown", "pid", pid)

	// Wait up to 5 seconds, then force kill.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// Check if process is still alive by sending signal 0.
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			slog.Info("watchdog: control plane terminated gracefully", "pid", pid)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	slog.Warn("watchdog: graceful shutdown timed out, sending SIGKILL", "pid", pid)
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		slog.Error("watchdog: SIGKILL failed", "pid", pid, "error", err)
	} else {
		slog.Info("watchdog: SIGKILL sent", "pid", pid)
	}
}

// killControlPlaneWindows uses os.Process.Kill for forceful termination on
// Windows, since Windows does not support Unix signals.
func killControlPlaneWindows(pid int) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		slog.Error("watchdog: failed to find process", "pid", pid, "error", err)
		return
	}

	slog.Warn("watchdog: killing control plane process on Windows", "pid", pid)
	if err := proc.Kill(); err != nil {
		slog.Error("watchdog: Kill failed", "pid", pid, "error", err)
	} else {
		slog.Info("watchdog: control plane process killed", "pid", pid)
	}
}

// alertOperator logs the alert at ERROR level. In production this would
// dispatch to a webhook, PagerDuty, Slack, or other alerting channel.
func alertOperator(reason string) {
	slog.Error("OPERATOR ALERT: watchdog detected an integrity or availability issue",
		"reason", reason,
		"action_required", "investigate control plane immediately",
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	)
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
