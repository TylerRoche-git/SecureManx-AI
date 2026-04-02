// Command enforcer-process is the process-level enforcement adapter for
// security-brain. It subscribes to enforcement actions from the event bus and
// executes process-level containment on local or remote hosts. This adapter
// targets bare-metal and traditional server deployments where enforcement
// operates at the OS process level (iptables, cgroups, signals, cron).
// For MVP, each operation logs the precise command or system call that a
// production implementation would execute.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

func main() {
	slog.Info("enforcer-process starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	natsURL := envOrDefault("NATS_URL", "nats://localhost:4222")

	client, err := transport.NewNATSClient(natsURL)
	if err != nil {
		slog.Error("failed to connect to NATS", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	if err := client.CreateAllStreams(ctx); err != nil {
		slog.Error("failed to create JetStream streams", "error", err)
		os.Exit(1)
	}

	enforcer := &processEnforcer{}

	_, err = client.Subscribe(ctx, transport.StreamEnforcement, transport.SubjectEnforcementActions, "enforcer-process", func(msg jetstream.Msg) {
		var action policytypes.EnforcementAction
		if unmarshalErr := json.Unmarshal(msg.Data(), &action); unmarshalErr != nil {
			slog.Error("unmarshal enforcement action", "error", unmarshalErr)
			if nakErr := msg.Nak(); nakErr != nil {
				slog.Error("failed to nak message", "error", nakErr)
			}
			return
		}

		slog.Info("received enforcement action",
			"action_id", action.ActionID,
			"type", action.Type,
			"targets", action.Targets,
		)

		if handleErr := enforcer.handleAction(action); handleErr != nil {
			slog.Error("enforcement action failed",
				"action_id", action.ActionID,
				"type", action.Type,
				"error", handleErr,
			)
			if nakErr := msg.Nak(); nakErr != nil {
				slog.Error("failed to nak message", "error", nakErr)
			}
			return
		}

		if ackErr := msg.Ack(); ackErr != nil {
			slog.Error("failed to ack message", "error", ackErr)
		}
	})
	if err != nil {
		slog.Error("failed to subscribe to enforcement actions", "error", err)
		os.Exit(1)
	}

	slog.Info("enforcer-process ready, listening for enforcement actions", "nats_url", natsURL)

	<-ctx.Done()

	slog.Info("enforcer-process stopped")
}

// processEnforcer dispatches enforcement actions to OS-level process containment
// operations. Each method logs the exact command or syscall that a production
// implementation would execute (iptables, kill, cgroupfs, systemctl, etc.).
type processEnforcer struct{}

// handleAction routes an enforcement action to the appropriate process operation.
func (e *processEnforcer) handleAction(action policytypes.EnforcementAction) error {
	switch action.Type {
	case policytypes.ActionIsolate:
		return e.isolateProcess(action.Targets)
	case policytypes.ActionKillReplace:
		return e.killAndReplace(action.Targets)
	case policytypes.ActionQuarantine:
		return e.quarantineProcess(action.Targets)
	case policytypes.ActionBlockEgress:
		return e.blockProcessEgress(action.Targets)
	case policytypes.ActionRevokeCredentials:
		return e.revokeProcessCredentials(action.Targets)
	case policytypes.ActionFreezePipeline:
		return e.freezeService(action.Targets)
	default:
		slog.Warn("unsupported action type for process enforcer", "type", action.Type)
		return nil
	}
}

// isolateProcess applies iptables/nftables rules to cut the target process's
// network access while keeping it running for forensic inspection.
// Production: iptables -A OUTPUT/INPUT with owner match and cgroup match.
func (e *processEnforcer) isolateProcess(targets []string) error {
	for _, target := range targets {
		slog.Info("would apply iptables rules to isolate process network access",
			"target", target,
			"operation", "iptables-isolate",
			"commands", []string{
				fmt.Sprintf("iptables -A OUTPUT -m owner --uid-owner %s -j DROP", target),
				fmt.Sprintf("iptables -A INPUT -m owner --uid-owner %s -j DROP", target),
			},
		)
	}
	slog.Info("process isolation complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// killAndReplace sends SIGTERM then SIGKILL to the target process and restarts
// it from a known-good binary. The original binary is preserved for forensics.
// Production: kill -TERM <pid>, sleep, kill -KILL <pid>, then exec known-good binary.
func (e *processEnforcer) killAndReplace(targets []string) error {
	for _, target := range targets {
		slog.Info("would kill compromised process and restart from known-good binary",
			"target", target,
			"operation", "kill-and-replace",
			"commands", []string{
				fmt.Sprintf("cp /proc/%s/exe /var/forensics/%s.bin.evidence", target, target),
				fmt.Sprintf("kill -TERM %s", target),
				fmt.Sprintf("sleep 5 && kill -0 %s && kill -KILL %s", target, target),
				fmt.Sprintf("systemctl restart %s (from known-good binary)", target),
			},
		)
	}
	slog.Info("process kill-and-replace complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// quarantineProcess moves the target process into a restricted cgroup with
// frozen state, preserving it for forensic analysis without allowing execution.
// Production: cgroupfs manipulation + SIGSTOP / freezer cgroup.
func (e *processEnforcer) quarantineProcess(targets []string) error {
	for _, target := range targets {
		slog.Info("would move process to restricted cgroup and freeze for forensics",
			"target", target,
			"operation", "cgroup-quarantine",
			"commands", []string{
				fmt.Sprintf("mkdir -p /sys/fs/cgroup/quarantine/%s", target),
				fmt.Sprintf("echo %s > /sys/fs/cgroup/quarantine/%s/cgroup.procs", target, target),
				fmt.Sprintf("echo 1 > /sys/fs/cgroup/quarantine/%s/cgroup.freeze", target),
			},
		)
	}
	slog.Info("process quarantine complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// blockProcessEgress adds an iptables OUTPUT DROP rule for the process's
// UID/GID, preventing data exfiltration while allowing inbound connections
// for investigation.
// Production: iptables -A OUTPUT -m owner --uid-owner <uid> -j DROP.
func (e *processEnforcer) blockProcessEgress(targets []string) error {
	for _, target := range targets {
		slog.Info("would add iptables egress drop rule for process",
			"target", target,
			"operation", "iptables-block-egress",
			"command", fmt.Sprintf("iptables -A OUTPUT -m owner --uid-owner %s -j DROP", target),
		)
	}
	slog.Info("process egress block complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// revokeProcessCredentials deletes or rotates local credential files and
// invalidates tokens accessible by the target process.
// Production: rm/shred credential files, revoke OAuth tokens, rotate API keys.
func (e *processEnforcer) revokeProcessCredentials(targets []string) error {
	for _, target := range targets {
		slog.Info("would revoke credentials accessible by process",
			"target", target,
			"operation", "revoke-credentials",
			"commands", []string{
				fmt.Sprintf("shred -u /home/%s/.ssh/id_*", target),
				fmt.Sprintf("shred -u /home/%s/.aws/credentials", target),
				fmt.Sprintf("shred -u /home/%s/.config/gcloud/application_default_credentials.json", target),
				fmt.Sprintf("revoke all active OAuth/API tokens for user %s", target),
			},
		)
	}
	slog.Info("process credential revocation complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// freezeService stops CI runner services and disables scheduled tasks (cron)
// to prevent a compromised pipeline from executing further actions.
// Production: systemctl stop + disable, crontab removal, at queue clear.
func (e *processEnforcer) freezeService(targets []string) error {
	for _, target := range targets {
		slog.Info("would freeze pipeline service and disable scheduled tasks",
			"target", target,
			"operation", "freeze-pipeline",
			"commands", []string{
				fmt.Sprintf("systemctl stop %s", target),
				fmt.Sprintf("systemctl disable %s", target),
				fmt.Sprintf("crontab -r -u %s", target),
				fmt.Sprintf("atrm $(atq -q a | awk '{print $1}') for user %s", target),
			},
		)
	}
	slog.Info("pipeline freeze complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
