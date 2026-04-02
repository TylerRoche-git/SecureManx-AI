// Command enforcer-vm is the cloud VM enforcement adapter for security-brain.
// It subscribes to enforcement actions from the event bus and executes
// containment and remediation operations against cloud VMs (AWS EC2, GCP
// Compute Engine, Azure VMs). For MVP, each operation logs the intended
// action with full detail; swapping in real cloud SDK calls requires only
// replacing the method bodies on vmEnforcer.
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
	slog.Info("enforcer-vm starting")

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

	enforcer := &vmEnforcer{}

	_, err = client.Subscribe(ctx, transport.StreamEnforcement, transport.SubjectEnforcementActions, "enforcer-vm", func(msg jetstream.Msg) {
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

	slog.Info("enforcer-vm ready, listening for enforcement actions", "nats_url", natsURL)

	<-ctx.Done()

	slog.Info("enforcer-vm stopped")
}

// vmEnforcer dispatches enforcement actions to VM-level containment operations.
// Each method logs the precise operation that a production implementation would
// perform via cloud SDK calls (e.g., AWS EC2 API, GCP Compute API, Azure SDK).
type vmEnforcer struct{}

// handleAction routes an enforcement action to the appropriate VM operation.
func (e *vmEnforcer) handleAction(action policytypes.EnforcementAction) error {
	switch action.Type {
	case policytypes.ActionIsolate:
		return e.isolateVM(action.Targets)
	case policytypes.ActionKillReplace:
		return e.killAndReplaceVM(action.Targets)
	case policytypes.ActionQuarantine:
		return e.quarantineVM(action.Targets)
	case policytypes.ActionBlockEgress:
		return e.blockEgressVM(action.Targets)
	case policytypes.ActionRevokeCredentials:
		return e.revokeVMCredentials(action.Targets)
	default:
		slog.Warn("unsupported action type for VM enforcer", "type", action.Type)
		return nil
	}
}

// isolateVM modifies the VM's security group / firewall rules to deny all
// traffic except monitoring and management access (e.g., SSH from bastion).
// Production: aws ec2 modify-instance-attribute / gcloud compute firewall-rules update.
func (e *vmEnforcer) isolateVM(targets []string) error {
	for _, target := range targets {
		slog.Info("would isolate VM: replace security group with isolation SG that denies all ingress/egress except monitoring",
			"vm", target,
			"operation", "modify-security-group",
			"rule", fmt.Sprintf("deny all traffic to/from %s except port 22 from bastion and port 9100 for prometheus", target),
		)
	}
	slog.Info("VM isolation complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// killAndReplaceVM stops the compromised VM and launches a replacement from a
// known-good AMI/image, preserving the original's disks for forensic analysis.
// Production: aws ec2 stop-instances + run-instances / gcloud compute instances stop + create.
func (e *vmEnforcer) killAndReplaceVM(targets []string) error {
	for _, target := range targets {
		slog.Info("would stop compromised VM and snapshot disks for forensics",
			"vm", target,
			"operation", "stop-and-snapshot",
			"detail", fmt.Sprintf("stop instance %s, snapshot all attached volumes, tag as forensic-evidence", target),
		)
		slog.Info("would launch replacement VM from known-good image",
			"vm", target,
			"operation", "launch-replacement",
			"detail", fmt.Sprintf("launch new instance with same config as %s from latest golden AMI/image", target),
		)
	}
	slog.Info("VM kill-and-replace complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// quarantineVM moves the VM to an isolated quarantine network/VPC for forensic
// investigation, detaching it from production subnets.
// Production: aws ec2 modify-instance-attribute --groups / gcloud compute instances move.
func (e *vmEnforcer) quarantineVM(targets []string) error {
	for _, target := range targets {
		slog.Info("would move VM to quarantine VPC/network for forensic analysis",
			"vm", target,
			"operation", "move-to-quarantine-network",
			"detail", fmt.Sprintf("detach %s from production subnet, attach to quarantine VPC with no internet access", target),
		)
	}
	slog.Info("VM quarantine complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// blockEgressVM adds an egress deny rule to the VM's security group, preventing
// data exfiltration while keeping the instance accessible for investigation.
// Production: aws ec2 authorize-security-group-egress --protocol -1 --cidr 0.0.0.0/0 DENY.
func (e *vmEnforcer) blockEgressVM(targets []string) error {
	for _, target := range targets {
		slog.Info("would add egress deny rule to VM security group",
			"vm", target,
			"operation", "block-egress",
			"rule", fmt.Sprintf("add outbound deny-all rule to security group of %s, keeping inbound SSH for investigation", target),
		)
	}
	slog.Info("VM egress block complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// revokeVMCredentials revokes the VM's instance role and rotates any attached
// credentials, preventing the compromised instance from accessing cloud APIs.
// Production: aws iam remove-role-from-instance-profile / gcloud compute instances set-service-account.
func (e *vmEnforcer) revokeVMCredentials(targets []string) error {
	for _, target := range targets {
		slog.Info("would revoke instance role and rotate credentials for VM",
			"vm", target,
			"operation", "revoke-instance-credentials",
			"detail", fmt.Sprintf("detach IAM instance profile from %s, invalidate temporary credentials, rotate service account keys", target),
		)
	}
	slog.Info("VM credential revocation complete", "targets", strings.Join(targets, ","), "count", len(targets))
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
