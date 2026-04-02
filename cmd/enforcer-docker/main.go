// Command enforcer-docker is the Docker enforcement adapter for security-brain.
// It subscribes to enforcement actions from the event bus and executes
// containment and remediation operations against Docker containers using the
// Docker Engine API. Each action manipulates real Docker resources: networks,
// containers, and secrets.
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
	"time"

	"github.com/moby/moby/api/types/network"
	dockerclient "github.com/moby/moby/client"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

const (
	quarantineNetworkName = "security-brain-quarantine"
	stopTimeoutSeconds    = 10
)

func main() {
	slog.Info("enforcer-docker starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	natsURL := envOrDefault("NATS_URL", "nats://localhost:4222")

	natsClient, err := transport.NewNATSClient(natsURL)
	if err != nil {
		slog.Error("failed to connect to NATS", "error", err)
		os.Exit(1)
	}
	defer natsClient.Close()

	if err := natsClient.CreateAllStreams(ctx); err != nil {
		slog.Error("failed to create JetStream streams", "error", err)
		os.Exit(1)
	}

	docker, err := newDockerClient()
	if err != nil {
		slog.Error("failed to create Docker client", "error", err)
		os.Exit(1)
	}
	defer docker.Close()

	enforcer := &dockerEnforcer{docker: docker}

	_, err = natsClient.Subscribe(ctx, transport.StreamEnforcement, transport.SubjectEnforcementActions, "enforcer-docker", func(msg jetstream.Msg) {
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

		if handleErr := enforcer.handleAction(ctx, action); handleErr != nil {
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

	slog.Info("enforcer-docker ready, listening for enforcement actions", "nats_url", natsURL)

	<-ctx.Done()

	slog.Info("enforcer-docker stopped")
}

// dockerEnforcer dispatches enforcement actions to Docker container operations
// using the Docker Engine API.
type dockerEnforcer struct {
	docker *dockerclient.Client
}

// newDockerClient creates a Docker API client configured from environment
// variables (DOCKER_HOST, DOCKER_TLS_VERIFY, DOCKER_CERT_PATH) or defaults
// to the local Unix socket.
func newDockerClient() (*dockerclient.Client, error) {
	return dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
}

// handleAction routes an enforcement action to the appropriate Docker operation.
func (e *dockerEnforcer) handleAction(ctx context.Context, action policytypes.EnforcementAction) error {
	switch action.Type {
	case policytypes.ActionIsolate:
		return e.isolate(ctx, action.Targets)
	case policytypes.ActionKillReplace:
		return e.killReplace(ctx, action.Targets)
	case policytypes.ActionQuarantine:
		return e.quarantine(ctx, action.Targets)
	case policytypes.ActionBlockEgress:
		return e.blockEgress(ctx, action.Targets)
	case policytypes.ActionRevokeCredentials:
		return e.revokeCredentials(ctx, action.Targets)
	default:
		slog.Warn("unsupported action type for Docker enforcer", "type", action.Type)
		return nil
	}
}

// isolate disconnects containers from all their networks and connects them to
// a quarantine network with no external access.
func (e *dockerEnforcer) isolate(ctx context.Context, targets []string) error {
	quarantineID, err := e.ensureQuarantineNetwork(ctx)
	if err != nil {
		return fmt.Errorf("ensure quarantine network: %w", err)
	}

	for _, target := range targets {
		result, inspectErr := e.docker.ContainerInspect(ctx, target, dockerclient.ContainerInspectOptions{})
		if inspectErr != nil {
			slog.Error("failed to inspect container for isolation", "container", target, "error", inspectErr)
			return fmt.Errorf("inspect container %s: %w", target, inspectErr)
		}
		info := result.Container

		// Disconnect from all current networks.
		if info.NetworkSettings != nil {
			for netName := range info.NetworkSettings.Networks {
				_, disconnectErr := e.docker.NetworkDisconnect(ctx, netName, dockerclient.NetworkDisconnectOptions{
					Container: target,
					Force:     true,
				})
				if disconnectErr != nil {
					slog.Error("failed to disconnect container from network",
						"container", target,
						"network", netName,
						"error", disconnectErr,
					)
					return fmt.Errorf("disconnect container %s from network %s: %w", target, netName, disconnectErr)
				}
				slog.Info("disconnected container from network",
					"container", target,
					"network", netName,
				)
			}
		}

		// Connect to quarantine network.
		_, connectErr := e.docker.NetworkConnect(ctx, quarantineID, dockerclient.NetworkConnectOptions{
			Container:      target,
			EndpointConfig: &network.EndpointSettings{},
		})
		if connectErr != nil {
			slog.Error("failed to connect container to quarantine network",
				"container", target,
				"error", connectErr,
			)
			return fmt.Errorf("connect container %s to quarantine network: %w", target, connectErr)
		}

		slog.Info("container isolated to quarantine network",
			"container", target,
			"container_id", info.ID,
			"quarantine_network", quarantineNetworkName,
		)
	}

	slog.Info("isolation complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// killReplace stops a compromised container, renames it for forensics, and
// starts a replacement from the same image with the original configuration.
func (e *dockerEnforcer) killReplace(ctx context.Context, targets []string) error {
	for _, target := range targets {
		result, inspectErr := e.docker.ContainerInspect(ctx, target, dockerclient.ContainerInspectOptions{})
		if inspectErr != nil {
			slog.Error("failed to inspect container for kill-replace", "container", target, "error", inspectErr)
			return fmt.Errorf("inspect container %s: %w", target, inspectErr)
		}
		info := result.Container

		originalName := strings.TrimPrefix(info.Name, "/")
		timestamp := time.Now().UTC().Format("20060102T150405Z")
		quarantinedName := fmt.Sprintf("%s-quarantined-%s", originalName, timestamp)

		// Stop the container with a timeout.
		stopTimeout := stopTimeoutSeconds
		_, stopErr := e.docker.ContainerStop(ctx, info.ID, dockerclient.ContainerStopOptions{
			Timeout: &stopTimeout,
		})
		if stopErr != nil {
			slog.Error("failed to stop container", "container", target, "error", stopErr)
			return fmt.Errorf("stop container %s: %w", target, stopErr)
		}
		slog.Info("stopped container for kill-replace", "container", target, "container_id", info.ID)

		// Rename for forensic preservation.
		_, renameErr := e.docker.ContainerRename(ctx, info.ID, dockerclient.ContainerRenameOptions{
			NewName: quarantinedName,
		})
		if renameErr != nil {
			slog.Error("failed to rename container", "container", target, "new_name", quarantinedName, "error", renameErr)
			return fmt.Errorf("rename container %s to %s: %w", target, quarantinedName, renameErr)
		}
		slog.Info("renamed container for forensics", "container", target, "new_name", quarantinedName)

		// Rebuild the container configuration from the inspected state.
		newContainerConfig := info.Config
		hostConfig := info.HostConfig

		// Rebuild networking config from the original container.
		var networkingConfig *network.NetworkingConfig
		if info.NetworkSettings != nil && len(info.NetworkSettings.Networks) > 0 {
			endpointsConfig := make(map[string]*network.EndpointSettings)
			for netName, netSettings := range info.NetworkSettings.Networks {
				endpointsConfig[netName] = &network.EndpointSettings{
					Aliases: netSettings.Aliases,
				}
			}
			networkingConfig = &network.NetworkingConfig{
				EndpointsConfig: endpointsConfig,
			}
		}

		// Create replacement container with the original name.
		createResp, createErr := e.docker.ContainerCreate(ctx, dockerclient.ContainerCreateOptions{
			Config:           newContainerConfig,
			HostConfig:       hostConfig,
			NetworkingConfig: networkingConfig,
			Name:             originalName,
		})
		if createErr != nil {
			slog.Error("failed to create replacement container",
				"original", target,
				"image", newContainerConfig.Image,
				"error", createErr,
			)
			return fmt.Errorf("create replacement for %s: %w", target, createErr)
		}

		_, startErr := e.docker.ContainerStart(ctx, createResp.ID, dockerclient.ContainerStartOptions{})
		if startErr != nil {
			slog.Error("failed to start replacement container",
				"container_id", createResp.ID,
				"error", startErr,
			)
			return fmt.Errorf("start replacement for %s: %w", target, startErr)
		}

		slog.Info("replacement container started",
			"original_name", originalName,
			"quarantined_as", quarantinedName,
			"new_container_id", createResp.ID,
			"image", newContainerConfig.Image,
		)
	}

	slog.Info("kill-replace complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// quarantine pauses containers to freeze their state for forensic analysis.
// If pausing is not supported, it falls back to network isolation.
func (e *dockerEnforcer) quarantine(ctx context.Context, targets []string) error {
	for _, target := range targets {
		_, pauseErr := e.docker.ContainerPause(ctx, target, dockerclient.ContainerPauseOptions{})
		if pauseErr != nil {
			slog.Warn("container pause failed, falling back to network isolation",
				"container", target,
				"error", pauseErr,
			)
			fallbackErr := e.isolate(ctx, []string{target})
			if fallbackErr != nil {
				return fmt.Errorf("quarantine fallback isolation for %s: %w", target, fallbackErr)
			}
			continue
		}
		slog.Info("container paused for quarantine forensics",
			"container", target,
		)
	}

	slog.Info("quarantine complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// blockEgress disconnects containers from external-facing networks and
// reconnects them only to an internal-only quarantine network, preventing
// data exfiltration while preserving the container state.
func (e *dockerEnforcer) blockEgress(ctx context.Context, targets []string) error {
	quarantineID, err := e.ensureQuarantineNetwork(ctx)
	if err != nil {
		return fmt.Errorf("ensure quarantine network: %w", err)
	}

	for _, target := range targets {
		result, inspectErr := e.docker.ContainerInspect(ctx, target, dockerclient.ContainerInspectOptions{})
		if inspectErr != nil {
			slog.Error("failed to inspect container for egress block", "container", target, "error", inspectErr)
			return fmt.Errorf("inspect container %s: %w", target, inspectErr)
		}
		info := result.Container

		// Disconnect from all networks that are not internal-only.
		if info.NetworkSettings != nil {
			for netName := range info.NetworkSettings.Networks {
				netResult, netInspectErr := e.docker.NetworkInspect(ctx, netName, dockerclient.NetworkInspectOptions{})
				if netInspectErr != nil {
					slog.Error("failed to inspect network", "network", netName, "error", netInspectErr)
					return fmt.Errorf("inspect network %s: %w", netName, netInspectErr)
				}

				// Keep the container on internal networks; disconnect from external ones.
				if netResult.Network.Internal {
					slog.Info("keeping container on internal network",
						"container", target,
						"network", netName,
					)
					continue
				}

				_, disconnectErr := e.docker.NetworkDisconnect(ctx, netName, dockerclient.NetworkDisconnectOptions{
					Container: target,
					Force:     true,
				})
				if disconnectErr != nil {
					slog.Error("failed to disconnect container from external network",
						"container", target,
						"network", netName,
						"error", disconnectErr,
					)
					return fmt.Errorf("disconnect container %s from network %s: %w", target, netName, disconnectErr)
				}
				slog.Info("disconnected container from external network",
					"container", target,
					"network", netName,
				)
			}
		}

		// Ensure the container is connected to the internal quarantine network.
		_, connectErr := e.docker.NetworkConnect(ctx, quarantineID, dockerclient.NetworkConnectOptions{
			Container:      target,
			EndpointConfig: &network.EndpointSettings{},
		})
		if connectErr != nil {
			// If already connected, this is not fatal.
			slog.Warn("could not connect to quarantine network (may already be connected)",
				"container", target,
				"error", connectErr,
			)
		} else {
			slog.Info("connected container to internal quarantine network",
				"container", target,
				"quarantine_network", quarantineNetworkName,
			)
		}

		slog.Info("egress blocked for container",
			"container", target,
			"container_id", info.ID,
		)
	}

	slog.Info("egress block complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// revokeCredentials stops containers that have mounted secrets or credential
// environment variables, then recreates them without those credentials.
func (e *dockerEnforcer) revokeCredentials(ctx context.Context, targets []string) error {
	for _, target := range targets {
		result, inspectErr := e.docker.ContainerInspect(ctx, target, dockerclient.ContainerInspectOptions{})
		if inspectErr != nil {
			slog.Error("failed to inspect container for credential revocation", "container", target, "error", inspectErr)
			return fmt.Errorf("inspect container %s: %w", target, inspectErr)
		}
		info := result.Container

		originalName := strings.TrimPrefix(info.Name, "/")

		// Identify credential-related environment variables.
		cleanEnv := filterCredentialEnvVars(info.Config.Env)
		removedEnvCount := len(info.Config.Env) - len(cleanEnv)

		// Identify secret/credential mounts to remove.
		cleanMounts := filterCredentialMounts(info.HostConfig.Binds)
		removedMountCount := len(info.HostConfig.Binds) - len(cleanMounts)

		slog.Info("identified credentials to revoke",
			"container", target,
			"env_vars_removed", removedEnvCount,
			"mounts_removed", removedMountCount,
		)

		// Stop the container.
		stopTimeout := stopTimeoutSeconds
		_, stopErr := e.docker.ContainerStop(ctx, info.ID, dockerclient.ContainerStopOptions{
			Timeout: &stopTimeout,
		})
		if stopErr != nil {
			slog.Error("failed to stop container for credential revocation", "container", target, "error", stopErr)
			return fmt.Errorf("stop container %s: %w", target, stopErr)
		}

		// Remove the original container.
		_, removeErr := e.docker.ContainerRemove(ctx, info.ID, dockerclient.ContainerRemoveOptions{Force: true})
		if removeErr != nil {
			slog.Error("failed to remove container for credential revocation", "container", target, "error", removeErr)
			return fmt.Errorf("remove container %s: %w", target, removeErr)
		}

		// Rebuild config without credential env vars and mounts.
		newConfig := info.Config
		newConfig.Env = cleanEnv

		newHostConfig := info.HostConfig
		newHostConfig.Binds = cleanMounts

		// Rebuild networking config.
		var networkingConfig *network.NetworkingConfig
		if info.NetworkSettings != nil && len(info.NetworkSettings.Networks) > 0 {
			endpointsConfig := make(map[string]*network.EndpointSettings)
			for netName, netSettings := range info.NetworkSettings.Networks {
				endpointsConfig[netName] = &network.EndpointSettings{
					Aliases: netSettings.Aliases,
				}
			}
			networkingConfig = &network.NetworkingConfig{
				EndpointsConfig: endpointsConfig,
			}
		}

		createResp, createErr := e.docker.ContainerCreate(ctx, dockerclient.ContainerCreateOptions{
			Config:           newConfig,
			HostConfig:       newHostConfig,
			NetworkingConfig: networkingConfig,
			Name:             originalName,
		})
		if createErr != nil {
			slog.Error("failed to recreate container without credentials",
				"container", originalName,
				"error", createErr,
			)
			return fmt.Errorf("recreate container %s without credentials: %w", originalName, createErr)
		}

		_, startErr := e.docker.ContainerStart(ctx, createResp.ID, dockerclient.ContainerStartOptions{})
		if startErr != nil {
			slog.Error("failed to start credential-revoked container",
				"container_id", createResp.ID,
				"error", startErr,
			)
			return fmt.Errorf("start credential-revoked container %s: %w", originalName, startErr)
		}

		slog.Info("container recreated without credentials",
			"container", originalName,
			"new_container_id", createResp.ID,
			"env_vars_removed", removedEnvCount,
			"mounts_removed", removedMountCount,
		)
	}

	slog.Info("credential revocation complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// ensureQuarantineNetwork creates a Docker bridge network with internal-only
// access (no external routing) for isolating compromised containers. If the
// network already exists, it returns its ID.
func (e *dockerEnforcer) ensureQuarantineNetwork(ctx context.Context) (string, error) {
	// Check if the quarantine network already exists.
	filterArgs := make(dockerclient.Filters).Add("name", quarantineNetworkName)
	existingNetworks, err := e.docker.NetworkList(ctx, dockerclient.NetworkListOptions{
		Filters: filterArgs,
	})
	if err != nil {
		return "", fmt.Errorf("list networks: %w", err)
	}

	// The filter is a substring match, so verify the exact name.
	for _, n := range existingNetworks.Items {
		if n.Name == quarantineNetworkName {
			slog.Info("quarantine network already exists", "network_id", n.ID)
			return n.ID, nil
		}
	}

	// Create the quarantine network.
	resp, createErr := e.docker.NetworkCreate(ctx, quarantineNetworkName, dockerclient.NetworkCreateOptions{
		Driver:   "bridge",
		Internal: true,
		Labels: map[string]string{
			"security-brain.purpose": "quarantine",
			"security-brain.managed": "true",
		},
	})
	if createErr != nil {
		return "", fmt.Errorf("create quarantine network: %w", createErr)
	}

	slog.Info("created quarantine network",
		"network_name", quarantineNetworkName,
		"network_id", resp.ID,
		"internal", true,
	)
	return resp.ID, nil
}

// credentialEnvPrefixes lists environment variable name prefixes that
// typically contain credentials or secrets.
var credentialEnvPrefixes = []string{
	"AWS_SECRET",
	"AWS_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_CLIENT_SECRET",
	"AZURE_TENANT_ID",
	"GCP_SERVICE_ACCOUNT",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"DATABASE_PASSWORD",
	"DB_PASSWORD",
	"DB_PASS",
	"MYSQL_PASSWORD",
	"POSTGRES_PASSWORD",
	"REDIS_PASSWORD",
	"API_KEY",
	"API_SECRET",
	"SECRET_KEY",
	"PRIVATE_KEY",
	"TOKEN",
	"PASSWORD",
	"CREDENTIALS",
}

// filterCredentialEnvVars removes environment variables that match known
// credential patterns, returning the remaining safe variables.
func filterCredentialEnvVars(envVars []string) []string {
	clean := make([]string, 0, len(envVars))
	for _, env := range envVars {
		key := env
		if idx := strings.Index(env, "="); idx >= 0 {
			key = env[:idx]
		}
		upperKey := strings.ToUpper(key)

		isCredential := false
		for _, prefix := range credentialEnvPrefixes {
			if strings.Contains(upperKey, prefix) {
				isCredential = true
				slog.Info("removing credential environment variable", "key", key)
				break
			}
		}

		if !isCredential {
			clean = append(clean, env)
		}
	}
	return clean
}

// credentialMountPatterns lists path substrings that typically indicate
// mounted secrets or credential files.
var credentialMountPatterns = []string{
	"/run/secrets",
	"/.ssh",
	"/.aws",
	"/.config/gcloud",
	"/.azure",
	"/credentials",
	"/secrets",
	"/private-keys",
	"/.kube/config",
	"/service-account",
}

// filterCredentialMounts removes bind mounts whose paths match known
// credential/secret mount patterns, returning the remaining safe mounts.
func filterCredentialMounts(binds []string) []string {
	clean := make([]string, 0, len(binds))
	for _, bind := range binds {
		lowerBind := strings.ToLower(bind)

		isCredentialMount := false
		for _, pattern := range credentialMountPatterns {
			if strings.Contains(lowerBind, pattern) {
				isCredentialMount = true
				slog.Info("removing credential mount", "bind", bind)
				break
			}
		}

		if !isCredentialMount {
			clean = append(clean, bind)
		}
	}
	return clean
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
