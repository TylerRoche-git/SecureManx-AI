// Command enforcer-istio is the Istio enforcement adapter for security-brain.
// It subscribes to enforcement actions from the event bus and executes
// containment and remediation operations via Istio service mesh resources
// (VirtualService, DestinationRule, Sidecar) using the Kubernetes dynamic
// client with unstructured objects to avoid the large Istio API dependency tree.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/policytypes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Istio GroupVersionResource definitions for the dynamic client.
var (
	virtualServiceGVR = schema.GroupVersionResource{
		Group:    "networking.istio.io",
		Version:  "v1beta1",
		Resource: "virtualservices",
	}
	destinationRuleGVR = schema.GroupVersionResource{
		Group:    "networking.istio.io",
		Version:  "v1beta1",
		Resource: "destinationrules",
	}
	sidecarGVR = schema.GroupVersionResource{
		Group:    "networking.istio.io",
		Version:  "v1beta1",
		Resource: "sidecars",
	}
)

func main() {
	slog.Info("enforcer-istio starting")

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

	dynClient, err := newDynamicClient()
	if err != nil {
		slog.Error("failed to create Kubernetes dynamic client", "error", err)
		os.Exit(1)
	}

	enforcer := &istioEnforcer{client: dynClient}

	_, err = client.Subscribe(ctx, transport.StreamEnforcement, transport.SubjectEnforcementActions, "enforcer-istio", func(msg jetstream.Msg) {
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

	slog.Info("enforcer-istio ready, listening for enforcement actions", "nats_url", natsURL)

	<-ctx.Done()

	slog.Info("enforcer-istio stopped")
}

// newDynamicClient creates a Kubernetes dynamic client. It first attempts
// in-cluster configuration (for pods running inside a cluster), then falls
// back to the user's kubeconfig file at ~/.kube/config.
func newDynamicClient() (dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("kubernetes config: %w", err)
		}
	}
	return dynamic.NewForConfig(config)
}

// istioEnforcer dispatches enforcement actions to Istio service mesh operations
// using the Kubernetes dynamic client and unstructured objects.
type istioEnforcer struct {
	client dynamic.Interface
}

// handleAction routes an enforcement action to the appropriate Istio operation.
func (e *istioEnforcer) handleAction(ctx context.Context, action policytypes.EnforcementAction) error {
	switch action.Type {
	case policytypes.ActionIsolate:
		return e.isolateTraffic(ctx, action.Targets)
	case policytypes.ActionKillReplace:
		return e.reroute(ctx, action.Targets)
	case policytypes.ActionBlockEgress:
		return e.blockEgress(ctx, action.Targets)
	case policytypes.ActionQuarantine:
		return e.isolateTraffic(ctx, action.Targets)
	default:
		slog.Warn("unsupported action type for Istio enforcer", "type", action.Type)
		return nil
	}
}

// parseNamespacedName splits a "namespace/name" string into its components.
func parseNamespacedName(target string) (namespace, name string, err error) {
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid target format %q: expected namespace/name", target)
	}
	return parts[0], parts[1], nil
}

// isolateTraffic creates a VirtualService with a fault injection abort rule
// that returns HTTP 503 for 100% of traffic to the target service. This
// effectively isolates the service at the mesh layer without modifying
// Kubernetes NetworkPolicies.
// Target format: "namespace/service-name".
func (e *istioEnforcer) isolateTraffic(ctx context.Context, targets []string) error {
	for _, target := range targets {
		namespace, serviceName, err := parseNamespacedName(target)
		if err != nil {
			return fmt.Errorf("isolate-traffic: %w", err)
		}

		vsName := "security-brain-isolate-" + serviceName

		vs := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.istio.io/v1beta1",
				"kind":       "VirtualService",
				"metadata": map[string]interface{}{
					"name":      vsName,
					"namespace": namespace,
					"labels": map[string]interface{}{
						"security-brain/managed-by": "enforcer-istio",
						"security-brain/action":     "isolate",
					},
				},
				"spec": map[string]interface{}{
					"hosts": []interface{}{serviceName},
					"http": []interface{}{
						map[string]interface{}{
							"fault": map[string]interface{}{
								"abort": map[string]interface{}{
									"httpStatus": int64(503),
									"percentage": map[string]interface{}{
										"value": float64(100),
									},
								},
							},
							"route": []interface{}{
								map[string]interface{}{
									"destination": map[string]interface{}{
										"host": serviceName,
									},
								},
							},
						},
					},
				},
			},
		}

		_, err = e.client.Resource(virtualServiceGVR).Namespace(namespace).Create(ctx, vs, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create VirtualService %s/%s: %w", namespace, vsName, err)
		}

		slog.Info("created isolation VirtualService with 503 fault injection",
			"virtualservice", vsName,
			"namespace", namespace,
			"service", serviceName,
			"http_status", 503,
			"percentage", 100,
		)
	}

	slog.Info("traffic isolation complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// reroute creates a VirtualService that routes traffic away from the affected
// service to healthy replicas, and applies a DestinationRule with circuit
// breaker settings to prevent cascading failures from the compromised upstream.
// Target format: "namespace/service-name".
func (e *istioEnforcer) reroute(ctx context.Context, targets []string) error {
	for _, target := range targets {
		namespace, serviceName, err := parseNamespacedName(target)
		if err != nil {
			return fmt.Errorf("reroute: %w", err)
		}

		// Create a VirtualService that routes traffic to healthy replicas by
		// adding retry and timeout settings. The service mesh load balancer
		// will naturally route to available endpoints once the unhealthy pod
		// is removed by the Kubernetes enforcer.
		vsName := "security-brain-reroute-" + serviceName

		vs := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.istio.io/v1beta1",
				"kind":       "VirtualService",
				"metadata": map[string]interface{}{
					"name":      vsName,
					"namespace": namespace,
					"labels": map[string]interface{}{
						"security-brain/managed-by": "enforcer-istio",
						"security-brain/action":     "reroute",
					},
				},
				"spec": map[string]interface{}{
					"hosts": []interface{}{serviceName},
					"http": []interface{}{
						map[string]interface{}{
							"timeout": "5s",
							"retries": map[string]interface{}{
								"attempts":      int64(3),
								"perTryTimeout": "2s",
								"retryOn":       "5xx,reset,connect-failure,retriable-4xx",
							},
							"route": []interface{}{
								map[string]interface{}{
									"destination": map[string]interface{}{
										"host": serviceName,
									},
								},
							},
						},
					},
				},
			},
		}

		_, err = e.client.Resource(virtualServiceGVR).Namespace(namespace).Create(ctx, vs, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create reroute VirtualService %s/%s: %w", namespace, vsName, err)
		}

		slog.Info("created reroute VirtualService with retry and timeout",
			"virtualservice", vsName,
			"namespace", namespace,
			"service", serviceName,
		)

		// Create a DestinationRule with circuit breaker to isolate the
		// compromised upstream and prevent cascading failures.
		drName := "security-brain-circuit-breaker-" + serviceName

		dr := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.istio.io/v1beta1",
				"kind":       "DestinationRule",
				"metadata": map[string]interface{}{
					"name":      drName,
					"namespace": namespace,
					"labels": map[string]interface{}{
						"security-brain/managed-by": "enforcer-istio",
						"security-brain/action":     "circuit-breaker",
					},
				},
				"spec": map[string]interface{}{
					"host": serviceName,
					"trafficPolicy": map[string]interface{}{
						"connectionPool": map[string]interface{}{
							"tcp": map[string]interface{}{
								"maxConnections": int64(1),
							},
							"http": map[string]interface{}{
								"h2UpgradePolicy":     "DEFAULT",
								"http1MaxPendingRequests": int64(1),
								"http2MaxRequests":        int64(1),
								"maxRequestsPerConnection": int64(1),
								"maxRetries":              int64(0),
							},
						},
						"outlierDetection": map[string]interface{}{
							"consecutive5xxErrors": int64(1),
							"interval":             "1s",
							"baseEjectionTime":     "300s",
							"maxEjectionPercent":   int64(100),
						},
					},
				},
			},
		}

		_, err = e.client.Resource(destinationRuleGVR).Namespace(namespace).Create(ctx, dr, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create DestinationRule %s/%s: %w", namespace, drName, err)
		}

		slog.Info("created circuit-breaker DestinationRule",
			"destinationrule", drName,
			"namespace", namespace,
			"service", serviceName,
			"max_connections", 1,
			"consecutive_errors_for_ejection", 1,
			"ejection_time", "300s",
		)
	}

	slog.Info("reroute complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// blockEgress creates a Sidecar resource that restricts the workload's egress
// to nothing by setting outboundTrafficPolicy to REGISTRY_ONLY with no egress
// hosts. This prevents any outbound traffic from the compromised workload
// through the Istio sidecar proxy.
// Target format: "namespace/service-name".
func (e *istioEnforcer) blockEgress(ctx context.Context, targets []string) error {
	for _, target := range targets {
		namespace, serviceName, err := parseNamespacedName(target)
		if err != nil {
			return fmt.Errorf("block-egress: %w", err)
		}

		sidecarName := "security-brain-block-egress-" + serviceName

		sidecar := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.istio.io/v1beta1",
				"kind":       "Sidecar",
				"metadata": map[string]interface{}{
					"name":      sidecarName,
					"namespace": namespace,
					"labels": map[string]interface{}{
						"security-brain/managed-by": "enforcer-istio",
						"security-brain/action":     "block-egress",
					},
				},
				"spec": map[string]interface{}{
					"workloadSelector": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": serviceName,
						},
					},
					"outboundTrafficPolicy": map[string]interface{}{
						"mode": "REGISTRY_ONLY",
					},
					// Empty egress list: no external hosts are reachable.
					"egress": []interface{}{
						map[string]interface{}{
							"hosts": []interface{}{
								// Allow only istio-system for control plane
								// communication; all other egress is blocked.
								"istio-system/*",
							},
						},
					},
				},
			},
		}

		_, err = e.client.Resource(sidecarGVR).Namespace(namespace).Create(ctx, sidecar, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create Sidecar %s/%s: %w", namespace, sidecarName, err)
		}

		slog.Info("created egress-blocking Sidecar resource",
			"sidecar", sidecarName,
			"namespace", namespace,
			"service", serviceName,
			"outbound_policy", "REGISTRY_ONLY",
		)
	}

	slog.Info("egress block via Sidecar complete", "targets", strings.Join(targets, ","), "count", len(targets))
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
