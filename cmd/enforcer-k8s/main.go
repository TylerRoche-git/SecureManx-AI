// Command enforcer-k8s is the Kubernetes enforcement adapter for security-brain.
// It subscribes to enforcement actions from the event bus and executes
// containment and remediation operations against Kubernetes workloads using
// the real Kubernetes client-go API. Actions include pod isolation via
// NetworkPolicy, pod deletion for kill-replace, node cordoning for quarantine,
// egress blocking, and service account credential revocation.
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
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/policytypes"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	slog.Info("enforcer-k8s starting")

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

	k8sClient, err := newK8sClient()
	if err != nil {
		slog.Error("failed to create Kubernetes client", "error", err)
		os.Exit(1)
	}

	enforcer := &k8sEnforcer{clientset: k8sClient}

	_, err = client.Subscribe(ctx, transport.StreamEnforcement, transport.SubjectEnforcementActions, "enforcer-k8s", func(msg jetstream.Msg) {
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

	slog.Info("enforcer-k8s ready, listening for enforcement actions", "nats_url", natsURL)

	<-ctx.Done()

	slog.Info("enforcer-k8s stopped")
}

// newK8sClient creates a Kubernetes clientset. It first attempts in-cluster
// configuration (for pods running inside a cluster), then falls back to the
// user's kubeconfig file at ~/.kube/config.
func newK8sClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("kubernetes config: %w", err)
		}
	}
	return kubernetes.NewForConfig(config)
}

// k8sEnforcer dispatches enforcement actions to Kubernetes API operations.
type k8sEnforcer struct {
	clientset *kubernetes.Clientset
}

// handleAction routes an enforcement action to the appropriate Kubernetes operation.
func (e *k8sEnforcer) handleAction(ctx context.Context, action policytypes.EnforcementAction) error {
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
		slog.Warn("unsupported action type for k8s enforcer", "type", action.Type)
		return nil
	}
}

// parseNamespacedName splits a "namespace/name" string into its components.
// Returns an error if the format is invalid.
func parseNamespacedName(target string) (namespace, name string, err error) {
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid target format %q: expected namespace/name", target)
	}
	return parts[0], parts[1], nil
}

// isolate creates a NetworkPolicy that denies all ingress and egress traffic
// for each target pod, and labels the pod with security-brain/status=isolated.
// Target format: "namespace/pod-name".
func (e *k8sEnforcer) isolate(ctx context.Context, targets []string) error {
	for _, target := range targets {
		namespace, podName, err := parseNamespacedName(target)
		if err != nil {
			return fmt.Errorf("isolate: %w", err)
		}

		pod, err := e.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get pod %s: %w", target, err)
		}

		matchLabels := make(map[string]string)
		for k, v := range pod.Labels {
			matchLabels[k] = v
		}
		// Always include the pod name label for precise targeting.
		matchLabels["security-brain/isolated-pod"] = podName

		policyName := "security-brain-isolate-" + podName

		netpol := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: namespace,
				Labels: map[string]string{
					"security-brain/managed-by": "enforcer-k8s",
					"security-brain/action":     "isolate",
				},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: matchLabels,
				},
				// Empty Ingress and Egress slices deny all traffic when the
				// corresponding PolicyTypes are listed.
				Ingress:     []networkingv1.NetworkPolicyIngressRule{},
				Egress:      []networkingv1.NetworkPolicyEgressRule{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			},
		}

		_, err = e.clientset.NetworkingV1().NetworkPolicies(namespace).Create(ctx, netpol, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create network policy %s: %w", policyName, err)
		}

		slog.Info("created isolation NetworkPolicy",
			"policy", policyName,
			"namespace", namespace,
			"pod", podName,
		)

		// Label the pod to mark it as isolated for observability and tooling.
		if pod.Labels == nil {
			pod.Labels = make(map[string]string)
		}
		pod.Labels["security-brain/status"] = "isolated"
		pod.Labels["security-brain/isolated-pod"] = podName

		_, err = e.clientset.CoreV1().Pods(namespace).Update(ctx, pod, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("label pod %s as isolated: %w", target, err)
		}

		slog.Info("labeled pod as isolated",
			"namespace", namespace,
			"pod", podName,
		)
	}

	slog.Info("pod isolation complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// killReplace first isolates the target pod via NetworkPolicy, then deletes it
// with a zero grace period for immediate termination. The owning controller
// (ReplicaSet, Deployment, StatefulSet) automatically creates a replacement pod.
// Target format: "namespace/pod-name".
func (e *k8sEnforcer) killReplace(ctx context.Context, targets []string) error {
	// First isolate the pods to prevent any further network communication.
	if err := e.isolate(ctx, targets); err != nil {
		return fmt.Errorf("kill-replace isolation phase: %w", err)
	}

	for _, target := range targets {
		namespace, podName, err := parseNamespacedName(target)
		if err != nil {
			return fmt.Errorf("kill-replace: %w", err)
		}

		gracePeriod := int64(0)
		deleteOpts := metav1.DeleteOptions{
			GracePeriodSeconds: &gracePeriod,
		}

		err = e.clientset.CoreV1().Pods(namespace).Delete(ctx, podName, deleteOpts)
		if err != nil {
			return fmt.Errorf("delete pod %s: %w", target, err)
		}

		slog.Info("deleted pod for kill-replace",
			"namespace", namespace,
			"pod", podName,
			"grace_period_seconds", 0,
		)

		// Wait briefly for the replacement pod to appear. The owning controller
		// (Deployment/ReplicaSet) will schedule a new pod automatically.
		waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
		defer waitCancel()

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		replacementFound := false
		for !replacementFound {
			select {
			case <-waitCtx.Done():
				slog.Warn("timed out waiting for replacement pod",
					"namespace", namespace,
					"original_pod", podName,
				)
				replacementFound = true
			case <-ticker.C:
				pods, listErr := e.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
				if listErr != nil {
					slog.Warn("error listing pods while waiting for replacement",
						"namespace", namespace,
						"error", listErr,
					)
					continue
				}
				for _, p := range pods.Items {
					if p.Name != podName && p.Status.Phase == corev1.PodRunning {
						slog.Info("replacement pod detected",
							"namespace", namespace,
							"replacement_pod", p.Name,
							"original_pod", podName,
						)
						replacementFound = true
						break
					}
				}
			}
		}
	}

	slog.Info("kill-replace complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// quarantine handles both pod quarantine and node cordoning.
// For targets in "namespace/pod-name" format: isolates the pod via NetworkPolicy and labels it.
// For targets that are plain node names (no slash): cordons the node by setting Unschedulable=true.
func (e *k8sEnforcer) quarantine(ctx context.Context, targets []string) error {
	for _, target := range targets {
		if strings.Contains(target, "/") {
			// Pod quarantine: use the isolate mechanism.
			if err := e.isolate(ctx, []string{target}); err != nil {
				return fmt.Errorf("quarantine pod %s: %w", target, err)
			}
			slog.Info("quarantined pod via network isolation", "target", target)
		} else {
			// Node quarantine: cordon the node.
			nodeName := target

			node, err := e.clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("get node %s: %w", nodeName, err)
			}

			node.Spec.Unschedulable = true

			if node.Labels == nil {
				node.Labels = make(map[string]string)
			}
			node.Labels["security-brain/status"] = "quarantined"

			_, err = e.clientset.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("cordon node %s: %w", nodeName, err)
			}

			slog.Info("cordoned node for quarantine",
				"node", nodeName,
				"unschedulable", true,
			)
		}
	}

	slog.Info("quarantine complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// blockEgress creates a NetworkPolicy that allows all ingress traffic but
// blocks all egress traffic for the target pod. This prevents data exfiltration
// while keeping the pod reachable for investigation.
// Target format: "namespace/pod-name".
func (e *k8sEnforcer) blockEgress(ctx context.Context, targets []string) error {
	for _, target := range targets {
		namespace, podName, err := parseNamespacedName(target)
		if err != nil {
			return fmt.Errorf("block-egress: %w", err)
		}

		pod, err := e.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get pod %s: %w", target, err)
		}

		matchLabels := make(map[string]string)
		for k, v := range pod.Labels {
			matchLabels[k] = v
		}
		matchLabels["security-brain/egress-blocked-pod"] = podName

		policyName := "security-brain-block-egress-" + podName

		netpol := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: namespace,
				Labels: map[string]string{
					"security-brain/managed-by": "enforcer-k8s",
					"security-brain/action":     "block-egress",
				},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: matchLabels,
				},
				// Allow all ingress by providing a single rule with no restrictions.
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{},
						From:  []networkingv1.NetworkPolicyPeer{},
					},
				},
				// Empty Egress slice with PolicyTypeEgress listed denies all egress.
				Egress:      []networkingv1.NetworkPolicyEgressRule{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			},
		}

		_, err = e.clientset.NetworkingV1().NetworkPolicies(namespace).Create(ctx, netpol, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create egress block policy %s: %w", policyName, err)
		}

		slog.Info("created egress-block NetworkPolicy",
			"policy", policyName,
			"namespace", namespace,
			"pod", podName,
		)

		// Label the pod to mark egress as blocked.
		if pod.Labels == nil {
			pod.Labels = make(map[string]string)
		}
		pod.Labels["security-brain/egress-blocked"] = "true"
		pod.Labels["security-brain/egress-blocked-pod"] = podName

		_, err = e.clientset.CoreV1().Pods(namespace).Update(ctx, pod, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("label pod %s with egress-blocked: %w", target, err)
		}

		slog.Info("labeled pod with egress-blocked",
			"namespace", namespace,
			"pod", podName,
		)
	}

	slog.Info("egress block complete", "targets", strings.Join(targets, ","), "count", len(targets))
	return nil
}

// revokeCredentials deletes all token secrets associated with a Kubernetes
// ServiceAccount, forcing credential rotation.
// Target format: "namespace/serviceaccount-name".
func (e *k8sEnforcer) revokeCredentials(ctx context.Context, targets []string) error {
	for _, target := range targets {
		namespace, saName, err := parseNamespacedName(target)
		if err != nil {
			return fmt.Errorf("revoke-credentials: %w", err)
		}

		// List all secrets in the namespace that belong to this service account.
		secrets, err := e.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
			FieldSelector: "type=" + string(corev1.SecretTypeServiceAccountToken),
		})
		if err != nil {
			return fmt.Errorf("list secrets for service account %s: %w", target, err)
		}

		deletedCount := 0
		for _, secret := range secrets.Items {
			// Check if this secret's annotation references the target service account.
			annotatedSA, ok := secret.Annotations[corev1.ServiceAccountNameKey]
			if !ok || annotatedSA != saName {
				continue
			}

			err = e.clientset.CoreV1().Secrets(namespace).Delete(ctx, secret.Name, metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("delete secret %s/%s: %w", namespace, secret.Name, err)
			}

			slog.Info("deleted service account token secret",
				"namespace", namespace,
				"service_account", saName,
				"secret", secret.Name,
			)
			deletedCount++
		}

		slog.Info("revoked credentials for service account",
			"namespace", namespace,
			"service_account", saName,
			"secrets_deleted", deletedCount,
		)
	}

	slog.Info("credential revocation complete", "targets", strings.Join(targets, ","), "count", len(targets))
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

