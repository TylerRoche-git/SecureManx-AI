package pluginapi

import "context"

// ImageRef identifies a container image with its trust anchors.
type ImageRef struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
}

// DeploySpec describes a workload to be redeployed from trusted state.
type DeploySpec struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Image     ImageRef `json:"image"`
	Replicas  int32    `json:"replicas"`
}

// RecoveryProvider handles rebuilding workloads from verified, trusted artefacts.
type RecoveryProvider interface {
	// Name returns a human-readable identifier for this recovery provider.
	Name() string

	// VerifyImage checks that the image matches its trust anchor (signature + hash).
	VerifyImage(ctx context.Context, ref ImageRef) error

	// Redeploy replaces a workload with a verified image.
	Redeploy(ctx context.Context, spec DeploySpec) error

	// Rollback reverses a redeployment.
	Rollback(ctx context.Context, deploymentID string) error
}
