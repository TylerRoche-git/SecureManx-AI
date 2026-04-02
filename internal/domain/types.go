package domain

import (
	"os"
	"time"

	"github.com/security-brain/security-brain/pkg/eventschema"
)

// CorrelationWindow groups events that occurred within a sliding time window
// for analysis by the correlation engine.
type CorrelationWindow struct {
	Duration  time.Duration        `json:"duration"`
	Events    []*eventschema.Event `json:"events"`
	StartedAt time.Time            `json:"started_at"`
}

// ControlPlaneConfig holds all configuration for the security-brain control plane.
type ControlPlaneConfig struct {
	NATSUrl           string        `json:"nats_url"`
	PostgresDSN       string        `json:"postgres_dsn"`
	PolicyDir         string        `json:"policy_dir"`
	PlaybooksDir      string        `json:"playbooks_dir"`
	APIAddr           string        `json:"api_addr"`
	CorrelationWindow time.Duration `json:"correlation_window"`
}

// LoadConfig reads configuration from environment variables, applying sensible
// defaults for any value that is not set. It returns a fully populated
// ControlPlaneConfig. The error return is reserved for future validation but
// is always nil with the current implementation.
func LoadConfig() (*ControlPlaneConfig, error) {
	cfg := &ControlPlaneConfig{
		NATSUrl:           envOrDefault("NATS_URL", "nats://localhost:4222"),
		PostgresDSN:       envOrDefault("POSTGRES_DSN", "postgres://secbrain:secbrain@localhost:5432/secbrain?sslmode=disable"),
		PolicyDir:         envOrDefault("POLICY_DIR", "/etc/security-brain/policies"),
		PlaybooksDir:      envOrDefault("PLAYBOOKS_DIR", "/etc/security-brain/playbooks"),
		APIAddr:           envOrDefault("API_ADDR", ":8080"),
		CorrelationWindow: parseDurationOrDefault("CORRELATION_WINDOW", 5*time.Minute),
	}

	return cfg, nil
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseDurationOrDefault reads the named environment variable and parses it as
// a Go duration string (e.g., "10m", "30s"). If the variable is empty or
// cannot be parsed, the provided fallback duration is returned.
func parseDurationOrDefault(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
