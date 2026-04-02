package sentinel

import "time"

// Heartbeat is published periodically to prove the control plane is alive and
// unmodified. External monitors (such as the watchdog) consume this signal to
// verify continuous operation and integrity.
type Heartbeat struct {
	Timestamp     time.Time `json:"timestamp"`
	BinaryHash    string    `json:"binary_hash"`
	PolicyHash    string    `json:"policy_hash"`
	CanaryOK      bool      `json:"canary_ok"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	Version       string    `json:"version"`
}

// HeartbeatSubject is the NATS subject on which the sentinel publishes its
// periodic heartbeat.
const HeartbeatSubject = "security.sentinel.heartbeat"

// Version is the current sentinel protocol version.
const Version = "0.1.0"
