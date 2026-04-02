#!/usr/bin/env bash
# Inject a test event via the NATS CLI or direct publish.
# Usage: ./scripts/inject-test-event.sh [critical|medium|low]
set -euo pipefail

SEVERITY="${1:-medium}"
CONFIDENCE="0.5"
SIGNAL_CLASS="test-signal"

case "$SEVERITY" in
  critical) CONFIDENCE="0.95"; SIGNAL_CLASS="credential-exfiltration" ;;
  medium)   CONFIDENCE="0.5";  SIGNAL_CLASS="anomalous-egress" ;;
  low)      CONFIDENCE="0.2";  SIGNAL_CLASS="routine-scan" ;;
esac

EVENT=$(cat <<ENDJSON
{
  "event_id": "$(uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_type": "runtime",
  "source_vendor": "test",
  "asset_id": "test-workload-1",
  "asset_type": "internal-service",
  "workload_id": "default/test-pod",
  "identity_id": "system:serviceaccount:default:test",
  "environment": "test",
  "signal_class": "$SIGNAL_CLASS",
  "severity": "$SEVERITY",
  "confidence": $CONFIDENCE,
  "observables": {"test": true},
  "evidence_refs": [],
  "suggested_actions": ["detect_only"],
  "blast_radius_hint": "isolated"
}
ENDJSON
)

echo "Injecting $SEVERITY event..."
echo "$EVENT" | nats pub security.events.raw 2>/dev/null || \
  curl -s -X POST http://localhost:8080/api/v1/events -d "$EVENT" -H "Content-Type: application/json" || \
  echo "Could not inject event. Is the control plane running?"

echo "Done. Check http://localhost:8080/api/v1/incidents"
