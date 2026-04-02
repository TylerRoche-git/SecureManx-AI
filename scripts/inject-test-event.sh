#!/usr/bin/env bash
# Inject a test event into the security-brain pipeline via the control plane API.
# Usage: ./scripts/inject-test-event.sh [critical|medium|low]
#
# The event is published to NATS and flows through:
#   ingest → normalize → correlate → policy → playbook → audit
#
# After injection, query incidents to see results:
#   curl http://localhost:8080/api/v1/incidents
set -euo pipefail

API="${SECURITY_BRAIN_API:-http://localhost:8080}"
SEVERITY="${1:-medium}"

case "$SEVERITY" in
  critical)
    CONFIDENCE=0.95
    SIGNAL_CLASS="credential-exfiltration"
    ;;
  medium)
    CONFIDENCE=0.5
    SIGNAL_CLASS="anomalous-egress"
    ;;
  low)
    CONFIDENCE=0.2
    SIGNAL_CLASS="routine-scan"
    ;;
  *)
    echo "Usage: $0 [critical|medium|low]"
    exit 1
    ;;
esac

EVENT=$(cat <<ENDJSON
{
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
  "observables": {"test": true, "injected_by": "inject-test-event.sh"},
  "evidence_refs": [],
  "suggested_actions": ["detect_only"],
  "blast_radius_hint": "isolated"
}
ENDJSON
)

echo "Injecting $SEVERITY event to $API/api/v1/events..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API/api/v1/events" \
  -H "Content-Type: application/json" \
  -d "$EVENT")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

if [ "$HTTP_CODE" = "202" ]; then
  echo "Accepted: $BODY"
  echo ""
  echo "Wait a moment, then check:"
  echo "  curl $API/api/v1/incidents"
  echo "  curl $API/api/v1/audit"
else
  echo "Failed (HTTP $HTTP_CODE): $BODY"
  exit 1
fi
