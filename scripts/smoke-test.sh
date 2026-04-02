#!/usr/bin/env bash
# End-to-end smoke test for security-brain.
# Requires: docker compose running (docker compose up -d)
#           OR control plane running locally
#
# This script proves the full pipeline works:
#   1. Health check passes
#   2. Inject a critical event via the API
#   3. Verify an incident was created
#   4. Verify audit records exist
#   5. Inject 3 weak signals to test correlation
#   6. Verify compound incident was created
set -euo pipefail

API="${SECURITY_BRAIN_API:-http://localhost:8080}"
PASS=0
FAIL=0

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "true" ]; then
    echo "  PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== Security Brain Smoke Test ==="
echo "API: $API"
echo ""

# --- Test 1: Health check ---
echo "[1/6] Health check..."
HEALTH=$(curl -sf "$API/healthz" 2>/dev/null || echo '{}')
STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
check "GET /healthz returns ok" "$([ "$STATUS" = "ok" ] && echo true || echo false)"

# --- Test 2: Inject critical event ---
echo "[2/6] Injecting critical event..."
INJECT=$(curl -sf -X POST "$API/api/v1/events" \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "runtime",
    "source_vendor": "test",
    "asset_id": "smoke-test-1",
    "asset_type": "internal-service",
    "workload_id": "default/smoke-test-pod",
    "identity_id": "system:serviceaccount:default:test",
    "environment": "smoke-test",
    "signal_class": "credential-exfiltration",
    "severity": "critical",
    "confidence": 0.95,
    "observables": {"smoke_test": true},
    "evidence_refs": [],
    "suggested_actions": ["quarantine"],
    "blast_radius_hint": "service"
  }' 2>/dev/null || echo '{}')
INJECT_STATUS=$(echo "$INJECT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
check "POST /api/v1/events returns accepted" "$([ "$INJECT_STATUS" = "accepted" ] && echo true || echo false)"

# Give the pipeline a moment to process
sleep 2

# --- Test 3: Verify incident was created ---
echo "[3/6] Checking for incidents..."
INCIDENTS=$(curl -sf "$API/api/v1/incidents" 2>/dev/null || echo '[]')
INCIDENT_COUNT=$(echo "$INCIDENTS" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data) if isinstance(data, list) else 0)" 2>/dev/null || echo "0")
check "Incidents exist after critical event" "$([ "$INCIDENT_COUNT" -gt 0 ] && echo true || echo false)"

# --- Test 4: Verify audit records ---
echo "[4/6] Checking audit trail..."
AUDIT=$(curl -sf "$API/api/v1/audit" 2>/dev/null || echo '[]')
AUDIT_COUNT=$(echo "$AUDIT" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data) if isinstance(data, list) else 0)" 2>/dev/null || echo "0")
check "Audit records exist" "$([ "$AUDIT_COUNT" -gt 0 ] && echo true || echo false)"

# --- Test 5: Inject 3 weak signals for correlation ---
echo "[5/6] Injecting 3 weak signals for correlation test..."
for signal_class in "anomalous-dns" "credential-access" "egress-to-unknown"; do
  curl -sf -X POST "$API/api/v1/events" \
    -H "Content-Type: application/json" \
    -d "{
      \"source_type\": \"runtime\",
      \"source_vendor\": \"test\",
      \"asset_id\": \"smoke-correlate-1\",
      \"asset_type\": \"internal-service\",
      \"workload_id\": \"default/correlate-pod\",
      \"identity_id\": \"system:serviceaccount:default:test\",
      \"environment\": \"smoke-test\",
      \"signal_class\": \"$signal_class\",
      \"severity\": \"medium\",
      \"confidence\": 0.4,
      \"observables\": {\"smoke_test\": true, \"signal\": \"$signal_class\"},
      \"evidence_refs\": [],
      \"suggested_actions\": [\"detect_only\"],
      \"blast_radius_hint\": \"isolated\"
    }" > /dev/null 2>&1
  sleep 0.5
done

sleep 2

# --- Test 6: Verify correlation produced a second incident ---
echo "[6/6] Checking for correlated incident..."
INCIDENTS2=$(curl -sf "$API/api/v1/incidents" 2>/dev/null || echo '[]')
INCIDENT_COUNT2=$(echo "$INCIDENTS2" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data) if isinstance(data, list) else 0)" 2>/dev/null || echo "0")
check "Multiple incidents after correlation" "$([ "$INCIDENT_COUNT2" -gt "$INCIDENT_COUNT" ] && echo true || echo false)"

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "SMOKE TEST FAILED"
  exit 1
else
  echo "SMOKE TEST PASSED"
fi
