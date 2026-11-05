#!/usr/bin/env bash
# One iteration of the fix-and-verify loop:
#   ./harness/loop.sh <N> [namespace] [manifest]       default: commons-grid, deploy-iter<N>.yaml
# records the time, applies the manifest, scans, WAITS until every pod is past the sensor's
# warm-up, DRIVES the application, evaluates (compliance/engine.py over compliance/adrs.yaml)
# into artefacts/kpi-<ns>-iter<N>.json, writes the rows to forensic_db.adr_findings and asks
# the MCP what the coding agent would be told.
# Needs ADR_CH (ClickHouse HTTP DSN), kubectl, kubescape, python3 + PyYAML.
set -euo pipefail
cd "$(dirname "$0")/.."
N=${1:?iteration}; NS=${2:-commons-grid}; MANIFEST=${3:-deploy-iter$N.yaml}
: "${ADR_CH:?ADR_CH=http://ingest_writer:changeme-ingest@<clickhouse>:8123}"
SCAN_DIR=${ADR_SCAN_DIR:-/tmp}
WARMUP=${WARMUP:-210}          # seconds a pod must be old before network rules are reliable (ADR-0005, measured)
export ADR_ITERATION=$N

kubectl -n honey rollout status ds/node-agent --timeout=300s >/dev/null   # never deploy into a rolling sensor
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
mkdir -p artefacts
SINCE=$(date -u +%s); echo "$SINCE" > "artefacts/iter$N-since"
kubectl -n "$NS" apply -f "$MANIFEST"
kubectl -n "$NS" rollout status deploy --timeout=300s || true
kubectl -n "$NS" get pods -o custom-columns='POD:.metadata.name,TIER:.metadata.labels.app\.kubernetes\.io/tier,PROFILE:.metadata.labels.kubescape\.io/user-defined-profile,STATUS:.status.phase'

# warm-up: wait until the YOUNGEST running pod is $WARMUP s old
while :; do
  YOUNGEST=$(kubectl -n "$NS" get pods -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.status.startTime}{"\n"}{end}' \
             | while read -r t; do echo $(( $(date -u +%s) - $(date -u -d "$t" +%s) )); done | sort -n | head -1)
  [ -n "${YOUNGEST:-}" ] && [ "$YOUNGEST" -ge "$WARMUP" ] && break
  echo "warm-up: youngest pod ${YOUNGEST:-?}s / ${WARMUP}s"; sleep 15
done

python3 compliance/drive.py "$NS" "${DRIVE_ROUNDS:-3}"                      # browser-shaped traffic over the prescribed edges
sleep "${SETTLE:-30}"                                                        # let the alerts and the Pixie rows land
ADR_SCAN_DIR="$SCAN_DIR" compliance/scan.sh "$NS" AllControls
python3 compliance/adr_kpi.py "$NS" --since "$SINCE" --scan "$SCAN_DIR/AllControls-$NS.json" --out "artefacts/kpi-$NS-iter$N.json"
python3 compliance/kpi_to_ch.py "artefacts/kpi-$NS-iter$N.json" "$N" harness

# the same evaluator, through the MCP: what the coding agent is told
{
  printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"loop","version":"0"}}}\n'
  printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"adr_architecture","arguments":{"namespace":"%s"}}}\n' "$NS"
  printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"adr_recheck","arguments":{"namespace":"%s","since_epoch":%s}}}\n' "$NS" "$SINCE"
  printf '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"adr_violations","arguments":{"namespace":"%s","since_minutes":%s}}}\n' "$NS" "$(( ($(date -u +%s) - SINCE) / 60 + 1 ))"
} | ADR_SCAN_DIR="$SCAN_DIR" python3 compliance/adr_mcp.py > "artefacts/iter$N-mcp.jsonl"

python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d['summary']))" "artefacts/kpi-$NS-iter$N.json"
echo "feedback for the coding agent: artefacts/iter$N-mcp.jsonl (previous rounds: harness/feedback/)"
