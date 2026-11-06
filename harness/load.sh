#!/usr/bin/env bash
# harness/load.sh <namespace> [seconds]   — put realistic traffic on the application before it is judged.
# Picks, in this order:
#   1. deploy-loadgen.yaml in the repo root     the application's own generator (iteration ≥1 deliverable):
#                                               applied as is; expected in namespace <ns>-load, driving the ingress host
#   2. load/k6.js in the repo root              the k6 script from the functional/integration suite (iteration 0 deliverable):
#                                               run in-cluster as a Job in namespace <ns>-load against BASE_URL
#   3. compliance/drive.py                      the harness's browser stand-in (GET /, scripts, /api paths)
# Every request the generator sends carries User-Agent adr-driver/<tool> and X-Test-Case: <use case>, so the wire
# evidence counts it as application traffic and the proof names the use cases that exercised each edge.
set -euo pipefail
cd "$(dirname "$0")/.."
NS=${1:?namespace}; SECONDS_=${2:-120}
LOADNS="$NS-load"
K6_IMAGE=${K6_IMAGE:-grafana/k6:0.54.0}

base_url() {  # the browser's entry point: ingress host (https) if one fronts the frontend, else the frontend Service
  python3 - "$NS" <<'PY'
import sys, os
sys.path.insert(0, "compliance"); import evidence, time
ns = sys.argv[1]
ev = evidence.Evidence.static(ns)
row = next(e for e in ev.events["ingress"] if e["scope"] == "namespace")
if row["fronts_frontend"] and row["hosts"]:
    print("https://" + row["hosts"][0]); sys.exit()
for sv in evidence.kget(["-n", ns, "get", "svc"]):
    if sv["metadata"]["name"] in row["frontend_services"] and sv["spec"].get("ports"):
        print(f"http://{sv['spec']['clusterIP']}:{sv['spec']['ports'][0]['port']}"); sys.exit()
for p in ev.events["pod"]:
    if p["tier"] == "frontend" and p["http_port"]:
        print(f"http://{p['ip']}:{p['http_port']}"); sys.exit()
PY
}

if [ -f deploy-loadgen.yaml ]; then
  echo "load: application generator deploy-loadgen.yaml"
  kubectl create namespace "$LOADNS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$LOADNS" apply -f deploy-loadgen.yaml
  kubectl -n "$LOADNS" rollout restart deploy >/dev/null 2>&1 || true     # a changed suite ConfigMap does not restart the generator by itself
  kubectl -n "$LOADNS" rollout status deploy --timeout=180s || true
  sleep "$SECONDS_"
elif [ -f load/k6.js ]; then
  URL=$(base_url); echo "load: k6 script load/k6.js against $URL for ${SECONDS_}s (in-cluster Job, $K6_IMAGE)"
  kubectl create namespace "$LOADNS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$LOADNS" delete job k6 --ignore-not-found --wait=true >/dev/null
  kubectl -n "$LOADNS" create configmap k6-script --from-file=k6.js=load/k6.js --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  cat <<YAML | kubectl -n "$LOADNS" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata: {name: k6}
spec:
  backoffLimit: 0
  template:
    metadata: {labels: {app.kubernetes.io/component: loadgen}}
    spec:
      restartPolicy: Never
      containers:
        - name: k6
          image: $K6_IMAGE
          args: ["run", "--insecure-skip-tls-verify", "/scripts/k6.js"]
          env: [{name: BASE_URL, value: "$URL"}, {name: DURATION, value: "${SECONDS_}s"}]
          volumeMounts: [{name: script, mountPath: /scripts}]
      volumes: [{name: script, configMap: {name: k6-script}}]
YAML
  kubectl -n "$LOADNS" wait --for=condition=complete "job/k6" --timeout=$((SECONDS_ + 180))s || kubectl -n "$LOADNS" logs job/k6 --tail=20
  kubectl -n "$LOADNS" logs job/k6 --tail=25 | grep -E 'http_reqs|checks|iterations|X-Test-Case|scenario' || true
else
  echo "load: harness browser stand-in (compliance/drive.py) — no load/k6.js, no deploy-loadgen.yaml"
  python3 compliance/drive.py "$NS" "${DRIVE_ROUNDS:-3}"
fi
