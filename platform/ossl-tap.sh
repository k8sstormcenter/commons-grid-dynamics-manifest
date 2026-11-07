#!/usr/bin/env bash
# ./platform/ossl-tap.sh <namespace> [container-name]   — start the OpenSSL tap on the namespace's frontend pod
# ./platform/ossl-tap.sh --stop                          — remove it (and its event file)
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${1:-}" = "--stop" ]; then kubectl -n honey delete pod ossl-tap-frontend --ignore-not-found; exit 0; fi
NS=${1:?namespace}; C=${2:-web}
export CID=$(kubectl -n "$NS" get pod -l app.kubernetes.io/tier=frontend -o jsonpath="{.items[0].status.containerStatuses[?(@.name==\"$C\")].containerID}" | sed 's#.*://##')
export NODE=$(kubectl -n "$NS" get pod -l app.kubernetes.io/tier=frontend -o jsonpath='{.items[0].spec.nodeName}')
[ -n "$CID" ] && [ -n "$NODE" ] || { echo "no frontend pod/container $C in $NS"; exit 1; }
envsubst '${CID} ${NODE}' < platform/ossl-tap.yaml | kubectl apply -f -
kubectl -n honey wait pod/ossl-tap-frontend --for=condition=Ready --timeout=120s
