#!/usr/bin/env bash
# Ensure the evaluator's in-cluster probe pods exist and are Running (one per namespace the application's
# NetworkPolicies admit: the load namespace for the API, monitoring for the metrics ports). The evaluator's
# http() falls back to `kubectl exec <probe> -- curl` when the host is not admitted (ADR_PROBE_PODS).
#   ./platform/adr-probe.sh [<app-namespace>]        default commons-grid -> commons-grid-load + monitoring
#   ./platform/adr-probe.sh --stop
set -euo pipefail
IMG=${ADR_PROBE_IMAGE:-curlimages/curl:8.11.1}
if [ "${1:-}" = "--stop" ]; then
  for ns in ${ADR_PROBE_NAMESPACES:-commons-grid-load monitoring}; do kubectl -n "$ns" delete pod adr-probe --ignore-not-found; done; exit 0
fi
APP=${1:-commons-grid}
for ns in ${ADR_PROBE_NAMESPACES:-${APP}-load monitoring}; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  phase=$(kubectl -n "$ns" get pod adr-probe -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [ "$phase" != "Running" ]; then
    kubectl -n "$ns" delete pod adr-probe --ignore-not-found --wait=true >/dev/null
    kubectl -n "$ns" run adr-probe --image="$IMG" --restart=Never --labels=app=adr-probe --command -- sleep infinity >/dev/null
  fi
  kubectl -n "$ns" wait pod/adr-probe --for=condition=Ready --timeout=120s >/dev/null
  echo "$ns/adr-probe $(kubectl -n "$ns" get pod adr-probe -o jsonpath='{.status.phase} {.status.podIP}')"
done
