#!/usr/bin/env bash
# Regenerates sbobs/cp-tier-*.yaml from fragments/: one generic base per tier, minus the
# subtract fragments. Every tier gets the runtime-tooling and sensitive-file subtracts; every
# tier except backend also gets the cluster-credentials subtract. git diff shows any drift.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd)
F="$D/fragments"
for t in frontend backend database middleware unclassified; do
  extra=("$F/subtract-cluster-credentials.yaml")
  [ "$t" = backend ] && extra=()
  ${BOBCTL:-bobctl} compose --name "tier-$t" -n sbob-library -o "$D/cp-tier-$t.yaml" \
    "$F/base-$t.yaml" "$F/subtract-runtime-tooling.yaml" "$F/subtract-sensitive-files.yaml" "${extra[@]}"
done
