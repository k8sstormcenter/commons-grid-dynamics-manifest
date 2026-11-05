# ADR-0006 — Workloads run as non-root

**Status:** accepted  
**Applies to:** every tier  
**Enforced by:** kyverno.validate, sbob.capabilities

## Decision

Containers set runAsNonRoot: true, a numeric runAsUser and allowPrivilegeEscalation: false. Where a rootless image variant exists, it is used. (The read-only root filesystem is ADR-0004's.)

## Why

An image whose entrypoint starts as root and drops privileges uses capabilities on the way down; the runtime sensor sees that as capability use against a profile that lists none. The manifest fields are the declared half; the capability event is the observed half. A finding read from the manifest ranks below one the sensor actually saw.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **containers' securityContext read from the pod spec** — at least 1: a container in the pod spec.
* **kubescape scan supplied (insecure capabilities / host namespaces)** — at least 1: the kubescape scan — supplied.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the container used a Linux capability, i.e. it starts as root and drops** — the runtime sensor saw a Linux capability the profile does not list was used.
* **container may run as root** — a container in the pod spec — runAsNonRoot not true.
* **privilege escalation is permitted** — a container in the pod spec — allowPrivilegeEscalation not false.
* **insecure capabilities requested** — the static scan flagged insecure capabilities.

## How to fix

* the container used a Linux capability, i.e. it starts as root and drops: switch to the rootless/distroless image variant; this is an image choice, not a profile gap
* container may run as root: set securityContext.runAsNonRoot = true and a numeric runAsUser
* privilege escalation is permitted: set securityContext.allowPrivilegeEscalation = false
* insecure capabilities requested: drop the capability (capabilities.drop [ALL])

## Reproduce without the tooling

```bash
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0004') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
# scan
kubescape scan framework AllControls --include-namespaces <ns> --format json --output /tmp/AllControls-<ns>.json
# scan_present
ls -l /tmp/AllControls-<ns>.json   # the scan file the evaluator was given
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| runtime | R0004 | the container used a Linux capability, i.e. it starts as root and drops |
| spec | runAsNonRoot not true | container may run as root |
| spec | allowPrivilegeEscalation not false | privilege escalation is permitted |
| scan | C-0046 | insecure capabilities requested |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
