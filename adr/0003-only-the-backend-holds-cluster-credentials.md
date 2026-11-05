# ADR-0003 — Only the backend tier holds cluster credentials

**Status:** accepted  
**Applies to:** tier=frontend, tier=database, tier=middleware  
**Enforced by:** sbob.opens, kyverno.validate

## Decision

Only tier=backend may mount and read the ServiceAccount token. Every other tier sets automountServiceAccountToken: false, and only the backend tier profile lists the token path.

## Why

The presentation tier is the most exposed surface and has no business with the cluster API. A token it never mounted cannot be stolen through it. The static check lists every pod that could read the token; the runtime check lists the ones that did — the shorter, more urgent list.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **non-backend containers' automountServiceAccountToken read from the pod spec** — at least 1: a container in the pod spec — tier not backend.
* **coverage** — every pod carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the workload read a cluster credential or sensitive file** — the runtime sensor saw the ServiceAccount token was read or a sensitive file was read — tier not backend.
* **the ServiceAccount token is mounted into a non-backend tier** — a container in the pod spec — automountServiceAccountToken true, tier not backend.

## How to fix

* the workload read a cluster credential or sensitive file: set automountServiceAccountToken=false; nothing outside tier=backend reads the token
* the ServiceAccount token is mounted into a non-backend tier: set spec.template.spec.automountServiceAccountToken = false

## Reproduce without the tooling

```bash
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0006', 'R0010') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| runtime | R0006 / R0010 | the workload read a cluster credential or sensitive file |
| spec | automountServiceAccountToken true, tier not backend | the ServiceAccount token is mounted into a non-backend tier |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
