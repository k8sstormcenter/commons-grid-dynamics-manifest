# ADR-0004 — Images are immutable at runtime; nothing is installed after build

**Status:** accepted  
**Applies to:** every tier  
**Enforced by:** sbob.execs, sbob.dns, sbob.egress

## Decision

No package manager and no general-purpose fetch tool executes inside a running container. Every dependency is resolved at build time and baked into the image; a running container needs no package repository and no external download.

## Why

Installing at runtime makes the running image unknowable and gives an attacker the tooling they would otherwise have to bring. The process rule is the noisiest of the set (lowest severity): it fires on any binary the profile does not list, so the finding names the binary and the engine discounts processes started by exec probes and by the tracer.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **coverage** — every pod carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **a process ran that is not part of the image's declared behaviour** — the runtime sensor saw a process the profile does not list was launched — tier not unclassified.
* **a DNS lookup was made for a name outside the learned set** — the runtime sensor saw a DNS name outside the learned set was resolved.
* **the workload reached an endpoint outside the cluster that its profile does not declare** — the runtime sensor saw an outbound connection the tier profile does not allow — peer external, tier not database, middleware, not on a prescribed edge.

## How to fix

* a process ran that is not part of the image's declared behaviour: if it is a package manager or fetch tool, move the work into the image build
* a DNS lookup was made for a name outside the learned set: declare the dependency explicitly, or remove it
* the workload reached an endpoint outside the cluster that its profile does not declare: declare the dependency in the tier profile egress, or remove the call

## Reproduce without the tooling

```bash
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0001', 'R0005', 'R0011') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| runtime | R0001 | a process ran that is not part of the image's declared behaviour |
| runtime | R0005 | a DNS lookup was made for a name outside the learned set |
| runtime | R0011 | the workload reached an endpoint outside the cluster that its profile does not declare |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
