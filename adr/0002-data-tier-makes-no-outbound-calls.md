# ADR-0002 — The data tier never initiates outbound connections

**Status:** accepted  
**Applies to:** tier=database, tier=middleware  
**Enforced by:** sbob.egress, netpol

## Decision

tier=database egress is limited to DNS and its own tier's replication ports. tier=middleware may additionally reach the database tier and its own cluster ports. Neither reaches anything outside the cluster. Backups, telemetry and extension downloads run as separate workloads labelled tier=backend.

## Why

A data store that initiates outbound connections has the shape of an exfiltration, a plugin download or a misplaced batch job. For this tier a single observed egress is already conclusive: the receiver is outside the cluster and cannot corroborate, and it does not need to.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **coverage** — every pod of tier database/middleware carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the data tier initiated an outbound connection** — the runtime sensor saw an outbound connection the tier profile does not allow — tier database or middleware, peer not dns, not on a prescribed edge.

## How to fix

* the data tier initiated an outbound connection: remove the outbound call; if a database genuinely needs egress it belongs in a job labelled tier=backend

## Reproduce without the tooling

```bash
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0011') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| runtime | R0011 | the data tier initiated an outbound connection |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
