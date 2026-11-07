# ADR-0001 — Tiers are strictly layered; the presentation tier never reaches the data tier

**Status:** accepted  
**Applies to:** every workload carrying app.kubernetes.io/tier  
**Enforced by:** sbob.egress, sbob.ingress, netpol

## Decision

A workload labelled tier=frontend opens connections only to tier=backend and to DNS. A workload labelled tier=database accepts connections only from tier=backend and from its own tier. Tiers reference each other by label selector, never by Service or pod name.

## Why

Tier skipping — the presentation tier querying the data store directly — is the first thing a generated application does, and it defeats every control the backend tier carries (authentication, authorisation, audit). Label selectors survive renames, rewrites and language changes, so the decision does not have to be re-stated per application. The runtime sensor sees the connection from both ends (the sender's profile and the receiver's), so a single stray probe cannot be mistaken for a tier skip.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **coverage** — every pod of tier frontend/backend/database/middleware carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.
* **frontend->backend flow seen on the wire** — at least 1: a captured flow — source tier frontend, destination tier backend.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the presentation tier reached the data tier directly** — the runtime sensor saw an outbound connection the tier profile does not allow — tier frontend, peer tier database or middleware.
* **the data tier accepted a connection from outside the application tier** — the runtime sensor saw an inbound connection the tier profile does not allow — tier database or middleware, peer pod or external or node or unknown, peer tier not backend, middleware, database.
* **the application tier was called by something other than the presentation tier** — the runtime sensor saw an inbound connection the tier profile does not allow — tier backend, peer pod, peer tier not frontend, backend, middleware.
* **a frontend->data-tier flow was captured on the wire** — a captured flow — source tier frontend, destination tier database or middleware.

## How to fix

* the presentation tier reached the data tier directly: route the query through the service labelled tier=backend
* the data tier accepted a connection from outside the application tier: route the query through the service labelled tier=backend; NetworkPolicy backend->database only
* the application tier was called by something other than the presentation tier: identify the caller; if it is legitimate give it tier=frontend, otherwise remove it

## Notes

Network rules are silent while a pod is younger than the warm-up (measured: nothing before ~150 s, reliable from ~210 s). A clean result on a young pod is not a pass; the engine reports NOT_OBSERVED until every pod of the tier is past warm-up and the allowed edge was seen.

## Reproduce without the tooling

```bash
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0011', 'R0012') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
# wire
clickhouse-client -q "SELECT pod, remote_addr, local_port, encrypted, req_path, count() FROM forensic_db.http_events WHERE namespace='<ns>' AND time_ > now()-INTERVAL 1 HOUR GROUP BY ALL"
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| runtime | R0011 | the presentation tier reached the data tier directly |
| runtime | R0012 | the data tier accepted a connection from outside the application tier |
| runtime | R0012 | the application tier was called by something other than the presentation tier |
| wire | captured flow frontend→database, middleware | a frontend->data-tier flow was captured on the wire |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
