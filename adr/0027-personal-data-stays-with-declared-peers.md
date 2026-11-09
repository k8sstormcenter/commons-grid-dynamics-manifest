# ADR-0027 — Personal data leaves the namespace only to the platform IdP, the data tier and declared processors; never to an external address

**Status:** proposed  
**Applies to:** every pod in an application namespace  
**Enforced by:** netpol, sbob.egress, dx-ktls

## Decision

Personal data leaves the namespace only to the platform IdP, the application's own data tier and processors named in the record of processing; never to an external address.

## Why

A third-party call is a processor contract and a transfer question. Egress is read from the sensor and the wire; bodies on cross-namespace hops are checked for personal data.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **coverage** — every pod carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **personal data sent to a peer outside the namespace that is not the platform IdP** — pii — leaves namespace, remote namespace not zitadel, pii class not None, ipv4.
* **egress to an external address** — a captured flow — outbound to outside the cluster, remote external.

## How to fix

* personal data sent to a peer outside the namespace that is not the platform IdP: default-deny egress; declare the processor; never post personal data to an external service
* egress to an external address: default-deny egress with explicit allows

## Reproduce without the tooling

```bash
# wire
clickhouse-client -q "SELECT pod, remote_addr, local_port, encrypted, req_path, count() FROM forensic_db.http_events WHERE namespace='<ns>' AND time_ > now()-INTERVAL 1 HOUR GROUP BY ALL"
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| pii | leaves namespace, remote namespace not zitadel, pii class not None, ipv4 | personal data sent to a peer outside the namespace that is not the platform IdP |
| wire | captured outbound to outside the cluster | egress to an external address |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
