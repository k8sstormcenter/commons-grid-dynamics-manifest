# ADR-0012 — Metrics are served on a dedicated port, scraped only by the platform

**Status:** proposed  
**Applies to:** tier=backend, tier=middleware, tier=database  
**Enforced by:** kyverno.validate, netpol

## Decision

Every tier=backend, tier=middleware and tier=database workload exposes metrics on a separate containerPort named metrics, reached only from the monitoring namespace. /metrics on the application port answers 404. Metric labels carry no user-supplied values.

## Why

Metrics on the application port are an unauthenticated read endpoint (ADR-0010 exempts them) and the first place internals leak. A dedicated, named port is what a NetworkPolicy and a scrape config can select.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **containerPort names read from the pod spec** — at least 1: a container in the pod spec — tier backend or middleware or database.
* **/metrics probed on the application port** — at least 1: an evaluator HTTP probe — path /metrics.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **no dedicated metrics port** — a container in the pod spec — tier backend or middleware or database, no containerPort named metrics.
* **/metrics served on the application port** — an evaluator HTTP probe — path /metrics, Authorization none, HTTP status 200.
* **metrics scraped by something other than the platform** — a captured flow — protocol http, path /metrics, HTTP status 200, remote not evaluator, node, remote namespace not monitoring.

## How to fix

* no dedicated metrics port: expose metrics on a second containerPort named metrics; add a ServiceMonitor/PodMonitor
* /metrics served on the application port: serve metrics on a port named metrics; 404 /metrics on the application port
* metrics scraped by something other than the platform: NetworkPolicy: metrics port from namespace monitoring only

## Reproduce without the tooling

```bash
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
# probe
curl -sk -o /dev/null -w '%{http_code}\n' http://<backend-pod-ip>:<port><route>   # then with -H 'Authorization: Bearer not.a.token', then with a platform-minted token
# wire
clickhouse-client -q "SELECT pod, remote_addr, local_port, encrypted, req_path, count() FROM forensic_db.http_events WHERE namespace='<ns>' AND time_ > now()-INTERVAL 1 HOUR GROUP BY ALL"
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| spec | tier backend or middleware or database, no containerPort named metrics | no dedicated metrics port |
| probe | GET /metrics with Authorization=none | /metrics served on the application port |
| wire | captured GET /metrics from outside monitoring | metrics scraped by something other than the platform |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
