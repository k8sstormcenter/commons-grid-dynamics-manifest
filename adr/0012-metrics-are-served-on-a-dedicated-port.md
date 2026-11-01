# ADR-0012 — Metrics are served on a dedicated port, scraped only by the platform

**Status:** proposed
**Applies to:** `tier=backend`, `tier=middleware`, `tier=database`

## Context

A production workload exposes Prometheus metrics. The default libraries mount `/metrics` on the
same listener as the API, which means the metrics are reachable by whoever can reach the API —
and, if the API is public, by everyone. `/metrics` leaks hostnames, request paths, dependency
addresses, version strings and, from a careless application, label values that are user data.
It also bypasses [ADR-0010](0010-backend-requests-are-authenticated-by-the-platform-idp.md) by
being the one route every framework exempts from authentication.

## Decision

* Every `tier=backend`/`middleware`/`database` workload exposes metrics on a **separate
  containerPort named `metrics`**, never on the port the application serves.
* The metrics port is not in any Service of type `NodePort`/`LoadBalancer` and not in an
  Ingress. It is reached by the platform's scraper through a `ServiceMonitor`/`PodMonitor`
  (or the equivalent scrape annotation), and a NetworkPolicy admits the monitoring namespace
  only ([ADR-0015](0015-ingress-is-the-platforms.md)).
* `/metrics` on the application port answers `404`. A `200` there is the violation.
* Metric labels carry no user-supplied values (no raw path with ids, no e-mail, no tenant name).

## Verified by

**Live probe (mechanical)** — `GET /metrics` on the application Service port: expect `404`
(or `401`). `GET /metrics` on the `metrics` containerPort from the evaluator: expect `200` with
`# TYPE` lines — the metrics exist and are where they belong.

**Static** — the pod template: a containerPort named `metrics`; no Service exposing it outside
the cluster; a `ServiceMonitor`/`PodMonitor` or scrape annotation selecting the workload.

**Runtime (Pixie `http_events`)** — requests to `/metrics` whose source is not the monitoring
namespace's scraper.

## Evidence emitted

```
ADR-0012 VIOLATED   METRICS_ON_APPLICATION_PORT
  observed  GET http://commons-grid-api:8000/metrics -> 200 (1.2 KB, 47 series)
  observed  no containerPort named metrics; no ServiceMonitor selects app=commons-grid-api
  fix       serve metrics on :9090 named "metrics"; 404 /metrics on :8000; add a ServiceMonitor;
            NetworkPolicy: metrics port from namespace monitoring only
```

## Consequences

* The platform's scraper is the only consumer; dashboards come from the platform's Prometheus,
  not from the application's Service.
* Frameworks that only support one listener need the metrics handler mounted in a second
  server process or a sidecar exporter — which is fine, the sidecar is still the same pod and
  the same profile.
