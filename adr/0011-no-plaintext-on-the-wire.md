# ADR-0011 — No plaintext on the wire

**Status:** proposed
**Applies to:** every tier; every Service and Ingress

## Context

A bearer token ([ADR-0010](0010-backend-requests-are-authenticated-by-the-platform-idp.md))
sent over plaintext HTTP is a credential on the wire. The first fixture served everything on
`http://<node>:30080`; a split version of it would, by default, call its backend over
`http://commons-grid-api:8000` and its database over an unencrypted postgres socket.

The platform can see this. Pixie's protocol tracers decode plaintext HTTP, postgres and redis
from the socket; traffic they cannot decode as plaintext is either TLS or not a protocol they
know. The kTLS/uprobe taps decode TLS *inside* the process for the trace, so going to TLS does
not cost observability — it only changes which tap carries the evidence.

## Decision

* Anything that leaves a pod is TLS: browser → frontend (terminated at the platform ingress),
  frontend → backend, backend → database, backend → IdP, backend → anything external.
* The platform terminates browser TLS at the ingress and issues workload certificates
  (cert-manager / mesh); applications consume a mounted certificate, they do not generate or
  commit one.
* The data tier requires TLS (`ssl=on` + `hostssl` only for postgres; `tls-port` only for
  redis) so a plaintext client fails to connect rather than silently downgrading.

## Verified by

**Pixie `http_events` / `pgsql_events` / `redis_events` (runtime)** — a decoded plaintext
request whose destination is a pod in this namespace, on a path other than loopback, is a
violation; the row names source pod, destination pod, port and path. Health and metrics
endpoints scraped by the platform are exempt by port ([ADR-0012](0012-metrics-are-served-on-a-dedicated-port.md)).

**kTLS tap (corroborating)** — the same request appearing in the TLS tap and not in the
plaintext tracer is the compliant signature.

**Static** — the Service and Ingress objects: an Ingress without `tls:` or a Service that
exposes a known plaintext port (80, 8000, 5432, 6379) to anything but its own namespace.

## Evidence emitted

```
ADR-0011 VIOLATED   PLAINTEXT_ON_THE_WIRE
  observed  http_events: commons-grid-web -> commons-grid-api:8000 GET /simulate (plaintext, 200)
  observed  pgsql_events: commons-grid-api -> commons-grid-db:5432 SELECT ... (plaintext)
  fix       mount the platform-issued certificate; serve https on the backend; sslmode=verify-full
            on the postgres client, ssl=on hostssl-only on the server; browser TLS at the ingress
```

## Consequences

* Plaintext evidence stops; the trace moves to the TLS tap. The dx-ktls tap must be running on
  the node for the compliant case to be *observed* rather than merely *not violated* — the KPI
  distinguishes the two.
* Local development with `http://` works until the manifest is applied to the platform, where
  it is a finding on the first request.
