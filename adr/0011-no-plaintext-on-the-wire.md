# ADR-0011 — No plaintext on the wire

**Status:** proposed  
**Applies to:** every tier; every Service and every exposure of the application  
**Enforced by:** platform-ingress, cert-manager, app-config

## Decision

Anything that leaves a pod is TLS, and the application is reachable only through the platform's tailnet exposure of its frontend Service: the exposed port is the frontend's own TLS port, frontend→backend, backend→database, backend→identity provider and backend→external are TLS. Workloads consume platform-issued certificates; they do not generate or commit their own. The data tier requires TLS so that a plaintext client fails instead of silently downgrading. Nothing is reachable over plaintext by bypassing the ingress.

## Why

A bearer token on a plaintext wire is a token for everyone on the path. The hosting path is observed, not assumed: the ingress/gateway object declares the TLS termination point, the wire tracer shows whether the ingress reaches the frontend over TLS, whether anything reaches it directly (NodePort, pod IP), whether tiers talk plaintext to each other, and whether any pod sends plaintext outside the cluster. Health probes and the evaluator's own requests are discounted; the traffic driver takes the browser's path through the ingress and counts as application traffic.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **the frontend is exposed through the platform (tailnet-exposed Service)** — at least 1: an ingress/gateway object — namespace-wide, fronting the frontend.
* **application flows captured on the wire (Pixie)** — at least 1: a captured flow — protocol http or pgsql or conn, remote not evaluator.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the platform ingress reaches the frontend over plaintext (TLS stops at the ingress instead of continuing to the pod)** — a captured flow — inbound, protocol http, plaintext, remote ingress, not a health path.
* **reached over plaintext bypassing the platform ingress (NodePort, direct Service or pod access)** — a captured flow — inbound, protocol http, plaintext, remote driver or external or unknown, not a health path.
* **plaintext between tiers** — a captured flow — protocol http or pgsql, plaintext, remote pod, not a health path.
* **plaintext egress to outside the cluster** — a captured flow — outbound to outside the cluster, plaintext, protocol http or pgsql.
* **plaintext port exposed outside the cluster** — a Service — type NodePort/LoadBalancer, a plaintext port exposed.
* **the exposed frontend endpoint is plaintext (the Service port exposed on the tailnet is not TLS)** — an ingress/gateway object — per object, fronting the frontend, without spec.tls.

## How to fix

* the platform ingress reaches the frontend over plaintext (TLS stops at the ingress instead of continuing to the pod): serve TLS on the frontend from a platform-issued certificate; point the ingress/gateway at the TLS port
* reached over plaintext bypassing the platform ingress (NodePort, direct Service or pod access): expose the frontend only through the platform ingress/gateway with TLS; ClusterIP Services
* plaintext between tiers: TLS from platform-issued certificates on every inter-tier hop; clients verify; postgres ssl=on hostssl-only
* plaintext egress to outside the cluster: use https/TLS for every external dependency
* plaintext port exposed outside the cluster: ClusterIP + Ingress with tls
* the exposed frontend endpoint is plaintext (the Service port exposed on the tailnet is not TLS): serve TLS on the frontend from a platform-issued certificate; expose only the https port

## Notes

The browser→ingress TLS handshake itself is not captured in the application namespace; it is judged from the ingress object's TLS declaration (a kernel-TLS tap can corroborate it when exported). Wire rows are exported around runtime alerts only; an edge with no captured rows is NOT_OBSERVED.

## Reproduce without the tooling

```bash
# wire
clickhouse-client -q "SELECT pod, remote_addr, local_port, encrypted, req_path, count() FROM forensic_db.http_events WHERE namespace='<ns>' AND time_ > now()-INTERVAL 1 HOUR GROUP BY ALL"
# svc
kubectl -n <ns> get svc -o custom-columns='NAME:.metadata.name,TYPE:.spec.type,PORTS:.spec.ports[*].port,NODEPORTS:.spec.ports[*].nodePort'
# ingress
kubectl -n <ns> get ingress,ingressroutes.traefik.io,httproutes.gateway.networking.k8s.io -o yaml | grep -n -E 'kind:|host|tls|entryPoints|parentRefs'
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| wire | captured inbound from ingress plaintext | the platform ingress reaches the frontend over plaintext (TLS stops at the ingress instead of continuing to the pod) |
| wire | captured inbound from driver, external, unknown plaintext | reached over plaintext bypassing the platform ingress (NodePort, direct Service or pod access) |
| wire | captured flow *→* plaintext | plaintext between tiers |
| wire | captured outbound to outside the cluster plaintext | plaintext egress to outside the cluster |
| svc | type NodePort/LoadBalancer, a plaintext port exposed | plaintext port exposed outside the cluster |
| ingress | per object, fronting the frontend, without spec.tls | the exposed frontend endpoint is plaintext (the Service port exposed on the tailnet is not TLS) |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
