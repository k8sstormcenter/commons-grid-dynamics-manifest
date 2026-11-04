# ADR-0011 — No plaintext on the wire

**Status:** proposed  
**Applies to:** every tier; every Service and Ingress  
**Enforced by:** cert-manager, app-config

## Decision

Anything that leaves a pod is TLS: browser→frontend (terminated at the platform ingress), frontend→backend, backend→database, backend→identity provider, backend→external. Workloads consume platform-issued certificates; they do not generate or commit their own. The data tier requires TLS so that a plaintext client fails instead of silently downgrading.

## Why

A bearer token on a plaintext wire is a token for everyone on the path. The wire tracer decodes plaintext protocols and marks each captured request encrypted or not, per source, destination, port and path; a kernel-TLS tap corroborates the encrypted side. Health probes and the evaluator's own requests are discounted.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **application flows captured on the wire (Pixie)** — at least 1: a captured flow — protocol http or pgsql or conn, remote not evaluator.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **plaintext on the wire** — a captured flow — protocol http or pgsql, plaintext, remote not evaluator, node, not a health path.
* **plaintext on the wire from a node address that is not a declared probe** — a captured flow — protocol http, plaintext, remote node, not a kubelet probe, not a health path.
* **plaintext port exposed outside the cluster** — a Service — type NodePort/LoadBalancer, a plaintext port exposed.
* **Ingress without TLS** — an Ingress — without spec.tls.

## How to fix

* plaintext on the wire: serve TLS from a platform-issued certificate; clients verify; postgres ssl=on hostssl-only
* plaintext on the wire from a node address that is not a declared probe: serve TLS; declare the probe if this is one
* plaintext port exposed outside the cluster: ClusterIP + Ingress with tls
* Ingress without TLS: add spec.tls with a cert-manager issued secret

## Notes

Wire rows are exported around runtime alerts only; an edge with no captured rows is NOT_OBSERVED, not COMPLIANT. Drive the application before judging.

## Reproduce without the tooling

```bash
# wire
clickhouse-client -q "SELECT pod, remote_addr, local_port, encrypted, req_path, count() FROM forensic_db.http_events WHERE namespace='<ns>' AND time_ > now()-INTERVAL 1 HOUR GROUP BY ALL"
# svc
kubectl -n <ns> get svc -o custom-columns='NAME:.metadata.name,TYPE:.spec.type,PORTS:.spec.ports[*].port,NODEPORTS:.spec.ports[*].nodePort'
# ingress
kubectl -n <ns> get ingress -o jsonpath='{range .items[*]}{.metadata.name} tls={.spec.tls}{"\n"}{end}'
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| wire | captured flow *→* plaintext | plaintext on the wire |
| wire | captured flow *→* plaintext | plaintext on the wire from a node address that is not a declared probe |
| svc | type NodePort/LoadBalancer, a plaintext port exposed | plaintext port exposed outside the cluster |
| ingress | without spec.tls | Ingress without TLS |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
