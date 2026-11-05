# ADR-0015 — Ingress is the platform's; a workload opens nothing itself

**Status:** proposed  
**Applies to:** every Service, Ingress and NetworkPolicy  
**Enforced by:** kyverno.validate, netpol

## Decision

No NodePort, no LoadBalancer, no hostPort and no hostNetwork created by an application. Browser traffic enters through the platform Ingress class, which terminates TLS and fronts only tier=frontend Services. Every namespace carries a default-deny NetworkPolicy for ingress and egress plus one allow per prescribed edge: ingress-controller→frontend, frontend→backend, backend→database, backend→identity provider, monitoring→metrics ports, everyone→DNS.

## Why

The network policy and the tier profile describe the same edges from two sides: the policy blocks, the profile detects. Where they disagree, the narrower one is right and the other is a finding. A workload that opens its own ingress bypasses the TLS termination and the policy.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **Services, pod templates and NetworkPolicies of the namespace examined** — at least 1: the namespace's NetworkPolicy set — namespace-wide.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **workload opens its own ingress** — a Service — type NodePort/LoadBalancer.
* **hostNetwork** — a container in the pod spec — hostNetwork set.
* **hostPort** — a container in the pod spec — hostPort set.
* **no platform ingress/gateway object fronts the frontend** — an ingress/gateway object — namespace-wide, none fronting the frontend.
* **no default-deny NetworkPolicy in the namespace** — the namespace's NetworkPolicy set — namespace-wide, no default-deny ingress+egress.

## How to fix

* workload opens its own ingress: type: ClusterIP; Ingress via the platform ingress class
* hostNetwork: remove hostNetwork
* hostPort: remove hostPort; use a Service
* no platform ingress/gateway object fronts the frontend: expose the frontend through the platform ingress class (Ingress / IngressRoute / HTTPRoute) with TLS; never a NodePort
* no default-deny NetworkPolicy in the namespace: default-deny ingress+egress; allow ingress-controller->frontend, frontend->backend, backend->database, backend->IdP, monitoring->metrics, all->DNS

## Reproduce without the tooling

```bash
# svc
kubectl -n <ns> get svc -o custom-columns='NAME:.metadata.name,TYPE:.spec.type,PORTS:.spec.ports[*].port,NODEPORTS:.spec.ports[*].nodePort'
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
# ingress
kubectl -n <ns> get ingress,ingressroutes.traefik.io,httproutes.gateway.networking.k8s.io -o yaml | grep -n -E 'kind:|host|tls|entryPoints|parentRefs'
# netpol
kubectl -n <ns> get netpol -o yaml
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| svc | type NodePort/LoadBalancer | workload opens its own ingress |
| spec | hostNetwork set | hostNetwork |
| spec | hostPort set | hostPort |
| ingress | namespace-wide, none fronting the frontend | no platform ingress/gateway object fronts the frontend |
| netpol | namespace-wide, no default-deny ingress+egress | no default-deny NetworkPolicy in the namespace |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
