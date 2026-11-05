# ADR-0019 — A workload is reachable only through the platform's tailnet exposure of its frontend Service; it opens nothing itself

**Status:** proposed  
**Applies to:** every Service, pod template and NetworkPolicy of an application namespace  
**Enforced by:** tailscale-operator, kyverno.validate, netpol

## Decision

An application opens nothing itself: no NodePort, no LoadBalancer, no hostPort, no hostNetwork, and no Ingress or Gateway objects, which this platform does not serve. Its frontend Service is exposed through the platform's tailscale operator — annotations tailscale.com/expose, a tailscale.com/hostname and tailscale.com/tags that place it under the tailnet ACL — and the exposed port is the frontend's own TLS port. Every namespace carries a default-deny NetworkPolicy for ingress and egress plus one allow per prescribed edge, including the tailnet proxy (namespace tailscale-system) to the frontend.

## Why

On this platform the tailnet is the perimeter: who may reach the application is decided by the tailnet ACL through the Service's tags, the endpoint gets a MagicDNS name, and nothing is reachable from the node network. An Ingress object cannot be admitted here, a NodePort bypasses the ACL, and a plaintext exposed port would be plaintext up to the proxy. The exposure is read from the Service annotations and status; the policy from the NetworkPolicy set.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **Services, exposure annotations and NetworkPolicies of the namespace examined** — at least 1: an ingress/gateway object — namespace-wide.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **workload opens its own ingress (NodePort / LoadBalancer)** — a Service — type NodePort/LoadBalancer.
* **hostNetwork** — a container in the pod spec — hostNetwork set.
* **hostPort** — a container in the pod spec — hostPort set.
* **an Ingress/Gateway object was declared; this platform serves none** — an ingress/gateway object — per object, kind Ingress or IngressRoute or HTTPRoute.
* **the frontend is not exposed through the platform's tailnet** — an ingress/gateway object — namespace-wide, none exposing the frontend.
* **the tailnet-exposed Service carries no tailscale tags (no ACL identity)** — an ingress/gateway object — per object, kind TailscaleService, tailscale tags empty.
* **no default-deny NetworkPolicy in the namespace** — the namespace's NetworkPolicy set — namespace-wide, no default-deny ingress+egress.

## How to fix

* workload opens its own ingress (NodePort / LoadBalancer): type: ClusterIP; expose the frontend Service through the tailscale operator annotations
* hostNetwork: remove hostNetwork
* hostPort: remove hostPort; use a Service
* an Ingress/Gateway object was declared; this platform serves none: remove it; expose the frontend Service with tailscale.com/expose, tailscale.com/hostname, tailscale.com/tags
* the frontend is not exposed through the platform's tailnet: annotate the frontend Service: tailscale.com/expose: "true", tailscale.com/hostname: <app>, tailscale.com/tags: tag:<platform tag>
* the tailnet-exposed Service carries no tailscale tags (no ACL identity): add tailscale.com/tags: tag:<platform tag> so the tailnet ACL governs who may reach it
* no default-deny NetworkPolicy in the namespace: default-deny ingress+egress; allow tailscale-system->frontend, frontend->backend, backend->database, backend->IdP, monitoring->metrics, all->DNS

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
| svc | type NodePort/LoadBalancer | workload opens its own ingress (NodePort / LoadBalancer) |
| spec | hostNetwork set | hostNetwork |
| spec | hostPort set | hostPort |
| ingress | per object, kind Ingress or IngressRoute or HTTPRoute | an Ingress/Gateway object was declared; this platform serves none |
| ingress | namespace-wide, none exposing the frontend | the frontend is not exposed through the platform's tailnet |
| ingress | per object, kind TailscaleService, tailscale tags empty | the tailnet-exposed Service carries no tailscale tags (no ACL identity) |
| netpol | namespace-wide, no default-deny ingress+egress | no default-deny NetworkPolicy in the namespace |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
