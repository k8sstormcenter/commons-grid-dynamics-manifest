# ADR-0015 — Ingress is the platform's; a workload opens nothing itself

**Status:** proposed
**Applies to:** every Service, Ingress, NetworkPolicy

## Context

The first fixture shipped `type: NodePort` on `30080` — the README's `http://<node-ip>:30080`.
On the cluster the port was already taken by another tenant and the Service was rejected; on an
empty cluster it would have put an unauthenticated, plaintext application on every node's
public interface. Nothing in the namespace restricted who could reach the pod from inside the
cluster either: no NetworkPolicy, so the tier layering of [ADR-0001](0001-strict-tier-layering.md)
was enforced by the runtime sensor alone, never by the network.

## Decision

* No `NodePort`, no `hostPort`, no `hostNetwork`, no `LoadBalancer` created by an application.
  Browser traffic enters through the platform `Ingress` class, which terminates TLS
  ([ADR-0011](0011-no-plaintext-on-the-wire.md)) and fronts only `tier=frontend` Services.
* Every namespace carries a default-deny `NetworkPolicy` for ingress and egress, plus one allow
  per edge the tier layering permits: ingress-controller → frontend, frontend → backend,
  backend → database, backend → IdP, monitoring → `metrics` ports
  ([ADR-0012](0012-metrics-are-served-on-a-dedicated-port.md)), everyone → DNS.
* The network policy and the SBoB describe the same edges. Where they disagree, the one that
  is narrower is right and the other is a finding.

## Verified by

**Static** — Services of type `NodePort`/`LoadBalancer`, `hostPort`/`hostNetwork` in pod specs
(C-0044 C-0041); a namespace with workloads and no NetworkPolicy (C-0030 C-0260); Ingress
objects without `tls:`.

**Runtime (corroborating)** — an `R0011` whose peer is permitted by the SBoB but denied by the
NetworkPolicy never completes; an `R0011` that completes to a peer the NetworkPolicy should
have blocked means the policy is not what it claims. Both are visible in `kubescape_logs` plus
the CNI's drop counters.

## Evidence emitted

```
ADR-0015 VIOLATED   WORKLOAD_OPENS_ITS_OWN_INGRESS
  observed  Service commons-grid-dynamics type=NodePort nodePort=30080 (rejected: port in use)
  observed  namespace commons-grid has 0 NetworkPolicy objects
  fix       Service type: ClusterIP; Ingress with tls: via the platform ingress class;
            default-deny NetworkPolicy + allows per tier edge (frontend->backend, backend->database)
```

## Consequences

* The application no longer chooses its own URL or port; the platform does, and the README
  points at a hostname.
* With default-deny in place, every undeclared egress fails fast instead of being merely
  observed — which makes the runtime findings quieter and the remaining ones more interesting.
