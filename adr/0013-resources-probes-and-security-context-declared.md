# ADR-0013 — Every workload declares its envelope: resources, probes, security context

**Status:** proposed  
**Applies to:** every workload  
**Enforced by:** kyverno.validate

## Decision

Every container declares resources.requests and resources.limits for cpu and memory, a liveness and a readiness probe (httpGet or tcpSocket, never exec), and a securityContext with runAsNonRoot: true, non-zero runAsUser/runAsGroup, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities.drop [ALL] and seccompProfile.type RuntimeDefault. Writable paths are named emptyDir mounts.

## Why

The envelope is what the scheduler, the profile and the incident responder rely on. Every field is read from the pod spec; the same manifest default appears once per container, grouped by the fix, not once per control. An exec probe enters the container through the runtime and shows up as capability use and process launches that are the probe's, not the image's.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **containers' resources, probes and securityContext read from the pod spec** — at least 1: a container in the pod spec.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **no cpu/memory requests** — a container in the pod spec — no resources.requests.
* **no cpu/memory limits** — a container in the pod spec — no resources.limits.
* **no liveness probe** — a container in the pod spec — no livenessProbe.
* **no readiness probe** — a container in the pod spec — no readinessProbe.
* **no seccomp profile** — a container in the pod spec — seccompProfile.type not RuntimeDefault, Localhost.
* **capabilities not dropped** — a container in the pod spec — capabilities not dropped (ALL).
* **exec probe enters the container through runc (CAP_SYS_ADMIN, /proc reads)** — a container in the pod spec — an exec probe.

## How to fix

* no cpu/memory requests: set resources.requests.cpu and .memory (choose values)
* no cpu/memory limits: set resources.limits.cpu and .memory (choose values)
* no liveness probe: add livenessProbe (httpGet /healthz or tcpSocket)
* no readiness probe: add readinessProbe (httpGet /readyz or tcpSocket)
* no seccomp profile: set securityContext.seccompProfile.type = RuntimeDefault
* capabilities not dropped: set securityContext.capabilities.drop = [ALL]
* exec probe enters the container through runc (CAP_SYS_ADMIN, /proc reads): use a tcpSocket or httpGet probe

## Reproduce without the tooling

```bash
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| spec | no resources.requests | no cpu/memory requests |
| spec | no resources.limits | no cpu/memory limits |
| spec | no livenessProbe | no liveness probe |
| spec | no readinessProbe | no readiness probe |
| spec | seccompProfile.type not RuntimeDefault, Localhost | no seccomp profile |
| spec | capabilities not dropped (ALL) | capabilities not dropped |
| spec | an exec probe | exec probe enters the container through runc (CAP_SYS_ADMIN, /proc reads) |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
