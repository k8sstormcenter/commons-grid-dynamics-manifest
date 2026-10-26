# ADR-0013 — Every workload declares its envelope: resources, probes, security context

**Status:** proposed
**Applies to:** every workload

## Context

The first fixture's manifest was eleven lines of pod spec: image, one port, `imagePullPolicy:
Always`. No resources, so the scheduler cannot place it and a runaway loop takes the node with
it. No probes, so a hung process stays in the Service. No security context, so it runs as root
with a writable filesystem, escalation permitted, and a service-account token mounted it never
uses. `kubescape scan framework AllControls` on that namespace failed six controls on one pod.

[ADR-0006](0006-workloads-run-as-non-root.md) covers the root part at runtime. The rest is a
manifest-shape decision that has no runtime signature until it hurts.

## Decision

Every container in a `tier=*` workload declares:

* `resources.requests` and `resources.limits` for cpu and memory
* `livenessProbe` and `readinessProbe`
* `securityContext`: `runAsNonRoot: true`, `runAsUser`/`runAsGroup` non-zero,
  `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
  `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`
* `automountServiceAccountToken: false` unless the workload talks to the API server, in which
  case it has its own ServiceAccount and Role

Writable paths are `emptyDir` mounts, named, so the SBoB can list them.

## Verified by

**Static (kubescape controls)**, grouped by fix as `review.compliance_findings` does:

| fix | controls |
|---|---|
| `resources.{requests,limits}` | C-0004 C-0009 C-0050 C-0268 C-0269 C-0270 C-0271 |
| `livenessProbe` / `readinessProbe` | C-0018 C-0056 |
| `securityContext.*` | C-0013 C-0016 C-0017 C-0046 C-0055 C-0210 C-0211 |
| `automountServiceAccountToken` | C-0034 C-0190 C-0261 |

**Runtime (corroborating)** — `R0004` (unexpected capability) and `R0006`/`R0010` (token
read) are the runtime shadows of the security-context and token findings; a writable root
filesystem shows as `R0002` writes outside the declared `emptyDir`s.

## Evidence emitted

```
ADR-0013 VIOLATED   ENVELOPE_UNDECLARED
  observed  C-0004 C-0009 C-0050 C-0268 C-0269 failed on commons-grid-dynamics: no resources
  observed  C-0018 C-0056 failed: no liveness/readiness probe
  observed  C-0016 C-0211 C-0017 C-0013 failed: escalation allowed, writable root, runs as root
  fix       set resources (decide: cpu/memory), add probes on /healthz /readyz, set the
            securityContext block above, automountServiceAccountToken: false
```

## Consequences

* Read-only root with nginx needs `emptyDir` on `/var/cache/nginx`, `/var/run`, `/tmp`; with
  python, `/tmp` only. These mounts are what the SBoB then declares — the envelope and the
  profile describe the same thing from two sides.
* The resource numbers are a decision the author makes (`YOUR_VALUE` in the scan); the
  evaluator reports them as *needs decision*, not as patchable.
