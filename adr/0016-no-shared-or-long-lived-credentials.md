# ADR-0016 — Credentials are per workload, short-lived, and never in environment variables or manifests

**Status:** proposed  
**Applies to:** every workload; every Secret in an application namespace  
**Enforced by:** kyverno.validate, secret-rotation, workload-identity

## Decision

A credential belongs to exactly one workload and to the one hop that workload initiates; it is never shared between workloads or tiers. Credentials are never written into manifests, ConfigMaps or environment variables: a Secret is mounted as a read-only file, or the workload uses platform-issued short-lived identity (the IdP's tokens, cert-manager certificates). Every long-lived credential is rotated; one older than 90 days is a finding.

## Why

A credential in an environment variable is readable by every process in the container, its children, core dumps and /proc, and it ends up in logs. A shared credential cannot be attributed when it leaks and cannot be revoked without collateral. A credential that never rotates is a credential that is still valid after the leak nobody noticed. The pod spec shows how credentials are delivered; the Secret objects show who shares what and for how long; the static scan finds values that were written down.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **containers' env, envFrom and volume mounts read from the pod spec** — at least 1: a container in the pod spec.
* **kubescape scan supplied (credentials in configuration)** — at least 1: the kubescape scan — supplied.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **a credential is written literally into the pod spec** — a container in the pod spec — a credential-named env var with a literal value.
* **a Secret is injected as an environment variable (visible to every process, child, core dump and /proc)** — a container in the pod spec — a Secret injected as an environment variable.
* **one Secret is used by several workloads (shared credential)** — a Secret of the namespace — referenced by more than one workload.
* **a credential crosses tiers** — a Secret of the namespace — referenced from more than one tier.
* **a long-lived credential (older than 90 days, never rotated)** — a Secret of the namespace — referenced by a workload, age in days > 90.
* **application credentials found in configuration files** — the static scan flagged credentials in configuration files.

## How to fix

* a credential is written literally into the pod spec: never put secrets in manifests or ConfigMaps; reference a Secret mounted as a file, or use workload identity
* a Secret is injected as an environment variable (visible to every process, child, core dump and /proc): mount the Secret as a read-only file (volume or CSI secrets store), or use short-lived workload identity
* one Secret is used by several workloads (shared credential): one credential per workload, so a leak is attributable and revocable without collateral
* a credential crosses tiers: each tier holds only the credentials for the hop it initiates
* a long-lived credential (older than 90 days, never rotated): rotate on a schedule; prefer platform-issued short-lived tokens (IdP, cert-manager)
* application credentials found in configuration files: move the value to a Secret mounted as a file, or to workload identity

## Notes

A workload that genuinely needs an exception gets it from the platform, never from its own manifest: the platform records "<namespace>/<workload>: ADR-0016=<reason>" in the exceptions ConfigMap, and the finding then stays in the report as a note (not counted, owner platform).

## Reproduce without the tooling

```bash
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
# secret
kubectl -n <ns> get secrets -o custom-columns='NAME:.metadata.name,TYPE:.type,AGE:.metadata.creationTimestamp'; kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, env, envFrom, volumeMounts}'
# scan
kubescape scan framework AllControls --include-namespaces <ns> --format json --output /tmp/AllControls-<ns>.json
# scan_present
ls -l /tmp/AllControls-<ns>.json   # the scan file the evaluator was given
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| spec | a credential-named env var with a literal value | a credential is written literally into the pod spec |
| spec | a Secret injected as an environment variable | a Secret is injected as an environment variable (visible to every process, child, core dump and /proc) |
| secret | referenced by more than one workload | one Secret is used by several workloads (shared credential) |
| secret | referenced from more than one tier | a credential crosses tiers |
| secret | referenced by a workload, age in days > 90 | a long-lived credential (older than 90 days, never rotated) |
| scan | C-0012 | application credentials found in configuration files |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
