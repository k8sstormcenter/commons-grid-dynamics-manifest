# ADR-0014 — Images are pinned by digest, signed; no latest

**Status:** proposed  
**Applies to:** every workload  
**Enforced by:** kyverno.validate, cosign

## Decision

Every container image is referenced by digest (repo@sha256:…). latest, no tag and mutable tags are rejected at admission. imagePullPolicy is IfNotPresent. Images are signed by the build that produced them and verified at admission. A profile is bound to a digest: a new digest means a new learn or an explicit profile bump, never a silent carry-over.

## Why

A floating tag moves under a learned profile; the first symptom is a flood of file-access alerts on a container nobody changed. The digest that actually ran is recorded on every runtime event, so the drift is visible after the fact — the pin is what prevents it.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **container images checked for @sha256 pins** — at least 1: a container in the pod spec.
* **kubescape scan supplied (image signature)** — at least 1: the kubescape scan — supplied.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **image is not pinned by digest** — a container in the pod spec — not pinned by digest.
* **pull policy Always on a pinned image** — a container in the pod spec — pinned by digest, imagePullPolicy Always.
* **image not signed** — the static scan flagged an unsigned image.

## How to fix

* image is not pinned by digest: image: <repo>:<tag>@sha256:<digest>; imagePullPolicy: IfNotPresent; sign with cosign
* pull policy Always on a pinned image: imagePullPolicy: IfNotPresent
* image not signed: sign with cosign in the publishing workflow; verify at admission

## Reproduce without the tooling

```bash
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
# scan
kubescape scan framework AllControls --include-namespaces <ns> --format json --output /tmp/AllControls-<ns>.json
# scan_present
ls -l /tmp/AllControls-<ns>.json   # the scan file the evaluator was given
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| spec | not pinned by digest | image is not pinned by digest |
| spec | pinned by digest, imagePullPolicy Always | pull policy Always on a pinned image |
| scan | C-0237 | image not signed |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
