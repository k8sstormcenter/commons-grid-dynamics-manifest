# ADR-0021 — Every image publishes an SBOM next to its digest and carries no critical or exploitable known vulnerability

**Status:** proposed  
**Applies to:** every container image in an application namespace  
**Enforced by:** cosign.attach-sbom, kubescape.kubevuln

## Decision

Every image publishes an SBOM next to its digest, and carries no known exploitable or critical vulnerability at deployment time.

## Why

An SBOM is what makes a vulnerability disclosure answerable in minutes instead of days. The SBOM referrer is read from the registry; vulnerabilities come from the image scan.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **image digests looked up for an SBOM** — at least 1: attest.
* **images scanned in-cluster by kubevuln (severities, relevancy)** — at least 1: vulns — scanned.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **no SBOM (SPDX/CycloneDX) attached to the image digest** — attest — pinned by digest, no sbom.
* **the image carries known CRITICAL vulnerabilities** — vulns — scanned, critical > 0.
* **HIGH vulnerabilities in packages the container actually loads at runtime** — vulns — scanned, high relevant > 0.
* **HIGH vulnerabilities in the image (not loaded at runtime so far)** *(informational, not counted)* — vulns — scanned, high > 0, high relevant 0.
* **image not scanned in-cluster (no VulnerabilityManifestSummary)** *(informational, not counted)* — vulns — no scanned.

## How to fix

* no SBOM (SPDX/CycloneDX) attached to the image digest: the platform build template attaches the SBOM (syft + cosign attest --type cyclonedx)
* the image carries known CRITICAL vulnerabilities: rebuild on a current base image and pinned dependencies; re-scan before pushing
* HIGH vulnerabilities in packages the container actually loads at runtime: upgrade the affected packages; the relevancy list names them (vulnerabilitymanifests, relevant)
* HIGH vulnerabilities in the image (not loaded at runtime so far): upgrade on the next rebuild
* image not scanned in-cluster (no VulnerabilityManifestSummary): platform: kubevuln must reach the registry; application: public or pull-secret-readable image

## Reproduce without the tooling

```bash
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| attest | pinned by digest, no sbom | no SBOM (SPDX/CycloneDX) attached to the image digest |
| vulns | scanned, critical > 0 | the image carries known CRITICAL vulnerabilities |
| vulns | scanned, high relevant > 0 | HIGH vulnerabilities in packages the container actually loads at runtime |
| vulns | scanned, high > 0, high relevant 0 | HIGH vulnerabilities in the image (not loaded at runtime so far) |
| vulns | no scanned | image not scanned in-cluster (no VulnerabilityManifestSummary) |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
