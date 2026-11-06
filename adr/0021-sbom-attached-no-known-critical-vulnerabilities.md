# ADR-0021 — Every image publishes an SBOM next to its digest and carries no critical or exploitable known vulnerability

**Status:** proposed  
**Applies to:** every container image in an application namespace  
**Enforced by:** cosign.attach-sbom, kubescape.vulnerability-scan

## Decision

Every image publishes an SBOM next to its digest, and carries no known exploitable or critical vulnerability at deployment time.

## Why

An SBOM is what makes a vulnerability disclosure answerable in minutes instead of days. The SBOM referrer is read from the registry; vulnerabilities come from the image scan.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **image digests looked up for an SBOM** — at least 1: attest.
* **kubescape scan supplied (vulnerability controls)** — at least 1: the kubescape scan — supplied.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **no SBOM (SPDX/CycloneDX) attached to the image digest** — attest — pinned by digest, no sbom.
* **image carries known exploitable or excessive vulnerabilities** — the static scan flagged C-0084 or C-0085 or C-0086.

## How to fix

* no SBOM (SPDX/CycloneDX) attached to the image digest: the platform build template attaches the SBOM (syft + cosign attest --type cyclonedx)
* image carries known exploitable or excessive vulnerabilities: rebuild on the current base image; pin dependencies; re-scan before pushing

## Reproduce without the tooling

```bash
# scan
kubescape scan framework AllControls --include-namespaces <ns> --format json --output /tmp/AllControls-<ns>.json
# scan_present
ls -l /tmp/AllControls-<ns>.json   # the scan file the evaluator was given
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| attest | pinned by digest, no sbom | no SBOM (SPDX/CycloneDX) attached to the image digest |
| scan | C-0084 / C-0085 / C-0086 | image carries known exploitable or excessive vulnerabilities |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
