# ADR-0020 — Every deployed image carries signed SLSA provenance from the platform's build workflow, and it names the code that was deployed

**Status:** proposed  
**Applies to:** every container image in an application namespace  
**Enforced by:** cosign.verify-attestation, kyverno.verifyImages

## Decision

An image is deployed only with a SLSA provenance attestation attached to its digest, signed by the platform's hosted build workflow (its OIDC identity), and the provenance names the source commit the image tag claims. The platform supplies the build workflow; the application only uses it.

## Why

Provenance is the one artefact that ties what runs to who built it from what. Without it a digest is just a hash; with it the deployment can be refused when the builder, the repository or the commit is not the expected one. The registry is read for the attestation, cosign verifies the signature against the builder identity, the running digest is compared with the subject.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **image digests looked up at their registry (provenance, signature, SBOM)** — at least 1: attest.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **image not pinned by digest, so no attestation can be bound to it (SLSA L1 needs a subject)** — attest — not pinned by digest.
* **no SLSA provenance attestation is attached to the image digest in the registry (build L1)** — attest — pinned by digest, no provenance.
* **provenance present but not verifiable against the platform builder identity and OIDC issuer (build L2)** — attest — provenance, no provenance verified.
* **the provenance names a different source commit than the image tag claims** — attest — provenance verified, expected sha set, no source matches.

## How to fix

* image not pinned by digest, so no attestation can be bound to it (SLSA L1 needs a subject): image: <repo>:<code-sha>@sha256:<digest>
* no SLSA provenance attestation is attached to the image digest in the registry (build L1): build with the platform build template (actions/attest-build-provenance or slsa-github-generator pushes the attestation next to the image)
* provenance present but not verifiable against the platform builder identity and OIDC issuer (build L2): build on the platform's hosted workflow; the attestation must be signed by its OIDC identity
* the provenance names a different source commit than the image tag claims: tag the image with the commit the workflow built; never retag

## Reproduce without the tooling

```bash
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| attest | not pinned by digest | image not pinned by digest, so no attestation can be bound to it (SLSA L1 needs a subject) |
| attest | pinned by digest, no provenance | no SLSA provenance attestation is attached to the image digest in the registry (build L1) |
| attest | provenance, no provenance verified | provenance present but not verifiable against the platform builder identity and OIDC issuer (build L2) |
| attest | provenance verified, expected sha set, no source matches | the provenance names a different source commit than the image tag claims |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
