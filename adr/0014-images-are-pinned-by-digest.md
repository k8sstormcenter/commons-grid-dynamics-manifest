# ADR-0014 — Images are pinned by digest

**Status:** proposed
**Applies to:** every workload

## Context

[ADR-0004](0004-images-are-immutable-at-runtime.md) says nothing changes inside a running
image. It says nothing about which image runs. The first fixture used
`ghcr.io/k8sstormcenter/commons-grid-dynamics:latest` with `imagePullPolicy: Always`: every pod
restart may run different code, and the SBoB learned on one build governs the next. The repo's
own announcement offered a commit-sha tag next to `latest` — the right one was one line away.

A profile is a statement about one image. A floating tag makes it a statement about nothing in
particular.

## Decision

* Every container image is referenced by digest: `repo@sha256:…` (a tag may precede the digest
  for readability, the digest is what binds).
* `:latest`, no tag, and mutable tags (`main`, `dev`, `stable`) are rejected at admission.
* `imagePullPolicy` is `IfNotPresent`; `Always` on a digest is harmless but signals a tag
  workflow and is flagged.
* Images are signed (cosign) by the build that produced them; the platform verifies the
  signature at admission. The SBoB is bound to the digest, so a new digest means a new learn
  or an explicit profile bump — never a silent carry-over.

## Verified by

**Static** — the pod template's `image:` strings: digest present or not; tag in the mutable set
or not; `imagePullPolicy`. kubescape C-0236 (image is not pinned) and C-0237 (image not signed)
when the scan supplies them.

**Runtime (corroborating)** — `RuntimeK8sDetails.imageDigest` on the rows versus the digest
the profile was learned against. A profile whose rows carry two digests over its lifetime was
learned on a moving target.

## Evidence emitted

```
ADR-0014 VIOLATED   IMAGE_NOT_PINNED
  observed  commons-grid-dynamics/web: ghcr.io/k8sstormcenter/commons-grid-dynamics:latest
            imagePullPolicy=Always; running digest sha256:229396b5…
  fix       image: ghcr.io/k8sstormcenter/commons-grid-dynamics:<sha>@sha256:229396b5…
            imagePullPolicy: IfNotPresent; sign with cosign in the publishing workflow
```

## Consequences

* Every deploy is a manifest change, which is where it belongs — a redeploy without a change
  is a no-op, and the profile stays valid.
* Base images used by the split (nginx, python, postgres) are pinned the same way; the kyverno
  image regexes match on the repository name and are unaffected by the digest suffix.
