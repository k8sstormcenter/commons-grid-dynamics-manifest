# ADR-0009 — A tier is declared, never guessed

**Status:** proposed
**Applies to:** every workload; `kyverno/02-label-tiers.yaml`

## Context

[ADR-0005](0005-every-workload-declares-its-tier.md) made admission assign a tier so that no pod
runs without a profile. `assign-workload-tier` does that in two steps: match the image name
against known components (`postgres|redis|…` → database, `nginx|caddy|…` → frontend, …), and if
nothing matches, fall back to the first containerPort — 80/443/8080 → frontend, 5432/6379/… →
database, anything else → unclassified.

The fallback was written for the demo fixture. On the first custom image it produced the wrong
answer with full confidence: `ghcr.io/k8sstormcenter/commons-grid-dynamics:latest` on port 80
became `tier=frontend`, got the permissive frontend baseline (`egress: null`, `ingress: null`)
and passed every tier ADR while serving an entire application ([ADR-0008](0008-presentation-tier-serves-presentation-only.md)).

A guessed tier is worse than an undeclared one. An undeclared pod is quarantined and visible;
a mis-guessed pod is governed by the wrong profile and invisible.

## Decision

* The tier of a workload is a declaration by its author: `app.kubernetes.io/tier` set in the
  manifest. Admission **validates** a declared tier; it only **assigns** one for images it can
  recognise.
* A workload whose image matches no known component and carries no tier label is
  `tier=unclassified` — quarantined, narrow profile, visible in the KPI — regardless of its port.
  The port fallback is removed from `assign-workload-tier`.
* The declared tier must be consistent with the image where the image is known: a workload
  that declares `tier=frontend` on a `postgres` image is rejected, not relabelled.

## Verified by

**Admission (static)** — the pod's `app.kubernetes.io/tier` label versus the manifest: absent
in the manifest and present on the pod means the tier was assigned. If the image matched a
known-component regex that is fine; if it did not, the tier was guessed and this ADR is
violated. `adr_arch.classification` reproduces the kyverno regexes from the rig so the
evaluator and the policy cannot drift.

**Runtime (corroborating)** — a guessed tier shows up as a profile mismatch: `R0002`/`R0003`
against a baseline that was learned for a different component.

## Evidence emitted

```
ADR-0009 VIOLATED   TIER_GUESSED_FROM_PORT
  observed  commons-grid-dynamics: image matched no known component; tier=frontend assigned
            from containerPort 80 (manifest declares no app.kubernetes.io/tier)
  fix       declare app.kubernetes.io/tier on every workload (frontend | backend | database);
            platform: drop the containerPort fallback in kyverno/02-label-tiers.yaml so a
            custom image without a declaration lands in tier-unclassified
```

## Consequences

* Custom images without a declaration are quarantined. That is the intended friction: the
  author writes one label and gets the right baseline, or writes nothing and gets a pod that
  can do almost nothing.
* The existing fixtures (`app.yaml`) rely on image matching only, so they are unaffected.
