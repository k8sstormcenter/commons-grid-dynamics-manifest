# ADR-0007 — A profile wildcard never covers a protected path that the profile does not also subtract

**Status:** accepted  
**Applies to:** every ContainerProfile stored for an application namespace  
**Enforced by:** sbob.authoring

## Decision

Tier profiles are generic: the platform cannot know what an application will run, so a tier profile may allow any process and any file. What it may not do is hide the paths other rules watch. Every wildcard that covers a protected path (password and sudo files, SSH keys, process environments, and the ServiceAccount token outside the backend tier) comes with a subtract entry for that path, so reading it still alerts.

## Why

Generality in a profile is bought with detection: a wildcard above a protected path silently disables the rule that watches it, and a suppressed rule produces exactly the silence a passing check produces. A subtract entry keeps the rule alive under the wildcard. No runtime evidence can confirm this ADR; the stored profile has to be read back, because collapsing happens on write.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **ContainerProfiles read back from the cluster (GET each)** — at least 1: a stored ContainerProfile.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **a profile wildcard covers a protected path that the profile does not subtract** — a stored ContainerProfile — wildcards over unsubtracted protected paths > 0.
* **the backend's ServiceAccount token allowance is not concrete, so R0006 cannot honour it** — a stored ContainerProfile — tier backend, token path not concrete.

## How to fix

* a profile wildcard covers a protected path that the profile does not subtract: compose the tier profile with the subtract fragments (sbobs/compose.sh), or list named files instead of the wildcard
* the backend's ServiceAccount token allowance is not concrete, so R0006 cannot honour it: list /var/run/secrets/kubernetes.io/serviceaccount/token literally

## Reproduce without the tooling

```bash
# profile
kubectl -n <ns> get containerprofiles.spdx.softwarecomposition.kubescape.io <name> -o json | jq '[.spec.opens[].path]'   # GET each; LIST returns an empty spec
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| profile | wildcards over unsubtracted protected paths > 0 | a profile wildcard covers a protected path that the profile does not subtract |
| profile | tier backend, token path not concrete | the backend's ServiceAccount token allowance is not concrete, so R0006 cannot honour it |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
