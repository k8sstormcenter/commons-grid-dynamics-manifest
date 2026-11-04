# ADR-0007 — A profile may not wildcard above a path another rule protects

**Status:** accepted  
**Applies to:** every ContainerProfile stored for an application namespace  
**Enforced by:** sbob.authoring

## Decision

No profile contains a wildcard entry at or above a path another rule protects: nothing directly under /etc, /run, /var/run or at the root. Only named files and named per-engine directories. The ServiceAccount token path appears only in the backend profile, written concretely.

## Why

Generality in a profile is bought with detection: a wildcard above a protected path silently disables the rule that watches it, and a suppressed rule produces exactly the silence a passing check produces. No runtime evidence can confirm this ADR; the stored profile has to be read back — the files on disk are not enough, because collapsing happens on write.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **ContainerProfiles read back from the cluster (GET each)** — at least 1: a stored ContainerProfile.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **profile wildcards above a protected path** — a stored ContainerProfile — wildcard entries > 0.
* **the backend's ServiceAccount token allowance is not concrete, so R0006 cannot honour it** — a stored ContainerProfile — tier backend, token path not concrete.

## How to fix

* profile wildcards above a protected path: regenerate the profile (bobctl) listing the named files the application actually reads
* the backend's ServiceAccount token allowance is not concrete, so R0006 cannot honour it: list /var/run/secrets/kubernetes.io/serviceaccount/token literally

## Reproduce without the tooling

```bash
# profile
kubectl -n <ns> get containerprofiles.spdx.softwarecomposition.kubescape.io <name> -o json | jq '[.spec.opens[].path]'   # GET each; LIST returns an empty spec
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| profile | wildcard entries > 0 | profile wildcards above a protected path |
| profile | tier backend, token path not concrete | the backend's ServiceAccount token allowance is not concrete, so R0006 cannot honour it |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
