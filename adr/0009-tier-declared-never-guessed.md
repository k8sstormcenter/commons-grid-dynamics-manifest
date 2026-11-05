# ADR-0009 — A tier is declared, never guessed

**Status:** proposed  
**Applies to:** every workload; the admission policy  
**Enforced by:** kyverno.mutate

## Decision

The tier of a workload is declared by its author in the manifest. Admission validates a declared tier and assigns one only for images it recognises; a container port is never evidence of a tier. A workload with no declaration and an unrecognised image is tier=unclassified regardless of its port.

## Why

A port fallback turned a monolith on port 80 into a trusted frontend with the lenient frontend profile. A guessed tier shows up later as a profile mismatch, which is the wrong place to learn it. The applied manifest (last-applied-configuration) is what tells declared from assigned.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **workloads whose applied manifest could be read (declared vs assigned tier)** — at least 1: a running pod — applied manifest readable.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **tier was guessed from the container port** — a running pod — tier assigned by port.
* **the admission policy still carries a containerPort fallback** *(owner: platform)* — the admission policy — a port-based rule present.

## How to fix

* tier was guessed from the container port: declare app.kubernetes.io/tier in the pod template (frontend|backend|database)
* the admission policy still carries a containerPort fallback: platform: remove the tier-by-port rules from kyverno/02-label-tiers.yaml

## Reproduce without the tooling

```bash
# pod
kubectl -n <ns> get pods -o custom-columns='POD:.metadata.name,TIER:.metadata.labels.app\.kubernetes\.io/tier,PROFILE:.metadata.labels.kubescape\.io/user-defined-profile,START:.status.startTime'
# policy
kubectl get clusterpolicy assign-workload-tier -o yaml | grep -n 'name: tier-by-'
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| pod | tier assigned by port | tier was guessed from the container port |
| policy | a port-based rule present | the admission policy still carries a containerPort fallback |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
