# ADR-0023 — The namespace declares what personal data it processes, why, on which lawful basis, for how long, and how a subject is erased

**Status:** proposed  
**Applies to:** every application namespace  
**Enforced by:** kyverno.validate, gdpr-processing ConfigMap

## Decision

Every namespace declares its record of processing (GDPR Art. 30) as the ConfigMap gdpr-processing: controller, purpose, lawful basis, categories of personal data (or none), retention in days and the erasure path. The declaration is the reference every other GDPR check is read against.

## Why

Compliance cannot be measured against an unstated intent. The declaration is cheap, lives next to the manifest, and turns "is this personal data?" into "is this declared?".

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **record of processing read from the namespace** — at least 1: declare — supplied.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **no record of processing (ConfigMap gdpr-processing) in the namespace** — declare — no present.
* **the record of processing is incomplete (purpose, lawful_basis or retention_days missing)** — declare — supplied, no complete.

## How to fix

* no record of processing (ConfigMap gdpr-processing) in the namespace: kubectl create configmap gdpr-processing --from-literal=controller=<team> --from-literal=purpose=<why> --from-literal=lawful_basis=<art.6 basis> --from-literal=categories=<email,name,...|none> --from-literal=retention_days=<n> --from-literal=erasure_path=</api/<collection>/{id}>
* the record of processing is incomplete (purpose, lawful_basis or retention_days missing): fill purpose, lawful_basis, retention_days; categories may be 'none'

## Reproduce without the tooling

```bash
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| declare | no present | no record of processing (ConfigMap gdpr-processing) in the namespace |
| declare | supplied, no complete | the record of processing is incomplete (purpose, lawful_basis or retention_days missing) |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
