# ADR-0026 — A subject created through the API can be erased through the API, and is then gone; identifiers are not guessable

**Status:** proposed  
**Applies to:** every backend API that stores records about people  
**Enforced by:** evaluator.canary, openapi.schema

## Decision

A subject created through the API can be erased through the API (DELETE on the declared erasure path) and is then gone: not retrievable, not listed. Subject identifiers are not guessable.

## Why

The right to erasure (Art. 17) is tested, not asserted. The platform creates a synthetic subject with a unique canary value, deletes it, reads it back, and looks for the canary in logs and on the wire.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **synthetic subject created through the API (canary), erased, re-read** — at least 1: erasure — created < 300.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **no DELETE for a created subject** — erasure — created < 300, no erasure supported.
* **the subject is still retrievable or listed after erasure** — erasure — erasure supported, no gone.
* **sequential numeric identifiers make subjects enumerable** *(informational, not counted)* — erasure — id ~ ^[0-9]{1,6}$.

## How to fix

* no DELETE for a created subject: DELETE /<collection>/{id} removes the record and everything derived from it
* the subject is still retrievable or listed after erasure: erase, not flag; purge caches and derived copies
* sequential numeric identifiers make subjects enumerable: use random identifiers (UUIDv4) for subject records

## Reproduce without the tooling

```bash
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| erasure | created < 300, no erasure supported | no DELETE for a created subject |
| erasure | erasure supported, no gone | the subject is still retrievable or listed after erasure |
| erasure | id ~ ^[0-9]{1,6}$ | sequential numeric identifiers make subjects enumerable |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
