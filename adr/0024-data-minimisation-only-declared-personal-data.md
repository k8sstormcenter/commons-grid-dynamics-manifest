# ADR-0024 — The API accepts, and the wire carries, no category of personal data beyond those declared in the record of processing

**Status:** proposed  
**Applies to:** every backend API and every captured request/response body  
**Enforced by:** openapi.schema, dx-ktls.openssl, pixie.http_events

## Decision

The API accepts no personal-data field of a category that is not declared, and the wire carries no category of personal data that is not declared (data minimisation, Art. 5(1)(c), 25).

## Why

A generated application collects whatever the prompt mentioned. The OpenAPI schema shows what it accepts; the decrypted bodies on the wire show what it actually carries. Both are compared with the record of processing.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **API schemas read from the backend (/openapi.json)** — at least 1: schema — schema present.
* **request/response bodies inspected on the wire (dx-ktls openssl mode → dx_kubelet_stream; Pixie http_events)** — at least 1: pii.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the API schema accepts a personal-data field of an undeclared category** — schema — field set, no declared.
* **an undeclared class of personal data was observed in request or response bodies** — pii — pii class not canary, ipv4, no declared.
* **personal data in a request URL (query string)** — pii — in url.

## How to fix

* the API schema accepts a personal-data field of an undeclared category: remove the field, or declare the category (and its purpose) in gdpr-processing
* an undeclared class of personal data was observed in request or response bodies: stop sending it, or declare the category and its purpose
* personal data in a request URL (query string): carry personal data only in request bodies over TLS

## Notes

The wire part needs decrypted bodies (dx-ktls or Pixie TLS tracing). Without them it is NOT_OBSERVED, never COMPLIANT.

## Reproduce without the tooling

```bash
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| schema | field set, no declared | the API schema accepts a personal-data field of an undeclared category |
| pii | pii class not canary, ipv4, no declared | an undeclared class of personal data was observed in request or response bodies |
| pii | in url | personal data in a request URL (query string) |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
