# ADR-0025 — Personal data never reaches stdout/stderr, metrics labels or request URLs

**Status:** proposed  
**Applies to:** every container  
**Enforced by:** logs, metrics-port, pixie.http_events

## Decision

Personal data never reaches stdout/stderr, metrics labels or request URLs. A synthetic subject planted by the platform must not appear in any log line.

## Why

Logs are copied, retained and read by people with no need to know; a URL ends up in every proxy and browser history. The container logs of the evaluation window are scanned for personal-data classes and for the planted canary.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **container logs of the window inspected** — at least 1: logs.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the synthetic subject's data was written to the container log** — logs — no clean, pii class canary.
* **personal data written to the container log** — logs — no clean, pii class not canary, ipv4.
* **client IP addresses written to the log without ip in the declared categories** *(informational, not counted)* — logs — no clean, pii class ipv4, no declared.

## How to fix

* the synthetic subject's data was written to the container log: log identifiers, never payloads; redact at the logger
* client IP addresses written to the log without ip in the declared categories: anonymise the client address in the access log, or declare 'ip' with a purpose

## Reproduce without the tooling

```bash
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| logs | no clean, pii class canary | the synthetic subject's data was written to the container log |
| logs | no clean, pii class not canary, ipv4 | personal data written to the container log |
| logs | no clean, pii class ipv4, no declared | client IP addresses written to the log without ip in the declared categories |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
