# ADR-0028 — Personal identifiers reach the data tier only as keyed hashes or tokens; never in clear in SQL or on the database hop

**Status:** proposed  
**Applies to:** every workload that stores records about people; the backend→database hop  
**Enforced by:** dx-ktls.openssl, pixie.pgsql_events, evaluator.canary

## Decision

A personal identifier (e-mail, name, phone, address, government or payment id) reaches the data tier only as a keyed hash (HMAC with a platform-held key) or a token; it is never written in clear into SQL text, never returned in clear from the database, and the clear value lives only in the request that carried it. Records are addressed by random identifiers.

## Why

Pseudonymisation (Art. 4(5), 25, 32) is the one GDPR measure that is visible on the wire: the platform decrypts the backend→database hop and inspects statements and result rows for personal-data classes, and it plants its own canary subject through the API — if the canary arrives at the database in clear, the application stores identifiers in clear. A breach of the database then exposes hashes, not people.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **coverage** — every pod of tier database carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.
* **statements/rows on the database hop inspected (TLS tap or pgsql_events)** — at least 1: pii — db hop, inspected > 0.
* **the platform's canary subject was written through the API (so the hop carried an identifier to hash)** — at least 1: erasure — created < 300.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the platform's canary subject reached the database hop in clear (not hashed/tokenised)** — pii — db hop, pii class canary.
* **a personal identifier was observed in clear on the database hop (SQL text or result rows)** — pii — db hop, pii class not None, canary, ipv4.

## How to fix

* the platform's canary subject reached the database hop in clear (not hashed/tokenised): HMAC-SHA256 (key from a platform Secret) or a token table before the INSERT; keep clear values only in the same request's response
* a personal identifier was observed in clear on the database hop (SQL text or result rows): hash or tokenise identifiers before storage; never SELECT them back in clear

## Notes

Needs a data tier to exist and the TLS tap (dx-ktls OpenSSL mode) or Pixie pgsql_events on the hop; without rows on the hop the ADR is NOT_OBSERVED, never COMPLIANT.

## Reproduce without the tooling

```bash
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| pii | db hop, pii class canary | the platform's canary subject reached the database hop in clear (not hashed/tokenised) |
| pii | db hop, pii class not None, canary, ipv4 | a personal identifier was observed in clear on the database hop (SQL text or result rows) |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
