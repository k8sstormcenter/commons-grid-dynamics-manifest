# ADR-0010 — Every backend request is authenticated by the platform identity provider

**Status:** proposed  
**Applies to:** tier=backend, tier=middleware; the tier=frontend client code that calls them  
**Enforced by:** app-code, idp-client

## Decision

Every request to a tier=backend or tier=middleware endpoint carries a bearer token issued by the platform identity provider, validated for issuer, audience, expiry and signature; a request without a valid token is answered 401 before application code runs. Health endpoints and the metrics port are the only exceptions. The frontend obtains the token through the provider's browser flow and never holds a client secret.

## Why

Authentication is platform-owned so that no application mints its own sessions. Probing without a token, with a garbage token and with a platform-minted token covers the three failure modes: open route, no signature check, wrong issuer/audience. Probing "/" alone proves nothing — an API that 404s on "/" passes as if it authenticated — so the routes the page actually calls are probed.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **backend routes probed without a token** — at least 1: an evaluator HTTP probe — tier backend or middleware, Authorization none, an existing route.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **backend answers without a bearer token** — an evaluator HTTP probe — tier backend or middleware, Authorization none, path not /metrics, HTTP status < 400.
* **backend accepts an invalid token** — an evaluator HTTP probe — Authorization garbage, HTTP status < 400.
* **backend rejects the platform IdP's token** — an evaluator HTTP probe — Authorization valid, HTTP status not 200, 201, 202, 204, 301, 302, 303, 307, 308, 404, 405.
* **the shell calls a backend but carries no authentication** — the page the frontend serves — tier frontend, backend call sites > 0, authentication markers 0.

Markers counted in the served client code (declared in `compliance/adrs.yaml`, app-neutral):

* `client_state`: `\b(localStorage|sessionStorage|indexedDB)\b`
* `backend_calls`: `\b(fetch\(|XMLHttpRequest|WebSocket|EventSource|axios)\b`
* `auth`: `\b(Authorization|Bearer|login|signin|oauth|openid|jwt|csrf)\b`

## How to fix

* backend answers without a bearer token: validate bearer tokens on every route against the platform IdP's JWKS (from its OIDC discovery document) — issuer, audience, expiry, signature; 401 otherwise
* backend accepts an invalid token: verify signature/issuer/audience/expiry against the IdP JWKS
* backend rejects the platform IdP's token: accept the platform IdP's issuer and audience; fetch its JWKS from the OIDC discovery document
* the shell calls a backend but carries no authentication: authorization-code + PKCE against the platform IdP; send Authorization Bearer on every API call

## Notes

On this platform the identity provider is Zitadel: issuer as published in its OIDC discovery document, JWKS at /oauth/v2/keys, audience = the project id; the platform provisions the per-namespace client (idp-client secret) the evaluator uses to mint a token.

## Reproduce without the tooling

```bash
# probe
curl -sk -o /dev/null -w '%{http_code}\n' http://<backend-pod-ip>:<port><route>   # then with -H 'Authorization: Bearer not.a.token', then with a platform-minted token
# content
curl -s http://<frontend-pod-ip>:<port>/ | grep -o '<script[^>]*src="[^"]*"'   # then fetch each script and grep for the markers listed above
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| probe | GET <route> with Authorization=none | backend answers without a bearer token |
| probe | GET <route> with Authorization=garbage | backend accepts an invalid token |
| probe | GET <route> with Authorization=valid | backend rejects the platform IdP's token |
| content | tier frontend, backend call sites > 0, authentication markers 0 | the shell calls a backend but carries no authentication |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
