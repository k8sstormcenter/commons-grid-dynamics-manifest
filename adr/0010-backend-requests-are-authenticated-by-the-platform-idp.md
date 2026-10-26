# ADR-0010 — Every backend request is authenticated by the platform identity provider

**Status:** proposed
**Applies to:** `tier=backend`, `tier=middleware`; the `tier=frontend` client code that calls them

## Context

Once an application is split ([ADR-0008](0008-presentation-tier-serves-presentation-only.md))
the backend API is the thing worth protecting, and the vibe-coder's default is to protect it
with nothing — or with a hand-rolled login that stores a password hash in the data tier and a
session id in `localStorage`. Both are the same mistake: identity becomes an application
concern, and every application solves it differently and wrongly.

The platform runs an identity provider: ZITADEL, deployed and profiled in
[`example/zitadel`](../../zitadel/DEMO.md) (nine SBoBs, 0 false positives on benign traffic).
Applications on the platform do not own identity; they verify tokens it issues.

| | |
|---|---|
| namespace / Service | `zitadel` / `zitadel:8080` (API + console), `zitadel-login:3000` (login UI) |
| discovery | `/.well-known/openid-configuration` |
| JWKS | `/oauth/v2/keys` |
| routing | ZITADEL routes on the `Host` header and compares it to `ExternalDomain`; a request to the ClusterIP without the right Host gets `404` from a healthy server. `ExternalDomain` is therefore set to the name backends use for the issuer. |
| profile | the IdP is itself a `tier=middleware` workload under these ADRs; its SBoBs are bound from container start (`distro.sh sbob`) |

## Decision

* Every request to a `tier=backend` or `tier=middleware` endpoint carries a bearer token issued
  by the platform IdP. The backend validates issuer, audience, expiry and signature against the
  IdP's JWKS. No other authentication scheme (basic auth, API key in a header, cookie session
  minted by the app) is accepted.
* A request without a valid token is answered `401` before any application code runs. Health
  (`/healthz`, `/readyz`) and the metrics port ([ADR-0012](0012-metrics-are-served-on-a-dedicated-port.md)) are the only exceptions.
* The `tier=frontend` shell obtains the token through the IdP's browser flow (authorization
  code + PKCE). It never holds a client secret ([ADR-0003](0003-no-cluster-credentials-in-presentation-tier.md)
  applies to IdP credentials too).
* The backend's egress to the IdP (discovery, JWKS) is declared in its profile. It is the one
  external destination a backend is expected to have besides the data tier.

## Verified by

**Live probe (mechanical)** — `GET` the backend Service's main port without `Authorization`:
expect `401` (or `403`). `200` is a violation. A `401` from a bogus token is the second half of
the check.

**Content (frontend)** — the shell's client code references the IdP (`openid`, `oauth`,
`Authorization: Bearer`, or the platform's OIDC client library). No auth markers in a frontend
that calls a backend is a violation on the frontend side.

**Runtime (corroborating)** — the backend profile carries egress to the IdP; `R0011` from a
backend to the IdP host without that declaration means it is validating tokens the profile
does not know about — allowed behaviour, undeclared profile, and a finding under ADR-0005.
Once Pixie `http_events` are joined, unauthenticated `200`s on backend ports are the direct
evidence.

## Evidence emitted

```
ADR-0010 VIOLATED   UNAUTHENTICATED_BACKEND
  observed  GET http://commons-grid-api:8000/simulate without Authorization -> 200 (expected 401)
  observed  frontend shell has no OIDC/bearer markers in served code
  fix       validate platform-IdP bearer tokens on every backend route (issuer/audience/JWKS);
            frontend: authorization-code + PKCE against the platform IdP; return 401 otherwise
```

## Consequences

* Applications gain a dependency on the IdP being reachable; the backend's startup must
  tolerate JWKS fetch failure without opening up (fail closed).
* The IdP's issuer URL, the client registration and the expected audience are platform
  configuration, not application configuration; they are injected, never baked into images.

## Known sharp edge

The `example/zitadel` values ship `TLS: {Enabled: false}` and `ExternalDomain: localhost` —
enough to profile the IdP, not enough to satisfy [ADR-0011](0011-no-plaintext-on-the-wire.md).
The platform deployment of the same chart sets `ExternalDomain` to the in-cluster issuer name
and terminates TLS; the SBoBs do not change, the egress peer does.

The live probe is a request from the evaluator into the backend's Service port. On the rig that
request originates from the node, not from a frontend pod, and is itself visible as an `R0011`-
less ingress to the backend — harmless, but it will appear in the backend's trace.
