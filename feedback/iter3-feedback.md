# Iteration 3 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-05T06:40Z by the platform operator after evaluating `deploy-iter3.yaml` @ 34c9391 (06:37:01Z, window 279 s, 2 pods, wire rows 55, all 7 use cases seen).
Iteration 3 was a client-driven change (database removed), not a response to the iteration-2 feedback; the iteration-2 items are answered by iteration 4.
Raw evaluator output: `artefacts/kpi-commons-grid-iter3.json`, `artefacts/iter3-mcp.jsonl`.

```
ITERATION 3 — ADR compliance of namespace commons-grid (deploy-iter3.yaml @ 34c9391, database removed, evaluated 2026-11-05T06:37:01Z, 2 pods governed and warm, 16 ADRs)
Summary: 6 VIOLATED / 9 COMPLIANT / 1 NOT_OBSERVED. Newly COMPLIANT: ADR-0001 (frontend->backend seen on the wire, no cross-tier shortcuts), ADR-0006 (no root, the db finding went with the db), ADR-0010 (valid platform token now accepted on the API routes), ADR-0012 (metrics ports on both components). Still compliant: 0003, 0007, 0013, 0014, 0017.
Load this window: frontend 1776 requests, backend 1418, all use cases (frontend-page, list/save/load runs, list/save/load simulations) tagged — loadgen works with client_credentials. Good.

COUNTED VIOLATIONS (observed → fix) — all of these are already addressed in your iteration 4 as described; the operator applies it next:
ADR-0004 Images immutable at runtime — writable volume over /usr/share/nginx/html (frontend) → readOnly: true
ADR-0011 No plaintext on the wire — frontend->backend on port 8000 is plain HTTP (55 wire rows, encrypted=0) → TLS on the backend from a cert-manager Certificate (ClusterIssuer platform-ca), the frontend's proxy verifies it; new in this round because the hop is now observed
ADR-0016 No shared or long-lived credentials — idp-client injected as env into api → read-only file mount
ADR-0018 No privilege, no host surface — 169.254.169.254 not blocked, 0 NetworkPolicies → default-deny egress + allows
ADR-0019 Exposure through the platform's tailnet — not exposed, no default-deny → tailscale annotations, 443→8443 TLS, NetworkPolicies
ADR-0005 [platform] the backend tier profile does not declare the backend->zitadel edge (alert on allowed traffic) — platform item, nothing for you.

NOT OBSERVED: ADR-0002 Data tier makes no outbound calls — there is no data tier any more; it stays NOT_OBSERVED (not a pass, not a fail) unless a database returns.

Next: iteration 4 (0df7f4a) is being evaluated now.
```
