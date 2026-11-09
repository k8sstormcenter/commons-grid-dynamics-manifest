# Iteration 4 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-05T06:47Z by the platform operator after evaluating `deploy-iter4.yaml` @ 0df7f4a (06:42:55Z, window 283 s, 2 pods, wire rows 50, 6 use cases seen).
Iteration 4 answers the iteration-2/3 feedback. Raw evaluator output: `artefacts/kpi-commons-grid-iter4.json`, `artefacts/iter4-mcp.jsonl`.

Operator note: the ADR-0016 row is an evaluator defect (name-based heuristic flagged `IDP_SECRET_DIR=/etc/idp-client`, a path, not a credential). The row stays in adr_findings as evidence; the evaluator fix (judge the value, not the name) is on the post-demo backlog.

```
ITERATION 4 — ADR compliance of namespace commons-grid (deploy-iter4.yaml @ 0df7f4a, evaluated 2026-11-05T06:42:55Z, 2 pods governed and warm, 16 ADRs)
Summary: 4 VIOLATED / 11 COMPLIANT / 1 NOT_OBSERVED. Newly COMPLIANT: ADR-0004 (html volume read-only), ADR-0018 (default-deny egress, metadata API blocked), ADR-0019 (frontend exposed through the tailnet on 443→8443 with the platform-ca certificate, default-deny in place). Still compliant: 0001, 0003, 0006, 0007, 0012, 0013, 0014, 0017.
Load this window: 50 wire rows, use cases list/save/load runs + simulations through the tailnet-facing frontend; loadgen fine.

COUNTED VIOLATIONS (observed → fix):
ADR-0010 Requests authenticated by the platform IdP — a VALID token minted by the platform from THIS namespace's own client (commons-grid/idp-client, project 398191533553091194 — the same project_id you mount at /etc/idp-client/project_id) gets 401 on /api/runs; your ACCEPTED_AUDIENCES=398230519810097786 only lists the loadgen's project. → accept the namespace's own project_id (read from the mounted file) AND the loadgen project: ACCEPTED_AUDIENCES = {file project_id} ∪ {398230519810097786}.
ADR-0011 No plaintext on the wire — frontend→backend on port 8000 is still plain HTTP (50 rows, encrypted=0) → serve the backend over TLS (Certificate from ClusterIssuer platform-ca, like the frontend), nginx proxy_pass https://commons-grid-backend:8443 with proxy_ssl_verify on and proxy_ssl_trusted_certificate from the platform-ca secret; update the backend-ingress/frontend-egress NetworkPolicies to 8443.
ADR-0016 — IGNORE: the evaluator flagged the env var name IDP_SECRET_DIR; its value is a path. Your file-mounted idp-client is correct; nothing to do.
ADR-0005 [platform] backend→zitadel edge not declared in the tier profile — platform item, nothing for you.

NOT OBSERVED: ADR-0002 (no data tier).

TARGET FOR ITERATION 5: the audience fix (0010) and TLS on the backend hop (0011). Those two would make the namespace fully compliant on everything you own.
```
