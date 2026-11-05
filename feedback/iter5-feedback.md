# Iteration 5 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-05T06:57Z by the platform operator after evaluating `deploy-iter5.yaml` @ 401bd87 (06:52:19Z, window 277 s, 2 pods, sensor rows 5041, wire rows 8).
Raw evaluator output: `artefacts/kpi-commons-grid-iter5.json`, `artefacts/iter5-mcp.jsonl`.

Operator notes (rows stay in adr_findings as evidence; evaluator fixes are post-demo backlog):
- ADR-0006: all 5 counted findings are R0004 capability alerts on `runc:[1:CHILD]` / `runc:[2:INIT]` at 06:48:13Z — the container runtime creating the pod, not the application (securityContext is complete: runAsNonRoot, runAsUser 10001, drop ALL, no priv-esc, read-only root, RuntimeDefault). Evaluator defect: runc processes at container creation must be discounted.
- ADR-0016: same name-heuristic false positive as iteration 4 (`IDP_SECRET_DIR` is a path).
- ADR-0005: platform — the backend tier profile declares the frontend→backend edge on 8000, the hop moved to 8443, so R0012 fired ×4700 on allowed traffic. Platform (bobctl) item.
- ADR-0011 is COMPLIANT on thin evidence: the frontend is tailnet-exposed with TLS, the frontend→backend hop was seen as a connection with encrypted=1 and no plaintext HTTP row was captured on it (8 wire rows total in the window). The only plaintext hop left is backend→zitadel:8080, which is the platform's IdP endpoint, not the application's choice.

```
ITERATION 5 — ADR compliance of namespace commons-grid (deploy-iter5.yaml @ 401bd87, evaluated 2026-11-05T06:52:19Z, 2 pods governed and warm, 16 ADRs)
Summary: 3 VIOLATED / 12 COMPLIANT / 1 NOT_OBSERVED. Newly COMPLIANT: ADR-0010 (platform token from this namespace's project accepted: 200, no token 401), ADR-0011 (frontend→backend over TLS on 8443, no plaintext HTTP observed on the hop, frontend TLS through the tailnet). Compliant: 0001, 0003, 0004, 0007, 0010, 0011, 0012, 0013, 0014, 0017, 0018, 0019.
Load this window: frontend 6171 requests, backend 4868.

The three remaining VIOLATED rows are NOT yours:
ADR-0006 — R0004 capability alerts on runc:[1:CHILD]/runc:[2:INIT] at pod creation (06:48:13Z), i.e. the container runtime starting your pod; your securityContext is complete. Evaluator defect, being fixed on the platform side.
ADR-0016 — the IDP_SECRET_DIR name false positive from iteration 4; nothing to do.
ADR-0005 [platform] — the backend tier profile still declares the frontend→backend edge on 8000; your move to 8443 is correct, the platform updates the profile.
NOT OBSERVED: ADR-0002 (no data tier).

Result: every ADR the application author owns is COMPLIANT as of iteration 5. No further iteration is requested; stay on 401bd87 unless the client asks for a change.
```
