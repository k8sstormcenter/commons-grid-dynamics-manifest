# Iteration 7 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-06T09:00Z by the platform operator. deploy-iter7.yaml @ c69cc3d (startup migration, /openapi.json via the
frontend, exporter probes), evaluated 08:46Z by the loop and re-scored 08:53–08:56Z after the evaluator's probes were moved
in-cluster. Rows: `forensic_db.adr_findings` iteration 7 (tools harness + rescore). No personal-data value appears in any
artefact: the tap redacts at ingest, the evaluator redacts its report.

```
ITERATION 7 — ADR compliance of namespace commons-grid (deploy-iter7.yaml @ c69cc3d, evaluated 2026-11-06T08:53Z, 4 pods governed and warm, 25 ADRs)
Summary: 5 VIOLATED / 20 COMPLIANT / 0 NOT_OBSERVED. Newly COMPLIANT: ADR-0023 (record of processing: email,name / 30 days / /api/runs/{id}), ADR-0024 (schema read from /openapi.json, personal-data fields name+e-mail are declared; 75 115 bodies inspected on three legs, nothing undeclared), ADR-0026 (platform canary: POST 201 → DELETE 204 → GET 404, absent from the list), ADR-0028 (the canary owner reached the database only as a hash: 19 745 statements/rows on the backend→database hop inspected, no e-mail or other identifier in clear), ADR-0027 (personal data goes to no peer outside the namespace). Still compliant: 0001–0004, 0006, 0007, 0010, 0011, 0014, 0016–0019, 0022, 0025.
Load: frontend 11 913 requests, backend 5 765 / 5 459 commands, database 34 754 commits; all use cases incl. save-run-with-owner.

COUNTED VIOLATIONS (observed → fix):
ADR-0013 Resources, probes and security context — the NEW database pod never became Ready: its postgres-exporter sidecar fails its own liveness/readiness (GET :9187/metrics → EOF/timeout) and is restarted in a loop, so the rollout timed out and the OLD pod (exporter without probes) is still the one serving. Cause to check: the exporter connects to postgres over the pod network while pg_hba is hostssl-only — give the exporter sslmode=require (or let it use the local socket / a `local` pg_hba line), then the probes pass and the rollout completes.
ADR-0012 Metrics on a dedicated port — the backend answers /metrics on its application port 8443 as well (200, 200 kB) → serve metrics only on the port named metrics (9100); 404 /metrics on 8443.
ADR-0021 SBOM / vulnerabilities — backend image 1 CRITICAL, 65 HIGH (15 loaded at runtime); postgres:16-alpine 5 CRITICAL / 46 HIGH; postgres-exporter 15 CRITICAL (14 loaded!) / 77 HIGH; upstream images carry no SBOM → rebuild the backend on a current base, move the exporter to a current release (quay.io/prometheuscommunity/postgres-exporter:v0.17.x) and postgres to the current 16.x digest.
ADR-0020 SLSA provenance — your images now carry buildx provenance/SBOM manifests (credited), but not an attestation signed by a hosted builder identity; the platform owner decides how private-repo builds get attested (nothing for you until then). Upstream images (postgres, exporter) have none.
ADR-0005 [platform] frontend→backend edge on 8443 not in the tier profile — platform item, nothing for you.

TARGET FOR ITERATION 8: exporter TLS (so the probes pass and the rollout completes), /metrics off port 8443, current base images for backend/postgres/exporter. After that, everything you own is compliant.
```
