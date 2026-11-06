# Iteration 5 — feedback on the new SLSA + GDPR ADRs (ADR-0020…0027), round 2, branch kcna26colo

Sent 2026-11-06T06:45Z by the platform operator. Evaluated on the running iteration-5 deployment (deploy-iter5.yaml @ 401bd87)
with the new controls; bodies on the wire from the platform's TLS tap (dx-ktls OpenSSL mode → ClickHouse), vulnerabilities
from the platform's in-cluster scanner (kubevuln). Rows: `forensic_db.adr_findings` iteration 5, tool `slsa-gdpr-trial`.

```
ITERATION 5 — new ADRs only (SLSA + GDPR), namespace commons-grid, deploy-iter5.yaml @ 401bd87, evaluated 2026-11-06T06:35–06:45Z
Summary over the 8 new ADRs: 4 VIOLATED / 3 COMPLIANT / 1 NOT_OBSERVED. The 16 earlier ADRs are unchanged (all yours compliant).
Load in the window: 2249 flows, all 7 use cases, bodies inspected: 10 395 (frontend inbound, frontend→backend, backend inbound).

COUNTED VIOLATIONS (observed → fix):
ADR-0020 SLSA provenance from the platform builder — neither image has a provenance attestation, signature or SBOM next to its digest in ghcr → build and push with the platform build template (GitHub Actions: actions/attest-build-provenance + anchore/sbom-action + cosign attest); the image tag must be the commit the workflow built.
ADR-0021 SBOM attached, no known critical vulnerabilities — backend image: 1 CRITICAL, 67 HIGH of which 13 are in packages loaded at runtime (python 3.12.16 base + deps) → rebuild on the current python:3.12-slim (or distroless) and refresh requirements; frontend image was private until now, its scan lands with the next rebuild.
ADR-0023 Record of processing declared — no ConfigMap gdpr-processing → add to the manifest:
  apiVersion: v1 / kind: ConfigMap / metadata.name: gdpr-processing / data: {controller: "<team>", purpose: "<why the app stores runs/simulations>", lawful_basis: "<Art.6 basis>", categories: "none" (or e.g. "email,name" if you store any), retention_days: "30", erasure_path: "/api/runs/{id}"}
ADR-0026 Data-subject rights — erasure works — a record created through POST /api/runs (201, id 123734) cannot be deleted: DELETE /api/runs/123734 → 501 Not Implemented → implement DELETE /api/runs/{id} and /api/simulations/{id} (204, then GET → 404 and absent from the list). Informational: ids are sequential (123734) → use UUIDs for records.

COMPLIANT: ADR-0022 (no code enters at runtime), ADR-0025 (no personal data in logs/URLs: logs clean), ADR-0027 (nothing leaves the namespace to an undeclared peer; one note: the undeleted canary record was served to the loadgen in list responses — it goes away with the DELETE above).
NOT OBSERVED: ADR-0024 (data minimisation) — bodies were inspected and carry no personal data, but the backend serves no /openapi.json, so the schema half cannot be read → expose the OpenAPI document (FastAPI: keep docs_url/openapi_url enabled) — then this ADR can pass.

TARGET FOR ITERATION 6: gdpr-processing ConfigMap, /openapi.json, DELETE endpoints, rebuild through the platform build template (fixes 0020/0021 together).
```
