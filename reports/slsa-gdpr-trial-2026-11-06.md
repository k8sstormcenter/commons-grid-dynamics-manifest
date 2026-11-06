# SLSA + GDPR controls — trial on the iteration-5 state (commons-grid, 2026-11-06)

Evaluated 2026-11-06 ~05:52Z over a 600 s window on the live iteration-5 deployment (deploy-iter5.yaml @ 401bd87,
2 pods, both governed, 82 630 s old). Same engine, same loop, same table: 39 rows in `forensic_db.adr_findings`
(iteration 5, tool `slsa-gdpr-trial`). Raw: `artefacts/kpi-commons-grid-iter5-slsa-gdpr.json`.

Result over the 8 new ADRs: **4 VIOLATED / 2 COMPLIANT / 2 NOT_OBSERVED** (all 24: 5 / 16 / 3).

| ADR | control | status | evidence | what decides it |
|---|---|---|---|---|
| 0020 SLSA provenance | S1–S4 (build L1–L3 + source match) | VIOLATED | both images: no `.att`, no `.sig`, no referrers at ghcr | registry read per digest; cosign verify not reached (nothing to verify; cosign install was denied on edge4 anyway) |
| 0021 SBOM + vulns | S6, S7 | VIOLATED | both images: no SBOM referrer at ghcr; **kubevuln (enabled 06:07Z)**: backend image 1 CRITICAL, 67 HIGH of which 13 relevant (loaded at runtime), 84 MEDIUM; frontend image scan not finished at run time (informational) | registry read + VulnerabilityManifestSummary per image (severities all/relevant) |
| 0022 No code at runtime | S11, S12 | COMPLIANT | 3406 sensor rows, no package-manager/downloader exec, no egress to a registry/code host | R0001/R0040 process names + R0011 domains; coverage ok |
| 0023 Record of processing | G1, G2 | VIOLATED | no ConfigMap `gdpr-processing` | static |
| 0024 Data minimisation | G3, G4, G5 | NOT_OBSERVED | backend serves no `/openapi.json` (404); 0 decrypted bodies on the wire | schema probe + bodies from dx-ktls/Pixie — **both missing** |
| 0025 No PII in logs/metrics/URLs | G6, G7 | COMPLIANT | canary not in logs; backend log clean; nginx access log has client IPs (2) → informational (ip not declared) | kubectl logs over the window |
| 0026 Erasure works | G12, G13, G21 | NOT_OBSERVED | canary POST `/api/runs` {name,email} → 400 bad request: the API's record shape is unknown without a schema, so no subject could be created | needs `/openapi.json` (or a declared erasure_path + sample) |
| 0027 PII stays with declared peers | G14, G16 | COMPLIANT (thin) | no external egress in the window; 0 wire bodies, so the PII part is untested | egress from sensor + wire; bodies missing |

Side findings from the same run: ADR-0006 now discounts the 12 runc rows (new `container_start` discount) and
counts 2 real ones — `sh` using CAP_SETUID/SETGID at 05:3xZ, which was my own `kubectl exec` into the pods while
checking libssl (correct: an exec is not the image). ADR-0016's `IDP_SECRET_DIR` false positive is gone
(value judged, not the name).

## Second run 06:1xZ — after enabling capabilities.vulnerabilityScan (kubevuln v0.3.159, soc skaffold)

ADR-0021 now scores from in-cluster evidence: `vulns` source reads `vulnerabilitymanifestsummaries` (GET per object;
LIST nulls .spec) — counted: CRITICAL > 0, HIGH relevant > 0; informational: HIGH not loaded, image not yet scanned.
Backend api: critical 1 (not relevant), high 67 / 13 relevant, medium 84, low 14. ADR-0006 is COMPLIANT in this
window (no exec of mine). 0001/0011 read NOT_OBSERVED in the 600 s window because the loadgen crashloops (coder's
liveness probe on k6 :6565) — no application flows, not a regression. kubevuln-scheduler cron 04:07 daily rescans.
Pull secret honey/duckling-pull stayed entlein after the hook (checked). dx-ktls OpenSSL build was stopped by
croedig; the wire-PII rows stay NOT_OBSERVED until a body source exists (Pixieagent asks AEDX about the existing
ecapture image).

## The wire-PII path (G4, G5, G16) is not scoreable yet — and why

* dx-ktls 49a3d1e hooks Go crypto/tls only (kubelet); nginx (OpenSSL 3.5.9/musl) and CPython (OpenSSL 3.5.7/glibc)
  are not covered — new code (SSL_read/SSL_write uprobes), Pixieagent/Buildagent's build.
* Pixie's PEM does attach to both (conn_stats ssl=1, protocol=HTTP/1), yet `http_events` has 0 rows for the
  namespace in 6 h, also for 10 small `Connection: close` requests (05:39Z) → PEM parse/emission defect, not load,
  not h2, not buffers. PEM is croedig's call.
* `forensic_db.tls_events` is Pixie's handshake table (no bodies). The dx tables that carry bodies are
  order-driven: `dx_ord__tls_events` / `dx_shadow__tls_events` fill only when an SBoB++ obligation opens an order
  after a profile violation. That formulation (which traces to include, which query/protocol patterns to look for)
  is not in `sbobs/` (grep: nothing) — it has to be re-authored by the dx owner as a fragment on the tier profiles,
  e.g. trigger R0011/R0012 or a dedicated canary rule → obligation naming `tls_events`/`http_events` with the PII
  regex classes (email, ipv4, ccn, iban, ssn) → rows in the canonical table the evaluator reads.

## What the coder must add for the GDPR rows to be measurable (feedback for the next iteration)
1. `ConfigMap gdpr-processing` (controller, purpose, lawful_basis, categories, retention_days, erasure_path).
2. Serve `/openapi.json` from the backend (FastAPI does by default; the app disabled it).
3. `DELETE /api/runs/{id}` (erasure path) — probably exists; untestable until 2.
4. Build through the platform build template so provenance + SBOM land in ghcr next to the digest.

## Files (r11)
compliance/adrs.yaml, compliance/adr_text.yaml, compliance/evidence.py (sources attest, declare, schema, pii, logs,
erasure; secret-value check; discount container_start), adr/0020–0027 + README (generated),
artefacts/kpi-commons-grid-iter5-slsa-gdpr.json, artefacts/iter5-slsa-gdpr-since, this report.
