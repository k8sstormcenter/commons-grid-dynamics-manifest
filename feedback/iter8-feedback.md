# Iteration 8 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-06T09:16Z by the platform operator. deploy-iter8.yaml @ 3cb9129 (exporter on the local socket, /metrics 404 on
8443, rebuilt backend / exporter v0.17.1 / postgres digest), evaluated 09:09:18Z by the loop (window 288 s, 5008 sensor rows,
397 wire rows, all use cases). Rows: `forensic_db.adr_findings` iteration 8. Raw: `artefacts/kpi-commons-grid-iter8.json`.
Operator note: the ADR-0027 row "egress to :: port 65535" is an evaluator artefact (a listen socket read as a peer) — fixed in
compliance/evidence.py after the run; row kept.

```
ITERATION 8 — ADR compliance of namespace commons-grid (deploy-iter8.yaml @ 3cb9129, evaluated 2026-11-06T09:09:18Z, 3 pods governed and warm, 25 ADRs)
Summary: 5 VIOLATED / 20 COMPLIANT / 0 NOT_OBSERVED. Newly COMPLIANT: ADR-0012 (metrics only on the metrics ports), ADR-0013 (database rollout completed: exporter on the local socket, probes pass), ADR-0021 for the backend and the exporter (no critical/relevant-high left on the rebuilt images). All GDPR ADRs (0023–0028) stay COMPLIANT. Load: frontend 8079, backend 5640 / 5218 commands, database 42 662 commits; all use cases incl. save-run-with-owner.

COUNTED VIOLATIONS (observed → fix):
ADR-0006 Run as non-root — the database container's entrypoint (docker-entrypoint.sh/gosu in postgres:16-alpine) used CAP_SETGID at start: the image starts as root and drops to postgres. Fix: run the container as uid 70 from the start (securityContext.runAsUser: 70, runAsGroup: 70, fsGroup: 70, allowPrivilegeEscalation false, drop ALL) — or a rootless postgres image.
ADR-0021 SBOM / vulnerabilities — only postgres:16-alpine is left: 5 CRITICAL / 46 HIGH (none loaded at runtime) and no SBOM upstream → current postgres:16-alpine3.21 digest or postgres:17-alpine; re-check with the scanner.
ADR-0020 SLSA provenance — unchanged, platform-owner decision; nothing for you.
ADR-0005 [platform] — profile edge; nothing for you.
ADR-0027 — one row "egress to :: port 65535" from the database is an evaluator artefact; ignore.

TARGET FOR ITERATION 9: postgres as uid 70 from the start, and a postgres digest without critical CVEs. That closes everything you own.
```
