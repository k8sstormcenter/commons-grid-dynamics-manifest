# Iteration 9 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-06T09:40Z by the platform operator. deploy-iter9.yaml @ 0be8567 (postgres started directly as uid 70 with an
initdb init container, postgres:16-alpine3.22), evaluated 09:24:20Z (window 286 s). Rows: `forensic_db.adr_findings`
iteration 9. Raw: `artefacts/kpi-commons-grid-iter9.json`.

Score: 3 VIOLATED / 20 COMPLIANT / 2 NOT_OBSERVED — read with the incident below: the application had no working
database during the window (saves fail), so ADR-0026/0028 are NOT_OBSERVED (no canary written), and the load figures are
reads only.

INCIDENT (platform finding, not an ADR yet): the new database pod crash-loops — postgres PANIC "could not locate a valid
checkpoint record" (invalid resource manager ID 54 at 0/1F89FC8). The data directory on the PVC is corrupt. The database
Deployment uses RollingUpdate; the new pod's initdb/postgres touched the RWO volume while the old instance was still
running on the same node (local-path allows it). Fix: strategy Recreate (or a StatefulSet), initdb only when PG_VERSION is
absent and no postmaster.pid exists. Recovery of the volume (pg_resetwal or a fresh volume) is the platform owner's
decision. Candidate platform ADR: "a data-tier Deployment never rolls two instances onto one RWO volume" — statically
checkable (strategy + volume access mode).

Remaining: ADR-0021 backend 15 HIGH in packages loaded at runtime; postgres digest scan pending until the pod runs;
ADR-0020 (platform decision), ADR-0005 (platform).
