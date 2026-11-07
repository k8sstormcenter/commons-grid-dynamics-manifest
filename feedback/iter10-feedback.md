# ADR feedback — commons-grid, iteration 10

Score (new SLSA/GDPR ADRs, ADR-0020..0028): **7 COMPLIANT / 2 VIOLATED**.
Whole-namespace: 22 COMPLIANT / 3 VIOLATED / 0 NOT_OBSERVED (the third violation, ADR-0005, is a platform profile gap, not yours).

Scored on the recovered database (fresh volume, guarded initdb, `Recreate` strategy) with the dataplane live. No crash-loop taint.

## Compliant — the pseudonymisation refactor landed

- **ADR-0028 pseudonymisation at rest — COMPLIANT.** This was the new obligation. On the backend→database hop every personal identifier is hashed; nothing in clear reached the wire. The canary subject you let us write was observed only in hashed form. The DB refactor did what it needed to.
- **ADR-0023 record of processing — COMPLIANT.** The processing ConfigMap declares controller, purpose, lawful basis, categories, retention and erasure path.
- **ADR-0024 data minimisation — COMPLIANT.** Observed body fields match the declared schema; no undeclared personal-data class on the wire.
- **ADR-0025 no PII in logs or URLs — COMPLIANT.**
- **ADR-0026 erasure — COMPLIANT.** Create → DELETE → GET returned 404; the subject is gone.
- **ADR-0027 PII stays with declared peers — COMPLIANT.**
- **ADR-0022 no code at runtime — COMPLIANT.**

## Violated

### ADR-0021 SBOM + vulnerabilities — VIOLATED (9)
The one in your control:
- **backend** (`commons-grid-dynamics-backend`): 0 critical, **15 relevant HIGH**. Upgrade the packages the relevancy list names (kubevuln `vulnerabilitymanifests`, `relevant`), then re-scan before pushing.
- **web** (`commons-grid-dynamics`): **15 critical**, 1 relevant HIGH. Rebuild on a current base image.

Third-party images (base-image problem, not your code, flagged for the platform): `postgres:16-alpine` 11 critical / 56 relevant HIGH and `postgres-exporter` 14 critical / 69 relevant HIGH. Both also publish **no SBOM** next to their digest.

### ADR-0020 SLSA provenance — VIOLATED (4)
- backend and web carry provenance, but it is **unverified** — the evaluator cannot verify the signature against the build workflow's OIDC identity for a private registry. This is a platform decision (croedig owns the private-repo attestation call), not a code change.
- postgres and exporter carry **no provenance** (third-party images).

## Not your line this iteration
- **ADR-0005 — VIOLATED (2):** R0012 unexpected-ingress alerts on the backend because the tier profile does not declare an architecture-prescribed edge. Platform profile gap.
