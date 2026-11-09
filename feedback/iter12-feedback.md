# ADR feedback — commons-grid, iteration 12

Full evaluation (all 25 ADRs), scored on the recovered database with the dataplane live.

**Result: 3 VIOLATED / 22 COMPLIANT / 0 NOT_OBSERVED.**

All GDPR ADRs are compliant, including pseudonymisation at rest (ADR-0028). The two remaining open items are platform decisions, not code.

## What iteration 12 fixed

- **ADR-0021 frontend criticals — cleared.** The web image dropped from 15 critical to **0 critical** (high 39 to 5). Upgrading curl and libcurl to 8.23.0-r0 and brotli-libs to 1.2.1-r0 in the frontend build did it.
- **ADR-0025 no PII in logs/URLs — COMPLIANT.** A one-off `ccn` flag on the web access log in the interim score was a classifier false positive: a resource UUID in a `/api/runs/<id>` URL whose digit run passed the card test. Fixed in the evaluator (raw-text path now rejects a digit run bounded by hex letters, same rule as the wire path). No real card data; your logs are clean.

## Still VIOLATED — all platform / accepted

### ADR-0020 SLSA provenance — VIOLATED (4), ACCEPTED
Closed as a platform decision: provenance will not be implemented and repository visibility will not change. No code action. This ADR stays VIOLATED by design and should be read as an accepted risk, not an open defect.

### ADR-0021 vulnerabilities — VIOLATED (8), not your code
- **backend** (`...-backend@sha256:93669f4a`): 0 critical, 60 HIGH — all Debian base-OS packages (libc6/glibc, util-linux, ncurses, perl-base, zlib1g, and 17 others), fix state 59 wont-fix / 1 not-fixed. Nothing to pin; no Python packages involved. This needs a base-image change (distroless or Chainguard/Wolfi) or platform risk-acceptance — a decision for the platform, not a refactor.
- **postgres** (`postgres:16-alpine`) and **postgres-exporter**: critical and HIGH CVEs plus no SBOM next to the digest. Third-party images.

### ADR-0005 unexpected ingress — VIOLATED (1), platform profile
R0012 fires on the declared frontend-to-backend edge because the tier profile does not list it. Platform tier-profile gap, not application code.

## Note
Iteration 11 (the first rebuild) is superseded by this one; its only open coder item (frontend criticals) is resolved here.
