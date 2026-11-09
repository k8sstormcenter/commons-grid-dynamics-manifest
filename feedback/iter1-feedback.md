# Iteration 1 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-05T06:20Z by the platform operator after evaluating `deploy-iter1.yaml` @ 558fad5 (scored twice: 06:14:33Z
first complete run, 06:17:27Z re-score with the load counters recognised; both kept in `adr_findings`).
Raw evaluator output: `artefacts/kpi-commons-grid-iter1.json`, `artefacts/iter1-mcp.jsonl`.

```
ITERATION 1 — ADR compliance of namespace commons-grid (deploy-iter1.yaml @ 558fad5, evaluated 2026-11-05T06:17:27Z, 3 pods governed and warm, 16 ADRs)
Summary: 8 VIOLATED / 6 COMPLIANT / 2 NOT_OBSERVED. Progress: ADR-0005 (declared tiers), ADR-0014 (digest pins, IfNotPresent) and ADR-0002 (data tier makes no outbound calls) are now COMPLIANT; 0007, 0016, 0017 still COMPLIANT.
Load measured from your metrics ports: frontend 3143 requests, backend 2283 API requests, 2274 database commands — every component carries load ✓. Your k6 suite ran in-cluster for 45 s.

COUNTED VIOLATIONS (observed → fix):
ADR-0003 Only the backend holds cluster credentials — commons-grid-db (postgres) mounts the ServiceAccount token → automountServiceAccountToken: false on the db AND the frontend
ADR-0004 Images immutable at runtime — container api (and web, postgres): readOnlyRootFilesystem unset → securityContext.readOnlyRootFilesystem: true on all three; writable paths (/tmp, nginx cache, postgres data) as named emptyDir mounts
ADR-0006 Run as non-root — api (and web, postgres): runAsNonRoot unset → runAsNonRoot: true + numeric runAsUser; allowPrivilegeEscalation unset → false
ADR-0010 Requests authenticated by the platform IdP — GET http://commons-grid-backend:8000/api/runs answers 200 with no Authorization header → every /api route must return 401 without a valid bearer token (validate issuer, audience, expiry, signature against the IdP JWKS; only /api/health may stay open); the shell (api.js) carries no authentication → authorization-code + PKCE against the IdP, send Authorization: Bearer on every API call
ADR-0012 Metrics on a dedicated port — commons-grid-db has no containerPort named metrics → add a postgres_exporter sidecar (pinned by digest) with containerPort 9187 named metrics
ADR-0013 Resources, probes and security context — api (and web, postgres): no resources.requests/limits → set both; no livenessProbe / readinessProbe → httpGet for api and web, tcpSocket for postgres; seccompProfile unset → RuntimeDefault; capabilities not dropped → drop [ALL]
ADR-0018 No privilege, no host surface — egress to 169.254.169.254 not blocked (0 NetworkPolicies) → default-deny egress plus explicit allows
ADR-0019 Exposure through the platform's tailnet — frontend not exposed through the platform → annotate the frontend Service tailscale.com/expose: "true", tailscale.com/hostname: "commons-grid", tailscale.com/tags: "tag:edge4", Service port 443 → container 8443 serving TLS from a cert-manager Certificate (ClusterIssuer platform-ca); no default-deny NetworkPolicy → default-deny ingress+egress with allows: tailscale-system→frontend:8443, frontend→backend:8000, backend→database:5432, backend→zitadel, monitoring→metrics ports, all→kube-dns:53

NOT OBSERVED (platform-side, nothing for you to change): ADR-0001 tier layering and ADR-0011 plaintext on the wire — the wire tracer exported no rows for your namespace in this window, so no frontend→backend flow and no X-Test-Case names are visible. I am fixing the export on the platform.

TARGET FOR ITERATION 2: the envelope on all three workloads (ADR-0013, 0006, 0004, 0003) plus authentication on the backend and the shell (ADR-0010). Commit deploy-loadgen.yaml (grafana/k6 Deployment, your script in a ConfigMap, namespace commons-grid-load, BASE_URL http://commons-grid-dynamics.commons-grid.svc for now, DURATION long) so the load runs continuously.
```
