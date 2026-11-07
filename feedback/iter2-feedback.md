# Iteration 2 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-05T06:35Z by the platform operator after evaluating `deploy-iter2.yaml` @ 18c3936 (06:31:18Z, window 458 s).
Raw evaluator output: `artefacts/kpi-commons-grid-iter2.json`, `artefacts/iter2-mcp.jsonl`.

```
ITERATION 2 — ADR compliance of namespace commons-grid (deploy-iter2.yaml @ 18c3936, evaluated 2026-11-05T06:31:18Z, 3 pods governed and warm, 16 ADRs)
Summary: 7 VIOLATED / 7 COMPLIANT / 2 NOT_OBSERVED. Newly COMPLIANT: ADR-0003 (no SA tokens outside the backend), ADR-0013 (envelope on all three). Still compliant: 0002, 0005, 0007, 0014, 0017.
Load this window was low (frontend 140 requests, backend 149, store 3): your loadgen Deployment could not start (it waited for the loadgen-token Secret). Your iteration-3 commit already replaces that with client_credentials from commons-grid-load/idp-client, so this resolves itself.

COUNTED VIOLATIONS (observed → fix):
ADR-0004 Images immutable at runtime — frontend mounts a writable volume at /usr/share/nginx/html → set readOnly: true on that volumeMount (and on /etc/nginx/conf.d if mounted)
ADR-0006 Run as non-root — the db container's start script used CAP_SETUID (bash) → the postgres entrypoint starts as root and drops; obsolete once the database is removed (iteration 3)
ADR-0010 Requests authenticated by the platform IdP — 401 without a token ✓ and for a garbage token ✓, but a VALID platform token gets 503 on /api/runs, /api/runs/, /api/simulations: the backend cannot fetch the IdP's discovery/JWKS. Fetch BOTH the discovery document and the JWKS from http://zitadel.zitadel.svc:8080 with the HTTP header "Host: localhost:8080" (not from the issuer URL http://localhost:8080, which does not resolve inside the pod), keep iss == "http://localhost:8080" for validation, and cache the keys. Verify from inside the pod: curl -H 'Host: localhost:8080' http://zitadel.zitadel.svc:8080/.well-known/openid-configuration
ADR-0012 Metrics on a dedicated port — db has no metrics port; obsolete once the database is removed
ADR-0016 No shared or long-lived credentials — Secret idp-client is injected into the api container as environment variables → mount it as a read-only file volume and read the values from files
ADR-0018 No privilege, no host surface — egress to 169.254.169.254 not blocked (0 NetworkPolicies) → default-deny egress plus explicit allows
ADR-0019 Exposure through the platform's tailnet — frontend not exposed through the platform, no default-deny NetworkPolicy → Service annotations tailscale.com/expose: "true", tailscale.com/hostname: "commons-grid", tailscale.com/tags: "tag:edge4"; Service 443 → container 8443 serving TLS from a cert-manager Certificate (ClusterIssuer platform-ca); default-deny ingress+egress with allows tailscale-system→frontend:8443, frontend→backend:8000, backend→zitadel:8080, monitoring→metrics ports, all→kube-dns:53

NOT OBSERVED (platform-side, nothing for you): ADR-0001, ADR-0011 — no wire rows exported for the namespace in this window.

TARGET FOR ITERATION 4 (iteration 3 is already queued): the JWKS fix (0010), idp-client as a file (0016), the read-only html mount (0004), then TLS + tailnet exposure + NetworkPolicies (0019/0018).
```
