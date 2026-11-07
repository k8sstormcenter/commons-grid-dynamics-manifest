# Iteration 0 — feedback sent to the citizen-coder agent (round 2, branch kcna26colo)

Sent 2026-11-05T06:00Z by the platform operator (edge4) after evaluating the naive manifest
(`deploy-iter0.yaml`, image `commons-grid-dynamics@sha256:229396b5…`) at 05:50:04Z, window 247 s,
16 ADRs. Raw evaluator output: `artefacts/kpi-commons-grid-iter0.json`, `artefacts/iter0-mcp.jsonl`.

```

ITERATION 0 — ADR compliance of namespace commons-grid (your naive manifest, evaluated 2026-11-05T05:50:04Z, window 247 s, 16 ADRs)
Summary: 9 VIOLATED / 3 COMPLIANT / 4 NOT_OBSERVED.
Status: ADR-0001=NOT_OBSERVED, 0002=NOT_OBSERVED, 0003=VIOLATED, 0004=VIOLATED, 0005=VIOLATED, 0006=VIOLATED, 0007=COMPLIANT, 0010=NOT_OBSERVED, 0011=VIOLATED, 0012=NOT_OBSERVED, 0013=VIOLATED, 0014=VIOLATED, 0016=COMPLIANT, 0017=COMPLIANT, 0018=VIOLATED, 0019=VIOLATED.

HOW THIS WORKS: I am the platform operator. Push deploy-iter1.yaml to branch kcna26colo of the manifest repo; I apply it, let the sensor warm up, put traffic on it, scan and send you iteration 1's feedback (about 5 minutes after your push). Each finding names what was observed and the exact change. Items marked [platform] are mine.

COUNTED VIOLATIONS (observed → fix), container "web" of Deployment commons-grid-dynamics unless stated:
ADR-0003 Only the backend holds cluster credentials — the ServiceAccount token is mounted (automountServiceAccountToken unset) → spec.template.spec.automountServiceAccountToken: false
ADR-0004 Images immutable at runtime — root filesystem writable (readOnlyRootFilesystem unset) → securityContext.readOnlyRootFilesystem: true; writable paths as named emptyDir mounts
ADR-0005 Every workload is classified and bound [platform] — admission guessed tier=frontend from port 80 → on your side: declare the label app.kubernetes.io/tier on every workload (frontend | backend | database)
ADR-0006 Run as non-root — runAsNonRoot unset, runAsUser unset → securityContext.runAsNonRoot: true, runAsUser: <numeric uid>; allowPrivilegeEscalation unset → securityContext.allowPrivilegeEscalation: false
ADR-0011 No plaintext on the wire — Service type NodePort exposes plaintext port 80 → Service type ClusterIP; the frontend serves TLS (see THIS PLATFORM)
ADR-0013 Resources, probes and security context — no resources.requests → set requests.cpu/memory; no resources.limits → set limits.cpu/memory; no livenessProbe → httpGet (e.g. / on the serving port); no readinessProbe → httpGet; no seccomp → securityContext.seccompProfile.type: RuntimeDefault; capabilities not dropped → securityContext.capabilities.drop: [ALL]
ADR-0014 Images pinned by digest — the image is pinned but imagePullPolicy: Always → imagePullPolicy: IfNotPresent
ADR-0018 No privilege, no host surface — egress to 169.254.169.254 (cloud metadata) not blocked: 0 NetworkPolicies → default-deny egress NetworkPolicy plus explicit allows (never one covering 169.254.169.254)
ADR-0019 Exposure through the platform's tailnet — Service type NodePort (nodePort 30080) → ClusterIP; the frontend is not exposed through the platform → annotate the frontend Service: tailscale.com/expose: "true", tailscale.com/hostname: "commons-grid", tailscale.com/tags: "tag:edge4"; no default-deny NetworkPolicy → default-deny ingress+egress with allows: tailscale-system→frontend, frontend→backend, backend→database, backend→zitadel (IdP), monitoring→metrics ports, all→kube-dns

NOT OBSERVED (evidence missing, not a pass): ADR-0001 tier layering, ADR-0002 data-tier egress, ADR-0010 authentication, ADR-0012 metrics — there is no backend and no database tier yet.
COMPLIANT: ADR-0007, ADR-0016 (no credentials found), ADR-0017 (default ServiceAccount, no bindings).

TARGET FOR ITERATION 1: split into three Deployments + ClusterIP Services with declared labels app.kubernetes.io/tier: frontend (the nginx shell), backend (an API, port 8000 or 8080), database (postgres or redis). Every image pinned by digest with imagePullPolicy IfNotPresent. The shell must call the backend (fetch to /api/…, nginx proxying /api/ to the backend Service), the backend must read and WRITE through the database. Keep namespace commons-grid.

TRAFFIC (required): commit load/k6.js in the manifest repo, derived from your functional tests. Every request: User-Agent "adr-driver/k6" and header "X-Test-Case: <use case>"; BASE_URL and DURATION come from env. Cover every component with real load: ≥ 200 frontend requests, ≥ 200 backend API requests and ≥ 200 database commands (writes AND reads through the API: save run, load run, list runs, persisted simulations) per minute of test. From iteration 2 on also commit deploy-loadgen.yaml: a Deployment (image grafana/k6, your script in a ConfigMap) in namespace commons-grid-load that runs the suite continuously with several virtual users. I read each component's load from its metrics port and will name any under-exercised component.

THIS PLATFORM (facts you cannot see from the manifest):
- Exposure: no Ingress or Gateway objects can be admitted here. The frontend Service is exposed through the tailscale operator (the three annotations above); the exposed port must be the frontend's own TLS port (Service 443 → container 8443, certificate from a cert-manager Certificate with ClusterIssuer platform-ca). The tailnet proxy pods live in namespace tailscale-system.
- Identity provider: Zitadel; issuer "http://localhost:8080", reached in-cluster at http://zitadel.zitadel.svc:8080 with the HTTP header "Host: localhost:8080" (OIDC discovery and JWKS at /oauth/v2/keys). Your namespace has Secret commons-grid/idp-client (client_id, client_secret, token_endpoint, project_id); the token audience is the project_id.
- No Prometheus operator: no PodMonitor/ServiceMonitor CRDs. Expose a containerPort named "metrics" and admit namespace monitoring on it; the platform scrapes it.
- Namespaces for NetworkPolicies: DNS = kube-system (kube-dns), ingress = traefik and tailscale-system, IdP = zitadel, monitoring = monitoring.
- Names like commons-grid.local do not resolve in-cluster; the loadgen targets https://commons-grid-dynamics.commons-grid.svc (skip TLS verify).
- The platform recognises tiers from image names (nginx/caddy → frontend, node/python/go → backend, postgres/redis → database) but you must declare app.kubernetes.io/tier yourself.
```
