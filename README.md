# commons-grid-dynamics-manifest

The ADR-compliance demo: a coding agent writes a Kubernetes app, the platform's
Architecture Decision Records are enforced as SBoBs + admission policy, the runtime
evidence lands in ClickHouse, one evaluator turns it into a `kpi.json` for the Pixie UI
and into MCP advice the agent uses to fix its own manifest. Four iterations of that loop
are in this repo, including every manifest the agent produced.

```
deploy*.yaml      the app manifests, iteration 0 (single pod) to 4 (three tiers, TLS, authN, NetworkPolicy)
adr/              the 15 ADRs the platform enforces, and how each is evaluated
sbobs/            the tier SBoBs (ContainerProfiles) exported from the running library namespace
kyverno/          admission: every new pod is classified into a tier and gets the tier SBoB cloned into its namespace
compliance/       the evaluator (adr_kpi.py -> kpi.json), the MCP server (adr_mcp.py), scan + review helpers
harness/          the iteration driver and the feedback that went to the coding agent each round
artefacts/        kpi.json per iteration, the MCP transcripts, the architecture drawing
platform/         demo-side platform glue: platform CA, IdP client provisioning, the kTLS tap
```

## Install

### 1. The SOC stack (kubescape + node-agent + storage + ClickHouse + Pixie + AE + dx)

Not installed from here. It is a Gardener shoot extension:
[k8sstormcenter/gardener-extension-shoot-rtsecurity-service](https://github.com/k8sstormcenter/gardener-extension-shoot-rtsecurity-service)
(`extensions: - type: shoot-rtsecurity-service`, see its `docs/extension-configuration.md`).
Without Gardener, the same chart is applied by the skaffold in
[k8sstormcenter/soc](https://github.com/k8sstormcenter/soc) (`skaffold run -m soc-stack`).
The kTLS tap this demo also uses (`platform/dx-ktls.yaml`, DaemonSet in `honey`) is not yet
part of the extension — tracked there.

Images are private for now; a public image set will be published for KubeCon.

### 2. Demo-side platform

```sh
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --version 3.9.2 --wait
helm upgrade --install cert-manager jetstack/cert-manager -n cert-manager --create-namespace --version v1.19.3 --set crds.enabled=true --wait
kubectl apply -f platform/platform-ca.yaml                       # ADR-0011: ClusterIssuer platform-ca
# ADR-0010 issuer: ZITADEL with its own SBoBs bound, from k8sstormcenter/bob example/zitadel
(cd bob/example/zitadel && ./distro.sh sbob)
```

### 3. ADRs as profiles and policy

```sh
kubectl create namespace sbob-library --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f sbobs/                                          # tier-frontend ... tier-unclassified
kubectl apply -f kyverno/                                        # rbac, clone-tier-sbobs, assign-workload-tier
```

From here every pod created in any namespace is labelled with its tier and
`kubescape.io/user-defined-profile: tier-<tier>`, and the library SBoBs are cloned into
its namespace, so node-agent judges it from its first syscall.

### 4. The app and the loop

```sh
./platform/idp-client.sh commons-grid                            # ZITADEL project + PKCE app + machine user -> Secret commons-grid/idp-client
export ADR_CH=http://<user>:<password>@<clickhouse>:8123          # the stack's ingest user; port-forward svc/clickhouse-forensic-soc-db
./harness/loop.sh 1                                              # apply deploy-iter1.yaml, scan, evaluate, ask the MCP
```

`loop.sh N` applies `deploy-iterN.yaml`, records the time, runs the kubescape static scan,
evaluates runtime + static evidence into `artefacts/kpi-commons-grid-iterN.json` and writes
the MCP answers to `artefacts/iterN-mcp.jsonl`. The coding agent (not in this repo) receives
`harness/feedback/iterN-msg.txt` and pushes `deploy-iter(N+1).yaml`.

MCP registration for the agent's side is in `compliance/README.md`.

## The manifests

Image: `ghcr.io/k8sstormcenter/commons-grid-dynamics` (source `k8sstormcenter/commons-grid-dynamics`).

| file | what |
|---|---|
| `deploy.yaml` | iteration 0: the app as one nginx pod, NodePort service |
| `deploy-pinned.yaml` | the app, image pinned to commit `9ab1489587f7030ef70dbc3b67e170e8bd9f027f` |
| `deploy-runtime.yaml` | the app with redis and postgres sidecars, reverse-proxied on 6379/5432 |
| `deploy-privileged.yaml` | debug deployment with node log and docker socket access |
| `deploy-iter1.yaml` | iteration 1: frontend (nginx) / backend (node API on 8000) / database (redis), tier labels, digest-pinned images, ClusterIP services |
| `deploy-iter2.yaml` | iteration 2: same three tiers with requests/limits, probes, non-root + read-only + drop ALL + RuntimeDefault, no SA token; nginx-unprivileged; no npm install at start; solvers, literature and UI state behind the API |
| `deploy-iter3.yaml` | iteration 3: bearer-token auth on the API (ZITADEL JWKS), PKCE login in the shell, metrics ports + exporters + PodMonitor, tcp-only probes, fsGroup/seLinuxOptions |
| `deploy-iter4.yaml` | iteration 4: NetworkPolicies (default-deny + per tier), cert-manager Certificates from `platform-ca`, TLS on web (8443), api (https 8000) and redis (tls-port 6379), ConfigMaps first + checksum/config annotations, reconnecting redis client, /api/ready |

| iteration | compliant / 15 | kpi |
|---|---|---|
| 1 | 5 (+1 not observed) | `artefacts/kpi-commons-grid-iter1.json` |
| 1, re-evaluated 20 min later | 6 | `artefacts/kpi.json` |
| 2 | 7 | `artefacts/kpi-commons-grid-iter2.json` |
| 3 | 12 | `artefacts/kpi-commons-grid-iter3.json` |
| 4 | 14 (the rest is platform-side) | `artefacts/kpi-commons-grid-iter4.json` |

Architecture: `artefacts/adr-architecture.html`.
