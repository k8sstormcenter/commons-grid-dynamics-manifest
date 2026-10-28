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

## Run the loop on your own app

Assumes the SOC stack is installed (section "Install" below) and this repo is checked out:

```sh
git clone -b demo https://github.com/k8sstormcenter/commons-grid-dynamics-manifest ~/adr-demo && cd ~/adr-demo
```

### 1. Point the evaluator at the evidence

The evaluator and the MCP read node-agent detections from the stack's ClickHouse. One variable:

```sh
export ADR_CH="http://ingest_writer:<password>@$(kubectl -n clickhouse get pod -l clickhouse.altinity.com/chi=forensic-soc-db -o jsonpath='{.items[0].status.podIP}'):8123"
```

(`ingest_writer` is the stack's ingest user; its password is in the soc chart values.)

### 2. Give your coding agent the MCP

```sh
claude mcp add adr -e ADR_CH="$ADR_CH" -- python3 ~/adr-demo/compliance/adr_mcp.py
```

The agent now has `adr_compliance`, `adr_violations`, `adr_explain`, `adr_architecture`,
`adr_recheck` (details in `compliance/README.md`). Nothing else is configured on the
agent's side: it does not know the ADRs, it asks.

### 3. Vibe-code an app

Ask the agent for an app, do not sanitise what it gives you. Have it target a namespace of
its own (`NS` below). Nothing needs preparing for that namespace: at admission kyverno
labels every pod with its tier and `kubescape.io/user-defined-profile: tier-<tier>` and
clones the tier SBoBs from `sbob-library` into the namespace, so node-agent governs the
pod from its first syscall. After the namespace exists, provision its identity on the
platform IdP (ADR-0010 is probed with it; the secret stays in the cluster):

```sh
./platform/idp-client.sh $NS
```

### 4. Iterate

```sh
./harness/loop.sh 1 $NS path/to/the-agents-manifest.yaml
```

`loop.sh N NS MANIFEST` records the time, applies the manifest, waits for the app to be
exercised (`WARMUP`, default 60 s: click around, hit the API), runs the kubescape static
scan, evaluates runtime + static evidence into `artefacts/kpi-$NS-iterN.json` (the file
the Pixie UI shows) and writes what the MCP answers to `artefacts/iterN-mcp.jsonl`.

Then close the loop through the agent:

> ask the `adr` MCP (`adr_architecture`, then `adr_violations`) what my app in namespace
> `$NS` violates and rewrite the manifest to comply; apply nothing yourself

Every finding carries the observed event (container, peer, port, process), the ADR it
broke, the fix and the ClickHouse evidence reference. Save the rewrite, run `loop.sh 2`,
repeat. `adr_recheck` with the `since` from `artefacts/iterN-since` is what tells the agent
whether its fix held. The feedback our agent received each round is in `harness/feedback/`.

Reading a result: `summary` in the kpi json (`compliant` / `violated` / `not_observed`,
`coverage.governed` must equal `coverage.pods`), `adrs[]` per decision with its findings,
`adr_explain` for the decision text.

Things that look like a broken demo and are not: evidence is filtered to live pods, so a
pod that was still rolling when the evaluation ran contributes nothing (`not_observed`);
`since` is per iteration, so an old violation never bleeds into the next round; `R0002`
(runtime writes, ADR-0004) must be enabled in the stack's default-rules.

## Install

### 1. The SOC stack (kubescape + node-agent + storage + ClickHouse + Pixie + AE + dx)

Not installed from here. It is a Gardener shoot extension:
[k8sstormcenter/gardener-extension-shoot-rtsecurity-service](https://github.com/k8sstormcenter/gardener-extension-shoot-rtsecurity-service)
(`extensions: - type: shoot-rtsecurity-service`, see its `docs/extension-configuration.md`).
Without Gardener, the same chart is applied by the skaffold in
[k8sstormcenter/soc](https://github.com/k8sstormcenter/soc) (`skaffold run -m soc-stack`).
The kTLS tap this demo also uses (`platform/dx-ktls.yaml`, DaemonSet in `honey`) lives on
the soc branch `ktls` (`tree/dx/`) until it is integrated; its table `dx_kubelet_stream`
keeps 24 h.

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

## The manifests our agent produced

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

To replay exactly our run: `./harness/loop.sh N` with no further arguments uses
namespace `commons-grid` and `deploy-iterN.yaml`.

| iteration | compliant / 15 | kpi |
|---|---|---|
| 1 | 5 (+1 not observed) | `artefacts/kpi-commons-grid-iter1.json` |
| 1, re-evaluated 20 min later | 6 | `artefacts/kpi.json` |
| 2 | 7 | `artefacts/kpi-commons-grid-iter2.json` |
| 3 | 12 | `artefacts/kpi-commons-grid-iter3.json` |
| 4 | 14 (the rest is platform-side) | `artefacts/kpi-commons-grid-iter4.json` |

Architecture: `artefacts/adr-architecture.html`.
