# Architecture Decision Records — and how each one is checked

Every ADR here resolves to a check the platform runs: at admission (kyverno), statically (the pod spec, a kubescape scan), at runtime (the eBPF sensor comparing a container with its tier profile) or on the wire (the Pixie tracer). The check is declared next to the decision in `compliance/adrs.yaml`; the engine evaluates it and reports, per ADR:

| status | meaning |
|---|---|
| `VIOLATED` | at least one counted finding: the observed event, the decision it broke, the fix |
| `COMPLIANT` | every required evidence item was examined and is clean — the proof says what was examined |
| `NOT_OBSERVED` | evidence missing: pods younger than the warm-up, no traffic driven, no scan supplied, a peer that cannot be attributed |

**No observation, no finding — and no observation, no pass.** A finding carries the event that produced it; a pass carries what was examined.

## How to read an ADR

Every ADR has the same sections: Decision · Why · How it is checked · What a violation looks like · How to fix · Reproduce without the tooling · Mechanical mapping.

*How it is checked* lists the evidence that must be present for `COMPLIANT`; if any item is missing the status is `NOT_OBSERVED` and the proof names it. *What a violation looks like* lists the predicates; every event matching one becomes a finding carrying the observed event, the decision it broke and the fix. Events the engine discounts (table below) stay in the report as notes with `counted=false` and never make an ADR `VIOLATED`. Rule and control identifiers appear only in each ADR's mapping table and its reproduce commands.

## The enforcement points

| point | when | mechanism | what it sees |
|---|---|---|---|
| admission | before the pod exists | kyverno mutate/validate | the manifest: tier label, profile binding, pins, ports, envelope |
| static | any time | the pod spec; `kubescape scan` controls | what was declared |
| runtime | while the container runs | node-agent + the tier ContainerProfile (SBoB) | processes, files, DNS, capabilities, network edges the profile does not declare |
| wire | while traffic flows | Pixie protocol tracers | the request itself: source, destination, port, path, encrypted or not |

## Preconditions for a verdict

* every pod carries `app.kubernetes.io/tier` and `kubescape.io/user-defined-profile` naming a profile that exists in its namespace (an unbound pod is unwatched)
* the tier profile declares the edges the architecture prescribes by label selector — otherwise allowed traffic alerts and the platform, not the application, owns the finding
* pods are older than the warm-up (210 s) before network rules are judged
* the application was driven over its prescribed edges (`compliance/drive.py`) — an unexercised edge cannot be COMPLIANT
* a kubescape scan is supplied for the static controls, or those ADRs stay NOT_OBSERVED

## The decision set

| ADR | summary | decision | enforced by |
|---|---|---|---|
| [0001](0001-strict-tier-layering.md) | Strict tier layering | Tiers are strictly layered; the presentation tier never reaches the data tier | sbob.egress, sbob.ingress, netpol |
| [0002](0002-data-tier-makes-no-outbound-calls.md) | Data tier makes no outbound calls | The data tier never initiates outbound connections | sbob.egress, netpol |
| [0003](0003-only-the-backend-holds-cluster-credentials.md) | Only the backend holds cluster credentials | Only the backend tier holds cluster credentials | sbob.opens, kyverno.validate |
| [0004](0004-images-immutable-at-runtime.md) | Images immutable at runtime | Images are immutable at runtime; nothing is installed after build | sbob.execs, sbob.dns, sbob.egress |
| [0005](0005-every-workload-declares-its-tier.md) | Every workload declares its tier | Every workload declares its tier; an undeclared one is quarantined | kyverno.mutate, clone-tier-sbobs |
| [0006](0006-run-as-non-root.md) | Run as non-root | Workloads run as non-root | kyverno.validate, sbob.capabilities |
| [0007](0007-detection-cannot-be-switched-off-by-a-profile.md) | Detection cannot be switched off by a profile | A profile may not wildcard above a path another rule protects | sbob.authoring |
| [0008](0008-frontend-serves-presentation-only.md) | Frontend serves presentation only | The presentation tier serves presentation only | content-probe |
| [0009](0009-tier-declared-never-guessed.md) | Tier declared, never guessed | A tier is declared, never guessed | kyverno.mutate |
| [0010](0010-requests-authenticated-by-the-platform-idp.md) | Requests authenticated by the platform IdP | Every backend request is authenticated by the platform identity provider | app-code, idp-client |
| [0011](0011-no-plaintext-on-the-wire.md) | No plaintext on the wire | No plaintext on the wire | platform-ingress, cert-manager, app-config |
| [0012](0012-metrics-on-a-dedicated-port.md) | Metrics on a dedicated port | Metrics are served on a dedicated port, scraped only by the platform | kyverno.validate, netpol |
| [0013](0013-resources-probes-and-security-context-declared.md) | Resources, probes and security context declared | Every workload declares its envelope: resources, probes, security context | kyverno.validate |
| [0014](0014-images-pinned-by-digest.md) | Images pinned by digest | Images are pinned by digest, signed; no latest | kyverno.validate, cosign |
| [0015](0015-ingress-belongs-to-the-platform.md) | Ingress belongs to the platform | Ingress is the platform's; a workload opens nothing itself | kyverno.validate, netpol |

## Prescribed edges

Traffic on these edges is never a violation of a tier ADR. A profile that alerts on one has a gap: that is a violation of ADR-0005 owned by the platform (`owner=platform`), because allowed traffic alerting means the profile was not declared as the architecture prescribes.

```
frontend -> backend
backend -> database
backend -> middleware
middleware -> database
backend -> backend
database -> database
backend -> identity provider (ns:zitadel on this platform)
every tier -> DNS
```

## Discounts

| name | what | effect |
|---|---|---|
| kubelet_probe | kubelet probe from the node's address on a port this pod declares as a probe target; the tier profile does not list it (platform/bobctl) | counted=false, owner=platform |
| evaluator / evaluator_wire | the evaluator's own request | counted=false, owner=application |
| departed_peer | the peer is not a live pod and pods of this namespace departed in the window (rollout); cannot be attributed | NOT_OBSERVED (cannot be attributed) |
| exec_started | process started by exec (kubelet exec probe or kubectl exec), not by the image; use tcpSocket/httpGet probes | counted=false, owner=application |
| tracer_parent | parent is the Pixie tracer; not the application's behaviour | counted=false, owner=application |

## Producing a verdict

```bash
export ADR_CH=http://ingest_writer:changeme-ingest@<clickhouse>:8123
./harness/loop.sh <N> <namespace> <manifest>      # apply, wait for warm-up, drive, scan, evaluate, write forensic_db.adr_findings
python3 compliance/adr_kpi.py <namespace> --since <epoch> --scan /tmp/AllControls-<namespace>.json --out kpi.json
python3 compliance/adr_mcp.py                       # the same evaluator as an MCP server for the coding agent
```

*Generated by `compliance/adr_docs.py`.*
