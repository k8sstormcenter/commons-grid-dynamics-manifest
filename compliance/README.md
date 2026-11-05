# ADR compliance — the generic evaluator

An ADR is a constraint; this directory turns it into a verdict with evidence. Nothing per-ADR
lives in Python: `adrs.yaml` declares every ADR's checks, `engine.py` evaluates them over the
events `evidence.py` collects, and `adr_docs.py` renders the ADR documents from the same YAML
(plus the prose in `adr_text.yaml`), so text and check cannot drift.

```
adrs.yaml + adr_text.yaml ──adr_docs.py──► ../adr/NNNN-*.md, ../adr/README.md
adrs.yaml ──engine.py──► per-ADR status + findings + proof
                 ▲
     evidence.py │ events from: ClickHouse (kubescape_logs, http/pgsql/conn_stats), kubectl
                 │ (pods, specs, svc, ingress, netpol, ContainerProfiles),
                 │ kubescape scan JSON, the evaluator's HTTP probes, the page a frontend serves
adr_kpi.py   the CLI the harness runs  → artefacts/kpi-<ns>-iterN.json
adr_mcp.py   the same evaluator as an MCP server; every call also writes forensic_db.adr_findings
kpi_to_ch.py load an existing kpi json into forensic_db.adr_findings (v1 and v2 files)
drive.py     browser-shaped traffic over the prescribed edges before judging
scan.sh      kubescape CLI scan of a namespace → /tmp/AllControls-<ns>.json (scan-failures.py reads it)
```

## Declaring an ADR

```yaml
- id: ADR-0002
  summary: Data tier makes no outbound calls        # the short label dashboards show
  title: The data tier never initiates outbound connections
  enforced_by: [sbob.egress, netpol]                 # what the platform writes to enforce it
  violated:                                          # every matching event is a finding
    - source: runtime
      rule: R0011
      tier: [database, middleware]
      peer_kind: {not: [dns]}
      edge_prescribed: false
      broken: the data tier initiated an outbound connection
      fix: remove the outbound call; if a database genuinely needs egress it belongs in a job labelled tier=backend
  observed:                                          # ALL must hold for COMPLIANT, else NOT_OBSERVED
    - source: coverage
      tiers: [database, middleware]
      what: data-tier pods governed and past warm-up
```

Filters: `field: value`, `field: [a, b]`, `field: {not: [...]}`, `{gt|ge|lt|le: n}`, `{regex: ..}`,
`{empty: true|false}`. `show:` adds fields to the finding's `observed` text; `group_by:` adds a
breakdown to the proof line; `counted: false` makes a predicate informational; `owner: platform`
marks it as the platform's to fix.

Status, one rule for all ADRs: a counted violation → `VIOLATED`; a match that cannot be attributed
(a peer that departed in a rollout) → `NOT_OBSERVED`; every `observed` predicate satisfied →
`COMPLIANT`; otherwise `NOT_OBSERVED`, and the proof names the unmet predicate.

Top-level `topology:` lists the edges the architecture prescribes (never a tier violation; a
profile that alerts on one has a gap, reported under ADR-0005 as the platform's). `discounts:`
lists the facts that take an event out of the count — kubelet probes, the evaluator's own
requests, prescribed edges, departed peers, exec-started processes, the tracer — each with the
note the finding carries.

## Event fields (what a predicate can filter on)

| source | one event per | fields |
|---|---|---|
| `pod` | running pod | pod, workload, tier, profile, bound, ip, node, age_s, warm, declared_known, declared_tier, assigned_by (declared/image/port/unclassified/none), image_known, probe_ports |
| `spec` | container | image, pinned, tag, mutable_tag, pull_policy, running_digest, port_names, has_metrics_port, host_ports, host_network, run_as_non_root, run_as_user, allow_priv_esc, read_only_root, caps_drop_all, seccomp, automount_sa, has_liveness, has_readiness, exec_probe, has_requests, has_limits |
| `svc` / `ingress` | object | type, ports, node_ports, plaintext_ports, exposed / tls, hosts |
| `netpol` | policy, plus one `scope: namespace` row | selects_all, default_deny_ingress, default_deny_egress, default_deny, policies |
| `profile` | ContainerProfile (GET each) | name, tier, opens, execs, wildcards, wildcard_paths, token_paths, token_concrete, has_egress, has_ingress, signed |
| `runtime` | distinct detection on a live pod | rule, severity, pod, workload, container, tier, node, profile, image, image_digest, process, pcomm, cmdline, message, count, pod_age_s, direction, peer_ip, peer_port, peer_kind (pod/node/evaluator/external/departed/dns/unknown), peer_pod, peer_tier (tier or `ns:<namespace>`), edge, edge_prescribed, kubelet_probe, domain, path, exec, capability |
| `wire` | aggregated flow | proto (http/pgsql/conn), role, src_pod, src_tier, dst_pod, dst_tier, remote_ip, remote_kind, remote_ns, port, encrypted, method, path, status, count, kubelet_probe, health_path |
| `scan` | failed control × fix path | control, name, path, severity, resources, value, action, agent_can_apply |
| `probe` | request the evaluator made | workload, tier, url, path, auth (none/garbage/valid), status, via, route, reachable |
| `content` | page-serving pod | serves_page, bytes, js_bytes, js_kb, scripts, functions, api_paths, n_api_paths, backend_calls, auth_markers, client_state, marker_* |

Runtime events are filtered to pods that exist now and to detections that postdate the pod
(the fix-and-verify loop must not see the previous revision's evidence); identical detections
are collapsed with a count. Peers are resolved against every pod in the cluster.

## Environment

| var | meaning |
|---|---|
| `ADR_CH` | ClickHouse HTTP DSN, `http://ingest_writer:changeme-ingest@<host>:8123` (required for runtime/wire evidence and for writing `adr_findings`) |
| `ADR_RIG` | directory holding `adr/` and `kyverno/` (default: `..`) |
| `ADR_SCAN_DIR` | where `scan.sh` writes `AllControls-<ns>.json` (default `/tmp`) |
| `ADR_ITERATION` | iteration number written to `adr_findings` (loop.sh sets it) |
| `ADR_PX_HOST` | `hostname` value on `adr_findings` rows (Pixie's ClickHouse source filters on it; default `edge4-server`) |
| `ADR_SPEC` | alternative `adrs.yaml` |

## MCP

```json
{"mcpServers":{"adr":{"command":"python3","args":["<checkout>/compliance/adr_mcp.py"],
  "env":{"ADR_CH":"http://ingest_writer:changeme-ingest@<clickhouse>:8123"}}}}
```

Tools: `adr_compliance`, `adr_violations` (`include_discounted` shows the notes), `adr_explain`
(decision text + the YAML checks), `adr_architecture` (per workload: tier, how it was assigned,
what it serves, its findings), `adr_recheck` (evidence after a redeploy). Needs `kubectl` access
and the `idp-client` secret in the namespace for the platform-token probe; PyYAML.

## The table Pixie shows

`forensic_db.adr_findings` (DDL in `../sql/adr_findings.sql`): one row per finding and one per
ADR without findings — `status`, `counted`, `note`, `owner`, `proof`, `decision_broken`,
`observed`, `fix`, `iteration`, `tool`. `../pxl/adr_findings.pxl` reads the last 30 minutes.
