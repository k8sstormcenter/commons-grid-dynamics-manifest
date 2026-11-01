# ADR compliance MCP

Stdio MCP server that tells a coding agent whether a namespace complies with the ADRs in
`../adr`, from the node-agent evidence the SOC stack stores in ClickHouse. The same
evaluator produces the `kpi.json` the Pixie UI shows.

Tools: `adr_compliance`, `adr_violations`, `adr_explain`, `adr_architecture`, `adr_recheck`.

Environment

| var | meaning |
|---|---|
| `ADR_CH` | ClickHouse HTTP DSN, `http://ingest_writer:changeme-ingest@<host>:8123` (required) |
| `ADR_RIG` | directory holding `adr/` (default: `..`) |
| `ADR_SCAN_DIR` | where `scan.sh` writes `AllControls-<ns>.json` (default `/tmp`) |

Register

```json
{"mcpServers":{"adr":{"command":"python3",
  "args":["<checkout>/compliance/adr_mcp.py"],
  "env":{"ADR_CH":"http://ingest_writer:changeme-ingest@<clickhouse>:8123"}}}}
```

Needs `kubectl` access to the target cluster (live pods, the `idp-client` secret for the
ADR-0010 probes) and PyYAML.

Files

| file | role |
|---|---|
| `adr_kpi.py` | `python3 adr_kpi.py <ns> --since <epoch> [--scan AllControls-<ns>.json] --out kpi.json` — runtime evidence (ClickHouse `kubescape_logs`, live pods only) + static scan → per-ADR status, findings with fix, coverage |
| `adr_checks.py` | live probes: ADR-0010 (401 / garbage token / IdP-minted token), TLS, ports, NetworkPolicies |
| `adr_arch.py` | is the workload what its tier says? classification from image/ports/kyverno policy, restructuring advice |
| `adr_mcp.py` | the MCP server over the same evaluator |
| `review.py` | the ADR map and the folding rules the evaluator imports (`ADR_MAP`, `runtime_findings`, `compliance_findings`) |
| `scan.sh`, `scan-failures.py` | kubescape CLI scan of a namespace → `/tmp/AllControls-<ns>.json`, and a reader for it |
