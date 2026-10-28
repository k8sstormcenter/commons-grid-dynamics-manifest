#!/usr/bin/env python3
"""
MCP server (stdio, JSON-RPC) that advises a coding agent on ADR compliance from the
evidence in ClickHouse. Wraps adr_kpi.evaluate — one evaluator for the kpi.json the
Pixie UI shows and for what the agent is told.

Tools
  adr_compliance   namespace, since_minutes  -> per-ADR status (the kpi.json summary)
  adr_violations   namespace, adr?, since_minutes -> findings: what was observed, which
                   decision it broke, the fix, and the CH evidence reference
  adr_explain      adr -> the decision text from the ADR file
  adr_architecture namespace -> is the workload what its tier says? verdict + reasons +
                   restructuring advice (split tiers, data tier, authN, pin, non-root)
  adr_recheck      namespace, since_epoch -> compliance for rows after a redeploy
                   (the fix-and-verify loop: pass the time you re-applied)

Register:  {"mcpServers":{"adr":{"command":"python3","args":["<checkout>/compliance/adr_mcp.py"],"env":{"ADR_CH":"http://ingest_writer:changeme-ingest@<clickhouse>:8123"}}}}
"""
import glob, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adr_kpi, adr_arch

SCAN = os.environ.get("ADR_SCAN_DIR", "/tmp")  # scan.sh writes /tmp/AllControls-<ns>.json


def scan_for(ns):
    p = os.path.join(SCAN, f"AllControls-{ns}.json")
    return p if os.path.exists(p) else None

TOOLS = [
    {"name": "adr_compliance",
     "description": "Is the namespace compliant with the platform's ADRs right now? Evidence is "
                    "node-agent runtime detections stored in ClickHouse, filtered to live pods.",
     "inputSchema": {"type": "object", "required": ["namespace"], "properties": {
         "namespace": {"type": "string"},
         "since_minutes": {"type": "integer", "default": 60}}}},
    {"name": "adr_violations",
     "description": "The violations with their evidence and the fix. Act on corroborated findings "
                    "first; each carries the observed event (container, peer, port, process).",
     "inputSchema": {"type": "object", "required": ["namespace"], "properties": {
         "namespace": {"type": "string"},
         "adr": {"type": "string", "description": "e.g. ADR-0001; omit for all"},
         "since_minutes": {"type": "integer", "default": 60}}}},
    {"name": "adr_explain",
     "description": "The decision text of one ADR: context, decision, how it is verified.",
     "inputSchema": {"type": "object", "required": ["adr"], "properties": {"adr": {"type": "string"}}}},
    {"name": "adr_architecture",
     "description": "Is each workload what its tier label claims? Combines how admission classified it "
                    "(image match vs port guess), what it serves (code size, solvers, datasets, state, "
                    "backend calls, auth markers), what it did (ClickHouse) and the manifest scan. Returns "
                    "a verdict with reasons and concrete restructuring advice (split tiers, data tier, authN, pin, non-root).",
     "inputSchema": {"type": "object", "required": ["namespace"], "properties": {
         "namespace": {"type": "string"}, "since_minutes": {"type": "integer", "default": 60}}}},
    {"name": "adr_recheck",
     "description": "Re-evaluate using only evidence after since_epoch (the moment you redeployed). "
                    "COMPLIANT here means the sensor watched the new pods and saw no violation; "
                    "NOT_OBSERVED means drive the workload and call again.",
     "inputSchema": {"type": "object", "required": ["namespace", "since_epoch"], "properties": {
         "namespace": {"type": "string"}, "since_epoch": {"type": "integer"}}}},
]


def compact(report, adr=None):
    out = []
    for x in report["adrs"]:
        if adr and x["id"] != adr:
            continue
        for f in x["findings"]:
            out.append({k: f.get(k) for k in ("adr", "source", "decision_broken", "observed", "fix", "rule",
                                               "workload", "container", "tier", "process", "control",
                                               "affected", "path", "value", "agent_can_apply",
                                               "corroborated_by", "confidence", "evidence", "owner", "cause", "counted", "note") if f.get(k) is not None})
    return out


def explain(adr):
    n = adr.split("-")[-1]
    hits = glob.glob(os.path.join(adr_kpi.RIG, "adr", f"{n}-*.md"))
    if not hits:
        return f"no ADR file for {adr}"
    txt = open(hits[0]).read()
    # decision + verification, not the whole essay
    keep = re.split(r"^## ", txt, flags=re.M)
    want = [s for s in keep if s.startswith(("Decision", "Verified by", "Evidence emitted")) or keep.index(s) == 0]
    return "\n## ".join(want)


def call(name, args):
    ns = args.get("namespace")
    now = int(time.time())
    if name == "adr_architecture":
        r = adr_kpi.evaluate(ns, now - 60 * int(args.get("since_minutes", 60)), now, scan_for(ns))
        return {"namespace": ns, "workloads": r["architecture"], "adr_summary": r["kpis"]}
    if name == "adr_compliance":
        r = adr_kpi.evaluate(ns, now - 60 * int(args.get("since_minutes", 60)), now, scan_for(ns))
        return {"namespace": ns, "summary": r["summary"], "kpis": r["kpis"],
                "broken_before_anything_else": r["broken_before_anything_else"],
                "source": r["source"]}
    if name == "adr_violations":
        r = adr_kpi.evaluate(ns, now - 60 * int(args.get("since_minutes", 60)), now, scan_for(ns))
        return {"namespace": ns, "violations": compact(r, args.get("adr")),
                "broken_before_anything_else": r["broken_before_anything_else"]}
    if name == "adr_explain":
        return {"adr": args["adr"], "text": explain(args["adr"])}
    if name == "adr_recheck":
        r = adr_kpi.evaluate(ns, int(args["since_epoch"]), now, scan_for(ns))
        return {"namespace": ns, "since_epoch": args["since_epoch"], "summary": r["summary"],
                "kpis": r["kpis"], "violations": compact(r)}
    raise ValueError(f"unknown tool {name}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        m, i = req.get("method"), req.get("id")
        if m == "initialize":
            res = {"protocolVersion": req["params"].get("protocolVersion", "2025-06-18"),
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "adr-compliance", "version": "0.1"}}
        elif m == "tools/list":
            res = {"tools": TOOLS}
        elif m == "tools/call":
            try:
                res = {"content": [{"type": "text", "text": json.dumps(
                    call(req["params"]["name"], req["params"].get("arguments", {})), indent=1)}]}
            except Exception as e:
                res = {"content": [{"type": "text", "text": str(e)}], "isError": True}
        elif m == "ping":
            res = {}
        elif i is None:
            continue  # notification
        else:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i,
                                         "error": {"code": -32601, "message": m}}) + "\n")
            sys.stdout.flush()
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": res}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
