#!/usr/bin/env python3
"""
MCP server (stdio, JSON-RPC) that advises a coding agent on ADR compliance from the evidence
in ClickHouse, the cluster objects and the kubescape scan. One evaluator (engine.py over
adrs.yaml) for the kpi.json the harness writes, for what the agent is told, and for the
forensic_db.adr_findings rows Pixie shows.

Tools
  adr_compliance   namespace, since_minutes       -> per-ADR status + proof
  adr_violations   namespace, adr?, since_minutes -> findings: what was observed, which decision it
                                                    broke, the fix, counted/discounted with the reason
  adr_explain      adr                            -> the decision text from the ADR file + its checks (adrs.yaml)
  adr_architecture namespace                      -> per workload: tier, how it was assigned, what it serves, its findings
  adr_recheck      namespace, since_epoch         -> compliance for evidence after a redeploy

Every evaluating call writes its rows to forensic_db.adr_findings (never fails the call;
the reply carries persisted_rows). Env: ADR_CH (ClickHouse HTTP DSN), ADR_SCAN_DIR,
ADR_ITERATION, ADR_PX_HOST, ADR_FINDINGS_TABLE.
"""
import datetime, glob, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine, evidence

SCAN = os.environ.get("ADR_SCAN_DIR", "/tmp")
PX_HOST = os.environ.get("ADR_PX_HOST", "edge4-server")   # Pixie's CH source filters hostname = PEM node: one value, read once
FINDINGS_TABLE = os.environ.get("ADR_FINDINGS_TABLE", "forensic_db.adr_findings")
SPEC = engine.load_spec()
SUMMARY = {a["id"]: a["summary"] for a in SPEC["adrs"]}


def scan_for(ns):
    p = os.path.join(SCAN, f"AllControls-{ns}.json")
    return p if os.path.exists(p) else None


TOOLS = [
    {"name": "adr_compliance",
     "description": "Is the namespace compliant with the platform's ADRs right now? Per ADR: VIOLATED (a counted "
                    "finding), COMPLIANT (the required evidence was examined and is clean — see proof) or NOT_OBSERVED "
                    "(evidence missing: drive the workload, wait for warm-up, supply a scan).",
     "inputSchema": {"type": "object", "required": ["namespace"], "properties": {
         "namespace": {"type": "string"}, "since_minutes": {"type": "integer", "default": 60}}}},
    {"name": "adr_violations",
     "description": "The findings with evidence and fix. counted=false rows are discounted (kubelet probe, evaluator, "
                    "prescribed edge the profile lacks, departed pod, exec-started) with the reason in note; fix those "
                    "owned by 'application' first.",
     "inputSchema": {"type": "object", "required": ["namespace"], "properties": {
         "namespace": {"type": "string"}, "adr": {"type": "string", "description": "e.g. ADR-0001; omit for all"},
         "since_minutes": {"type": "integer", "default": 60}, "include_discounted": {"type": "boolean", "default": False}}}},
    {"name": "adr_explain",
     "description": "One ADR: decision text, and exactly how it is checked (the adrs.yaml predicates).",
     "inputSchema": {"type": "object", "required": ["adr"], "properties": {"adr": {"type": "string"}}}},
    {"name": "adr_architecture",
     "description": "Per workload: tier and how admission assigned it (declared / image / port / unclassified), profile "
                    "binding and age, what a page-serving pod serves (code size, solvers, datasets, api paths, auth "
                    "markers), and its findings by ADR.",
     "inputSchema": {"type": "object", "required": ["namespace"], "properties": {
         "namespace": {"type": "string"}, "since_minutes": {"type": "integer", "default": 60}}}},
    {"name": "adr_recheck",
     "description": "Re-evaluate using only evidence after since_epoch (the moment you redeployed). NOT_OBSERVED means: "
                    "pods younger than the warm-up, or no traffic driven — drive the workload and call again.",
     "inputSchema": {"type": "object", "required": ["namespace", "since_epoch"], "properties": {
         "namespace": {"type": "string"}, "since_epoch": {"type": "integer"}}}},
]


# ---------------------------------------------------------------- forensic_db.adr_findings

def findings_rows(report, tool, iteration=None):
    """One row per finding (counted or discounted, with its note), one row per ADR without findings;
    every row carries the ADR's proof. Accepts adr-kpi/v1 reports too (older artefacts)."""
    fmt = lambda t: t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    now = fmt(datetime.datetime.now(datetime.timezone.utc))
    src, cov = report.get("source", {}), report.get("summary", {}).get("coverage", {})
    fallback = (f"window {src.get('window', {}).get('from')}-{src.get('window', {}).get('to')}: {src.get('rows')} node-agent detections "
                f"(rules {src.get('rules_seen')}); {cov.get('governed')}/{cov.get('pods')} pod(s) governed; {src.get('static')}")
    it = int(os.environ.get("ADR_ITERATION", "0")) if iteration is None else iteration
    out = []
    for a in report["adrs"]:
        status = a["status"]
        if report.get("schema") != "adr-kpi/v2":  # v1: a rollover-peer discount was COMPLIANT; it is NOT_OBSERVED
            for f in a["findings"]:
                if "is not a live pod" in (f.get("note") or "") and f.get("counted") is False:
                    f["unattributed"] = True
            if status == "COMPLIANT" and any(f.get("unattributed") for f in a["findings"]):
                status = "NOT_OBSERVED"
        base = {"event_time": now, "hostname": PX_HOST, "kpi_time": fmt(datetime.datetime.fromisoformat(report["generated_at"])),
                "cluster": report.get("cluster") or "", "namespace": report["namespace"], "iteration": it, "tool": tool,
                "adr": a["id"], "adr_summary": SUMMARY.get(a["id"], a["title"]), "title": a["title"], "status": status,
                "violations": a["violations"], "proof": a.get("proof") or fallback}
        for f in a["findings"] or [{}]:
            note = f.get("note") or " — ".join(x for x in (f.get("cause"),) if x) if f else (a.get("note") or "")
            out.append({**base, "counted": bool(f) and f.get("counted", True), "note": note or "",
                        "owner": f.get("owner", "") if f else "",
                        **{k: str(f.get(k) or "") for k in ("source", "rule", "workload", "decision_broken", "observed", "fix")}})
    return out


def persist(report, tool, iteration=None):
    rows = findings_rows(report, tool, iteration)
    try:
        evidence.ch(f"INSERT INTO {FINDINGS_TABLE} FORMAT JSONEachRow\n" + "\n".join(json.dumps(r) for r in rows))
        return len(rows)
    except Exception as e:
        return f"not persisted: {e}"


# ---------------------------------------------------------------- tools

def compact(report, adr=None, include_discounted=False):
    out = []
    for x in report["adrs"]:
        if adr and x["id"] != adr:
            continue
        for f in x["findings"]:
            if not f["counted"] and not include_discounted:
                continue
            out.append({k: f.get(k) for k in ("adr", "source", "evidence_class", "workload", "container", "tier", "rule",
                                               "decision_broken", "observed", "fix", "owner", "counted", "note", "evidence")
                        if f.get(k) not in (None, "", [])})
    return out


def explain(adr):
    n = adr.split("-")[-1]
    hits = glob.glob(os.path.join(evidence.RIG, "adr", f"{n}-*.md"))
    txt = open(hits[0]).read() if hits else f"no ADR file for {adr}"
    keep = re.split(r"^## ", txt, flags=re.M)
    want = [s for s in keep if keep.index(s) == 0 or s.startswith(("Decision", "Why", "How it is checked", "Verified by"))]
    spec = next((a for a in SPEC["adrs"] if a["id"] == adr), None)
    return {"adr": adr, "text": "\n## ".join(want), "checks": spec}


TRAFFIC_ASK = {
    "why": "runtime ADRs are judged on traffic; without it they stay NOT_OBSERVED and the proof names the silent edge",
    "iteration_0": "turn the functional/integration test-suite into load/k6.js (template harness/load/k6-example.js): every "
                   "request carries User-Agent adr-driver/k6 and X-Test-Case: <use case>; every use case appears at least once; "
                   "everything goes through the platform ingress host (BASE_URL), never a pod IP or NodePort",
    "iteration_1_and_later": "ship deploy-loadgen.yaml: a Deployment (grafana/k6, the script in a ConfigMap) in namespace "
                             "<app>-load that runs the same suite continuously against the ingress host",
    "runtime_tests": "keep adding functional use cases to the suite, one X-Test-Case per use case; the proof reports per "
                     "prescribed edge which use cases exercised it",
    "harness": "harness/load.sh <ns> [seconds] picks deploy-loadgen.yaml, then load/k6.js, then the harness's own browser stand-in",
}


def traffic_view(r):
    src = r["source"]
    silent = [a["id"] for a in r["adrs"] if a["status"] == "NOT_OBSERVED" and any(p["source"] in ("wire", "coverage") for p in
              next((x for x in SPEC["adrs"] if x["id"] == a["id"]), {}).get("observed", []))]
    return {"wire_rows": src.get("wire_rows", 0), "test_cases_seen": src.get("test_cases", []),
            "not_observed_for_lack_of_traffic": silent, "ask": TRAFFIC_ASK}


def status_view(r):
    return [{"adr": a["id"], "summary": a["summary"], "status": a["status"], "violations": a["violations"], "proof": a["proof"]} for a in r["adrs"]]


def _call(name, args):
    ns = args.get("namespace")
    now = int(time.time())
    if name == "adr_explain":
        return explain(args["adr"]), None
    since = int(args["since_epoch"]) if name == "adr_recheck" else now - 60 * int(args.get("since_minutes", 60))
    r = engine.evaluate(ns, since, now, scan_for(ns))
    if name in ("adr_compliance", "adr_recheck"):
        return {"namespace": ns, "since_epoch": since, "summary": r["summary"], "adrs": status_view(r),
                "traffic": traffic_view(r),
                "broken_before_anything_else": r["broken_before_anything_else"], "source": r["source"]}, r
    if name == "adr_violations":
        return {"namespace": ns, "violations": compact(r, args.get("adr"), args.get("include_discounted", False)),
                "broken_before_anything_else": r["broken_before_anything_else"]}, r
    if name == "adr_architecture":
        by_pod = {}
        for a in r["adrs"]:
            for f in a["findings"]:
                by_pod.setdefault(f["workload"], []).append({"adr": a["id"], "counted": f["counted"], "decision_broken": f["decision_broken"]})
        return {"namespace": ns, "workloads": [{**w, "content": next((c for c in r["content"] if c["pod"] == w["pod"]), None),
                                               "findings": by_pod.get(w["workload"], []) + by_pod.get(w["pod"], [])} for w in r["workloads"]],
                "adr_summary": r["kpis"]}, r
    raise ValueError(f"unknown tool {name}")


def call(name, args):
    res, report = _call(name, args)
    if report is not None:
        res["persisted_rows"] = persist(report, name)
    return res


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        m, i = req.get("method"), req.get("id")
        if m == "initialize":
            res = {"protocolVersion": req["params"].get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}},
                   "serverInfo": {"name": "adr-compliance", "version": "0.2"}}
        elif m == "tools/list":
            res = {"tools": TOOLS}
        elif m == "tools/call":
            try:
                res = {"content": [{"type": "text", "text": json.dumps(call(req["params"]["name"], req["params"].get("arguments", {})), indent=1, default=str)}]}
            except Exception as e:
                res = {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}
        elif m == "ping":
            res = {}
        elif i is None:
            continue
        else:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": m}}) + "\n"); sys.stdout.flush()
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": res}) + "\n"); sys.stdout.flush()


if __name__ == "__main__":
    main()
