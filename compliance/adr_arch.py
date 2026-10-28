#!/usr/bin/env python3
"""
Architecture feedback: is this workload what its tier label says it is?

Admission can only read the manifest. assign-workload-tier matched nothing in the
image name and fell back to containerPort 80 -> tier=frontend. That is a guess, and
the runtime + content evidence can contradict it. This module gathers that evidence
and turns it into advice for the coder's agent: split, add a data tier, add authN,
pin, drop root.

Evidence sources, all observable:
  classification   how kyverno arrived at the tier (image regex vs port fallback)
  content          what the pod actually serves on its port (size, inline code,
                   solvers, datasets, state, backend calls, auth markers)
  behaviour        what the pod did (CH rows) vs what its profile declares
  manifest         kubescape scan controls (optional)
"""
import json, os, re, subprocess, urllib.request
import yaml

UA = "adr-evaluator/1"  # same tag as adr_checks: the wire check drops the evaluator's own requests


import ssl
_NOVERIFY = ssl.create_default_context(); _NOVERIFY.check_hostname = False; _NOVERIFY.verify_mode = ssl.CERT_NONE


def _get(url):
    # the evaluator reads content, it is not a client of the app: it does not verify the
    # serving certificate (that is ADR-0011's job, judged from the wire)
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=10,
                                  context=_NOVERIFY if url.startswith("https") else None).read().decode("utf-8", "replace")


def scheme_of(pod, port):
    """https when the pod itself says so: containerPort named https/tls, or an httpGet probe with scheme HTTPS on that port."""
    for c in pod["spec"]["containers"]:
        for pt in c.get("ports", []) or []:
            if pt.get("containerPort") == port and (pt.get("name") or "").lower() in ("https", "tls", "ssl"):
                return "https"
        for k in ("livenessProbe", "readinessProbe", "startupProbe"):
            hg = (c.get(k) or {}).get("httpGet") or {}
            if hg.get("port") == port and hg.get("scheme") == "HTTPS":
                return "https"
    return "https" if port in (443, 8443) else "http"

RIG = os.environ.get("ADR_RIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# Markers inside served JS. Each is a reason, not a score.
CODE_MARKERS = {
    "numeric_solvers": r"\b(rk4|dp45|runge|jacobian|eigenvalues?|newton|solveLinear|integrate|monte ?carlo|ensemble)\b",
    "statistics":      r"\b(gauss|poisson|gamma|lognormal|binom|gini)\b",
    "simulation":      r"\b(simulate|simulation|genWorld|sweep2D|modelA|modelB)\b",
    "money":           r"(€|EUR|\bprice\b|\bcost\b|\bfine\b|\bdues\b|tokenomics)",
    "client_state":    r"\b(localStorage|sessionStorage|indexedDB)\b",
    "backend_calls":   r"\b(fetch\(|XMLHttpRequest|WebSocket|EventSource|axios)\b",
    "auth":            r"\b(Authorization|Bearer|login|signin|oauth|openid|jwt|csrf)\b",
}


def kyverno_rules():
    """The image regexes assign-workload-tier uses, read from the rig so they never drift."""
    out = []
    for f in sorted(os.listdir(os.path.join(RIG, "kyverno"))):
        if not f.startswith("02"):
            continue
        for doc in yaml.safe_load_all(open(os.path.join(RIG, "kyverno", f))):
            for r in (doc or {}).get("spec", {}).get("rules", []):
                name = r.get("name", "")
                for pc in (r.get("preconditions", {}) or {}).get("all", []):
                    m = re.search(r"regex_match\('([^']+)',\s*imgs\)", str(pc.get("key", "")))
                    if m:
                        out.append((name, m.group(1)))
    return out


def classification(pod):
    imgs = ",".join(c["image"] for c in pod["spec"]["containers"])
    ports = [p.get("containerPort") for c in pod["spec"]["containers"] for p in c.get("ports", []) or []]
    tier = pod["metadata"].get("labels", {}).get("app.kubernetes.io/tier")
    by_image = [name for name, rx in kyverno_rules() if re.match(rx, imgs)]
    return {
        "tier": tier, "images": imgs.split(","), "ports": ports,
        "matched_by": ("image: " + by_image[0]) if by_image else ("port fallback" if tier and tier != "unclassified" else "none"),
        "custom_image": not by_image,
    }


def content(ip, port=80, scheme="http"):
    try:
        body = _get(f"{scheme}://{ip}:{port}/")
    except Exception as e:
        return {"error": str(e)}
    scripts = "".join(re.findall(r"<script[^>]*>(.*?)</script>", body, re.S))
    ext = re.findall(r'<script[^>]+src="([^"]+)"', body)
    # what the browser executes is inline + every same-origin script the shell loads;
    # moving the engine from <script> into engine.js changes nothing about the tier
    loaded = {}
    for src in ext:
        if "://" in src:
            continue
        try:
            loaded[src] = _get(f"{scheme}://{ip}:{port}/{src.lstrip('/')}")
        except Exception as e:
            loaded[src] = ""
    scripts += "".join(loaded.values())
    markers = {k: len(re.findall(rx, scripts)) for k, rx in CODE_MARKERS.items()}
    # A solver the shell *defines* is computation; a solver the shell *names* (a route
    # "/api/ode/rk4", a tab label) is a call. Only definitions count.
    fns = re.findall(r"function\s+([A-Za-z_]\w*)", scripts)
    fns += re.findall(r"(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_]\w*\s*=>)", scripts)
    fns += re.findall(r"(?m)^\s*(?:async\s+)?([A-Za-z_]\w*)\s*\([^)]*\)\s*\{", scripts)
    vocab = re.compile("|".join(CODE_MARKERS[k] for k in ("numeric_solvers", "statistics", "simulation")), re.I)
    defined_solvers = []
    for f in sorted(set(fns)):
        if not vocab.search(f):
            continue
        # a wrapper whose body goes straight to the API is a call site, not a solver
        m = re.search(r"\b" + re.escape(f) + r"\s*(?:=\s*(?:async\s*)?)?\([^)]*\)\s*(?:=>\s*)?\{(.{0,160})", scripts, re.S)
        body = m.group(1) if m else ""
        if re.search(r"\b(fetch\(|API\.(?:get|post)|axios)\b", body):
            continue
        defined_solvers.append(f)
    api_paths = sorted({m for m in re.findall(r"['\"`](/api/[A-Za-z0-9_/.-]*)['\"`]", scripts)})
    datasets = re.findall(r"(?:const|let|var)\s+([A-Z][A-Z_]+)\s*=\s*\[\s*\{", scripts)
    title = re.search(r"<title>([^<]*)", body)
    return {
        "title": title.group(1).strip() if title else None,
        "bytes": len(body), "inline_js_bytes": len(scripts), "external_scripts": ext,
        "script_bytes": {k: len(v) for k, v in loaded.items()},
        "functions": len(set(fns)), "function_sample": fns[:12], "defined_solvers": defined_solvers,
        "datasets": datasets, "markers": markers, "api_paths": api_paths,
    }


def behaviour(ns, pod_name, rows):
    """rows: kubescape_logs rows for the namespace (adr_kpi.rows)."""
    mine = [r for r in rows if r["k8s"].get("podName") == pod_name]
    egress = [r for r in mine if r["RuleID"] == "R0011"]
    opens = sorted({(r["brm"].get("arguments") or {}).get("path") or r["message"].split(" to ")[-1]
                    for r in mine if r["RuleID"] == "R0002"})
    return {
        "rows": len(mine), "rules": sorted({r["RuleID"] for r in mine}),
        "egress_events": len(egress),
        "egress_peers": sorted({f"{(r['brm'].get('arguments') or {}).get('ip')}:{(r['brm'].get('arguments') or {}).get('port')}" for r in egress}),
        "unexpected_opens": opens[:10],
    }


def judge(cls, con, beh, scan_static):
    """Reasons first, verdict second. Every recommendation names the evidence it rests on.
    Content reasons apply to the tier that serves a page (frontend); runtime reasons to every tier."""
    reasons, recs = [], []
    tier = cls["tier"]
    serves_page = bool(con) and "error" not in con
    logic = con.get("markers", {}) if serves_page else {}
    heavy = serves_page and (con.get("inline_js_bytes", 0) > 50_000 or con.get("functions", 0) > 100)
    computes = serves_page and bool(con.get("defined_solvers"))
    has_data = serves_page and bool(con.get("datasets"))
    calls_backend = logic.get("backend_calls", 0) > 0 or beh["egress_events"] > 0
    no_backend = serves_page and not calls_backend
    no_auth = serves_page and logic.get("auth", 0) == 0
    client_state = serves_page and logic.get("client_state", 0) > 0
    solver_names = con.get("defined_solvers", []) if serves_page else []

    if cls["custom_image"]:
        reasons.append(f"tier={tier} came from the {cls['matched_by']} on port {cls['ports']}: "
                       f"the image {cls['images'][0]} matched no known component, so the tier is a guess")
    if computes:
        reasons.append(f"the served page executes {con['inline_js_bytes']//1024} KB of client code (inline + loaded scripts: "
                       f"{', '.join(con.get('external_scripts', [])) or 'none'}), {con['functions']} functions, "
                       f"including numerical solvers/simulation ({', '.join(solver_names)})")
    if has_data:
        reasons.append(f"business data is embedded in the page: datasets {con['datasets']}, "
                       f"{logic.get('money',0)} money/pricing references")
    if no_backend:
        reasons.append("no backend exists: zero fetch/XHR in the code, zero egress events from the pod, "
                       "and the tier-frontend profile declares no egress")
    if client_state:
        reasons.append("application state is kept in the browser (localStorage)")
    if no_auth:
        reasons.append("no authentication anywhere: no auth markers in the code, no Authorization handling")
    if beh["unexpected_opens"]:
        reasons.append(f"the container read files the tier-{tier} baseline does not declare (R0002): {beh['unexpected_opens'][:3]}")
    if beh["egress_peers"]:
        reasons.append(f"egress observed to {beh['egress_peers']}")

    monolith = heavy and computes and no_backend
    if monolith:
        verdict = "SINGLE_TIER_APPLICATION_IN_PRESENTATION_TIER"
    elif tier == "frontend" and (computes or has_data) and calls_backend:
        verdict = "COMPUTATION_IN_PRESENTATION_TIER"
    elif cls["custom_image"]:
        verdict = "TIER_GUESSED_FROM_PORT"
    else:
        verdict = "CONSISTENT_WITH_TIER"

    if monolith:
        recs.append({"what": "split into tiers", "how":
                     "keep nginx as the presentation tier serving only the shell (HTML/CSS/static JS); move the "
                     "simulation engine and solvers into a tier=backend service (python/node/go image) exposed on 8000/8080; "
                     "the presentation tier calls it over HTTP — that is the egress ADR-0001 expects"})
        recs.append({"what": "move the data out of the page", "how":
                     f"presets/packages/abuse tables ({', '.join(con['datasets'])}) belong in a tier=database store "
                     "(postgres/redis image so admission classifies it) read by the backend, not shipped to every browser"})
    elif verdict == "COMPUTATION_IN_PRESENTATION_TIER":
        recs.append({"what": "finish the split", "how":
                     f"the shell still ships the engine ({', '.join(solver_names[:8])}); every solver, integrator and "
                     "sweep belongs behind the API — the browser renders results, it does not compute them; "
                     "pricing/preset constants come from GET /api/constants, not from a script file"})
    if no_auth:
        recs.append({"what": "add authentication", "how":
                     "put authN on the backend API (OIDC/JWT bearer on every request); the frontend never holds "
                     "credentials (ADR-0003); unauthenticated requests get 401 — then the request trace carries the evidence"})
    if client_state:
        recs.append({"what": "server-side state", "how": "localStorage state cannot be audited or shared; persist runs via the backend into the data tier"})
    if cls["custom_image"]:
        recs.append({"what": "declare the tier explicitly", "how":
                     "set app.kubernetes.io/tier on each workload in the manifest; admission then validates instead of guessing, "
                     "and a custom image on port 80 no longer passes as a plain frontend"})
    for s in scan_static or []:
        if s.get("adr") in ("ADR-0004", "ADR-0006"):
            recs.append({"what": s["adr"] + " " + s["decision_broken"], "how": s["fix"]})
    return verdict, reasons, recs


def architecture(ns, rows, scan_static=None):
    pods = json.loads(subprocess.run(["kubectl", "-n", ns, "get", "pods", "-o", "json"],
                                     capture_output=True, text=True).stdout or "{}").get("items", [])
    out = []
    for p in pods:
        if p["status"].get("phase") != "Running":
            continue
        cls = classification(p)
        port = next((pt for pt in cls["ports"] if pt in (80, 8080, 3000, 8000, 443, 8443)), cls["ports"][0] if cls["ports"] else None)
        con = content(p["status"]["podIP"], port, scheme_of(p, port)) if port else None
        beh = behaviour(ns, p["metadata"]["name"], rows)
        verdict, reasons, recs = judge(cls, con or {}, beh, scan_static)
        out.append({"pod": p["metadata"]["name"], "verdict": verdict, "classification": cls,
                    "content": con, "behaviour": beh, "reasons": reasons, "recommendations": recs})
    return out


if __name__ == "__main__":
    import sys, time
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import adr_kpi
    ns = sys.argv[1]
    since = int(sys.argv[2]) if len(sys.argv) > 2 else int(time.time()) - 3600
    print(json.dumps(architecture(ns, adr_kpi.rows(ns, since, int(time.time()))), indent=1))
