#!/usr/bin/env python3
"""
adr_docs.py [--out <dir>]  — render adr/NNNN-*.md and adr/README.md from adrs.yaml (the checks)
and adr_text.yaml (the prose). The documents are generated, so an ADR's text and the check the
engine runs cannot drift; edit the YAML, not the markdown.

Every ADR has the same sections, in this order:
  Decision · Why · How it is checked · What a violation looks like · How to fix · [Notes] ·
  Reproduce without the tooling · Mechanical mapping (one table)
Rule and control IDs appear only in the mapping table and the Reproduce commands.
"""
import argparse, os, re
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = yaml.safe_load(open(os.path.join(HERE, "adrs.yaml")))
TEXT = yaml.safe_load(open(os.path.join(HERE, "adr_text.yaml")))
RESERVED = {"source", "broken", "fix", "owner", "min", "max", "what", "counted", "note", "name", "show", "group_by",
            "tiers", "unattributed", "min_age_s"}

SOURCE_WORDS = {
    "runtime": "the runtime sensor saw", "wire": "a captured flow", "spec": "a container in the pod spec",
    "pod": "a running pod", "svc": "a Service", "ingress": "an Ingress", "netpol": "the namespace's NetworkPolicy set",
    "profile": "a stored ContainerProfile", "policy": "the admission policy", "scan": "the static scan flagged",
    "ingress": "an ingress/gateway object", "secret": "a Secret of the namespace", "rbac": "a workload ServiceAccount's bindings",
    "probe": "an evaluator HTTP probe", "content": "the page the frontend serves", "scan_present": "the kubescape scan",
}
RULE_WORDS = {
    "R0001": "a process the profile does not list was launched", "R0002": "a file the profile does not list was opened",
    "R0004": "a Linux capability the profile does not list was used", "R0005": "a DNS name outside the learned set was resolved",
    "R0006": "the ServiceAccount token was read", "R0010": "a sensitive file was read",
    "R0011": "an outbound connection the tier profile does not allow", "R0012": "an inbound connection the tier profile does not allow",
    "R0040": "a process ran with arguments the profile does not list", "R1017": "a profile binding that resolves to nothing",
    "R1001": "a binary that is not part of the container image was executed", "R1004": "a process was executed from a mounted volume",
    "R1002": "a kernel module load was attempted", "R0007": "the Kubernetes API was called outside the profile",
}
CONTROL_WORDS = {"C-0046": "insecure capabilities", "C-0038": "a shared host PID/IPC namespace", "C-0041": "host network access",
                 "C-0237": "an unsigned image", "C-0236": "an unpinned image", "C-0034": "a mounted ServiceAccount token",
                 "C-0057": "a privileged container", "C-0048": "a hostPath mount", "C-0074": "a mounted container runtime socket",
                 "C-0012": "credentials in configuration files", "C-0035": "an administrative role", "C-0015": "listing Secrets",
                 "C-0002": "exec into containers", "C-0007": "delete capabilities", "C-0063": "portforward privileges",
                 "C-0065": "impersonation", "C-0031": "deleting events", "C-0186": "access to Secrets", "C-0187": "wildcards in roles",
                 "C-0188": "pod creation rights", "C-0191": "bind/impersonate/escalate"}
FIELD_WORDS = {
    "tier": "tier", "peer_tier": "peer tier", "tags": "tailscale tags", "peer_kind": "peer", "src_tier": "source tier", "dst_tier": "destination tier",
    "proto": "protocol", "encrypted": "encrypted", "path": "path", "remote_kind": "remote", "remote_ns": "remote namespace",
    "run_as_non_root": "runAsNonRoot", "allow_priv_esc": "allowPrivilegeEscalation", "read_only_root": "readOnlyRootFilesystem",
    "seccomp": "seccompProfile.type", "pull_policy": "imagePullPolicy", "scope": "scope", "assigned_by": "tier assigned by",
    "wildcards": "wildcards over unsubtracted protected paths", "unsubtracted_paths": "protected paths left unsubtracted", "js_bytes": "client code bytes", "n_solvers": "solvers defined in the page",
    "n_datasets": "datasets embedded in the page", "client_state": "browser-storage uses", "backend_calls": "backend call sites",
    "auth_markers": "authentication markers", "auth": "Authorization", "status": "HTTP status",
    "via_ingress": "via the ingress controller", "egress_external": "outbound to outside the cluster", "fronts_frontend": "fronting the frontend",
    "role": "direction", "kind": "kind", "image_overlays": "writable volume over an image path",
    "env_literal_secrets": "credential-named env vars with literal values", "env_secret_refs": "Secrets injected as env",
    "host_path_mounts": "hostPath mounts", "caps_add_dangerous": "dangerous capabilities added", "age_days": "age in days",
    "metadata_api_blocked": "metadata API blocked by NetworkPolicy", "secrets_read": "can read Secrets", "wildcard_verbs": "wildcard verbs",
    "wildcard_resources": "wildcard resources", "cluster_scoped": "cluster-scoped binding", "is_default": "the default ServiceAccount",
    "has_bindings": "bindings", "exec": "exec/attach/portforward", "escalate": "escalate/bind/impersonate", "admin": "an administrative role",
}
# (field, value) -> phrase; booleans and None rendered as statements, not "= True/False"
PHRASE = {
    ("tier", None): "no tier label", ("bound", False): "its profile missing in the namespace", ("bound", True): "profile bound",
    ("tls", False): "without spec.tls", ("edge_prescribed", False): "not on a prescribed edge", ("edge_prescribed", True): "on a prescribed edge",
    ("default_deny", False): "no default-deny ingress+egress", ("has_metrics_port", False): "no containerPort named metrics",
    ("has_requests", False): "no resources.requests", ("has_limits", False): "no resources.limits",
    ("has_liveness", False): "no livenessProbe", ("has_readiness", False): "no readinessProbe",
    ("caps_drop_all", False): "capabilities not dropped (ALL)", ("pinned", False): "not pinned by digest", ("pinned", True): "pinned by digest",
    ("health_path", False): "not a health path", ("kubelet_probe", False): "not a kubelet probe",
    ("token_concrete", False): "token path not concrete", ("serves_page", True): "serving a page",
    ("automount_sa", True): "automountServiceAccountToken true", ("exec_probe", True): "an exec probe",
    ("host_network", True): "hostNetwork set", ("exposed", True): "type NodePort/LoadBalancer",
    ("declared_known", True): "applied manifest readable", ("has_port_fallback", True): "a port-based rule present",
    ("route", True): "an existing route", ("present", True): "supplied", ("encrypted", 0): "plaintext",
    ("role", "server"): "inbound", ("role", "client"): "outbound", ("fronts_frontend", False): "none fronting the frontend",
    ("fronts_frontend", True): "fronting the frontend", ("egress_external", True): "outbound to outside the cluster",
    ("scope", "namespace"): "namespace-wide", ("scope", "object"): "per object",
    ("tags", "empty"): "no tailscale tags", ("fronts_frontend", False): "none exposing the frontend",
    ("host_ports", "nonempty"): "hostPort set", ("plaintext_ports", "nonempty"): "a plaintext port exposed",
    ("image_overlays", "nonempty"): "a writable volume mounted over an image path",
    ("env_literal_secrets", "nonempty"): "a credential-named env var with a literal value", ("env_secret_refs", "nonempty"): "a Secret injected as an environment variable",
    ("host_path_mounts", "nonempty"): "a hostPath mounted", ("caps_add_dangerous", "nonempty"): "a dangerous capability added",
    ("shared", True): "referenced by more than one workload", ("cross_tier", True): "referenced from more than one tier", ("referenced", True): "referenced by a workload",
    ("privileged", True): "privileged", ("runtime_socket", True): "the container runtime socket mounted", ("host_pid", True): "hostPID", ("host_ipc", True): "hostIPC",
    ("metadata_api_blocked", False): "the metadata API not blocked", ("remote_kind", "metadata"): "to the cloud metadata API",
    ("is_default", True): "the default ServiceAccount", ("has_bindings", True): "with bindings",
}


def lst(v):
    return ", ".join(map(str, v)) if isinstance(v, list) else str(v)


def phrase(k, v):
    w = FIELD_WORDS.get(k, k.replace("_", " "))
    if isinstance(v, dict):
        out = []
        for op, arg in v.items():
            if op == "empty":
                out.append(PHRASE.get((k, "nonempty"), f"{w} set") if not arg else f"{w} empty")
            elif op == "not":
                a = arg if isinstance(arg, list) else [arg]
                out.append(f"{w} not {', '.join('true' if x is True else 'false' if x is False else str(x) for x in a)}")
            else:
                out.append(f"{w} {dict(gt='>', ge='≥', lt='<', le='≤', regex='~', **{'in': 'in'})[op]} {lst(arg)}")
        return " ".join(out)
    if isinstance(v, list):
        return f"{w} {' or '.join(map(str, v))}"
    if (k, v) in PHRASE:
        return PHRASE[(k, v)]
    if v is True:
        return w
    if v is False:
        return f"no {w}"
    if v is None:
        return f"no {w}"
    return f"{w} {v}"


def describe(pred):
    src = pred["source"]
    rest = [(k, v) for k, v in pred.items() if k not in RESERVED and k not in ("rule", "control")]
    if src == "runtime":
        rules = pred.get("rule"); rules = rules if isinstance(rules, list) else [rules] if rules else []
        head = SOURCE_WORDS[src] + " " + (" or ".join(RULE_WORDS.get(r, r) for r in rules) if rules else "a detection")
    elif src == "scan":
        ctl = pred.get("control"); ctl = ctl if isinstance(ctl, list) else [ctl]
        head = SOURCE_WORDS[src] + " " + " or ".join(CONTROL_WORDS.get(c, c) for c in ctl)
    else:
        head = SOURCE_WORDS.get(src, src)
    return head + (" — " + ", ".join(phrase(k, v) for k, v in rest) if rest else "")


def mapping_key(pred):
    src = pred["source"]
    if src == "runtime":
        return lst(pred.get("rule")).replace(", ", " / ")
    if src == "scan":
        return lst(pred.get("control")).replace(", ", " / ")
    if src == "probe":
        return f"GET {pred.get('path', '<route>') if not isinstance(pred.get('path'), dict) else '<route>'} with Authorization={pred.get('auth')}"
    if src == "wire":
        if pred.get("path"):
            return f"captured GET {pred['path']}" + (" from outside monitoring" if "remote_ns" in pred else "")
        if pred.get("role") == "server":
            return f"captured inbound from {lst(pred.get('remote_kind', '*'))}" + (" plaintext" if pred.get("encrypted") == 0 else "")
        if pred.get("egress_external"):
            return "captured outbound to outside the cluster" + (" plaintext" if pred.get("encrypted") == 0 else "")
        return f"captured flow {lst(pred.get('src_tier', '*'))}→{lst(pred.get('dst_tier', '*'))}" + (" plaintext" if pred.get("encrypted") == 0 else "")
    return ", ".join(phrase(k, v) for k, v in pred.items() if k not in RESERVED)


REPRO = {
    "runtime": "clickhouse-client -q \"SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ({rules}) AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)\"",
    "wire": "clickhouse-client -q \"SELECT pod, remote_addr, local_port, encrypted, req_path, count() FROM forensic_db.http_events WHERE namespace='<ns>' AND time_ > now()-INTERVAL 1 HOUR GROUP BY ALL\"",
    "spec": "kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {{name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}}'",
    "pod": "kubectl -n <ns> get pods -o custom-columns='POD:.metadata.name,TIER:.metadata.labels.app\\.kubernetes\\.io/tier,PROFILE:.metadata.labels.kubescape\\.io/user-defined-profile,START:.status.startTime'",
    "svc": "kubectl -n <ns> get svc -o custom-columns='NAME:.metadata.name,TYPE:.spec.type,PORTS:.spec.ports[*].port,NODEPORTS:.spec.ports[*].nodePort'",
    "ingress": "kubectl -n <ns> get ingress,ingressroutes.traefik.io,httproutes.gateway.networking.k8s.io -o yaml | grep -n -E 'kind:|host|tls|entryPoints|parentRefs'",
    "netpol": "kubectl -n <ns> get netpol -o yaml",
    "profile": "kubectl -n <ns> get containerprofiles.spdx.softwarecomposition.kubescape.io <name> -o json | jq '[.spec.opens[].path]'   # GET each; LIST returns an empty spec",
    "scan": "kubescape scan framework AllControls --include-namespaces <ns> --format json --output /tmp/AllControls-<ns>.json",
    "scan_present": "ls -l /tmp/AllControls-<ns>.json   # the scan file the evaluator was given",
    "secret": "kubectl -n <ns> get secrets -o custom-columns='NAME:.metadata.name,TYPE:.type,AGE:.metadata.creationTimestamp'; kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {{name, env, envFrom, volumeMounts}}'",
    "rbac": "kubectl -n <ns> get rolebindings -o wide; kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.namespace==\"<ns>\") | {{name:.metadata.name, role:.roleRef.name}}'",
    "probe": "curl -sk -o /dev/null -w '%{{http_code}}\\n' http://<backend-pod-ip>:<port><route>   # then with -H 'Authorization: Bearer not.a.token', then with a platform-minted token",
    "content": "curl -s http://<frontend-pod-ip>:<port>/ | grep -o '<script[^>]*src=\"[^\"]*\"'   # then fetch each script and grep for the markers listed above",
}
EDGE_WORDS = {"ns:zitadel": "identity provider (ns:zitadel on this platform)", "dns": "DNS", "*": "every tier"}


def render_adr(a):
    t = TEXT[a["id"]]
    L = [f"# {a['id']} — {a['title']}", "",
         f"**Status:** {t['status']}  ", f"**Applies to:** {t['applies_to']}  ",
         f"**Enforced by:** {', '.join(a.get('enforced_by', []))}", "",
         "## Decision", "", t["decision"].strip(), "",
         "## Why", "", t["why"].strip(), "",
         "## How it is checked", "",
         "`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):", ""]
    for p in a.get("observed", []):
        if p["source"] == "coverage":
            tiers = p.get("tiers")
            L.append(f"* **coverage** — every pod{' of tier ' + '/'.join(tiers) if tiers else ''} carries a tier label, is bound to a profile that exists, "
                     f"is older than the warm-up ({SPEC.get('warmup_s', 210)} s), and the sensor reported at least one event for the namespace in the window.")
        else:
            L.append(f"* **{p.get('what', p['source'])}** — at least {p.get('min', 1)}: {describe(p)}.")
    L += ["", "## What a violation looks like", "", "Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).", ""]
    for p in a.get("violated", []):
        tag = " *(informational, not counted)*" if p.get("counted") is False else (" *(owner: platform)*" if p.get("owner") == "platform" else "")
        L.append(f"* **{p['broken']}**{tag} — {describe(p)}.")
    if any(p["source"] == "content" for p in a.get("violated", []) + a.get("observed", [])):
        L += ["", "Markers counted in the served client code (declared in `compliance/adrs.yaml`, app-neutral):", ""]
        for k, rx in SPEC.get("content_markers", {}).items():
            L.append(f"* `{k}`: `{rx}`")
    L += ["", "## How to fix", ""]
    seen = set()
    for p in a.get("violated", []):
        if p["fix"] not in seen:
            seen.add(p["fix"]); L.append(f"* {p['broken']}: {p['fix']}")
    if t.get("notes"):
        L += ["", "## Notes", "", t["notes"].strip()]
    L += ["", "## Reproduce without the tooling", "", "```bash"]
    srcs = []
    for p in a.get("violated", []) + a.get("observed", []):
        if p["source"] not in srcs and p["source"] in REPRO:
            srcs.append(p["source"])
    rules = sorted({r for p in a.get("violated", []) if p["source"] == "runtime" for r in (p.get("rule") if isinstance(p.get("rule"), list) else [p.get("rule")]) if r})
    for s in srcs:
        L.append(f"# {s}")
        L.append(REPRO[s].format(rules=", ".join(f"'{r}'" for r in rules) or "'R0011','R0012'"))
    L += ["```", "", "## Mechanical mapping", "", "| source | key | decision broken |", "|---|---|---|"]
    L += [f"| {p['source']} | {mapping_key(p)} | {p['broken']} |" for p in a.get("violated", [])]
    L += ["", "*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*", ""]
    return "\n".join(L)


def render_readme():
    L = ["# Architecture Decision Records — and how each one is checked", "",
         "Every ADR here resolves to a check the platform runs: at admission (kyverno), statically (the pod spec, a kubescape scan), "
         "at runtime (the eBPF sensor comparing a container with its tier profile) or on the wire (the Pixie tracer). "
         "The check is declared next to the decision in `compliance/adrs.yaml`; the engine evaluates it and reports, per ADR:", "",
         "| status | meaning |", "|---|---|",
         "| `VIOLATED` | at least one counted finding: the observed event, the decision it broke, the fix |",
         "| `COMPLIANT` | every required evidence item was examined and is clean — the proof says what was examined |",
         "| `NOT_OBSERVED` | evidence missing: pods younger than the warm-up, no traffic driven, no scan supplied, a peer that cannot be attributed |", "",
         "**No observation, no finding — and no observation, no pass.** A finding carries the event that produced it; a pass carries what was examined.", "",
         "## How to read an ADR", "",
         "Every ADR has the same sections: Decision · Why · How it is checked · What a violation looks like · How to fix · Reproduce without the tooling · Mechanical mapping.", "",
         "*How it is checked* lists the evidence that must be present for `COMPLIANT`; if any item is missing the status is `NOT_OBSERVED` and the proof names it. "
         "*What a violation looks like* lists the predicates; every event matching one becomes a finding carrying the observed event, the decision it broke and the fix. "
         "Events the engine discounts (table below) stay in the report as notes with `counted=false` and never make an ADR `VIOLATED`. "
         "Rule and control identifiers appear only in each ADR's mapping table and its reproduce commands.", "",
         "## The enforcement points", "",
         "| point | when | mechanism | what it sees |", "|---|---|---|---|",
         "| admission | before the pod exists | kyverno mutate/validate | the manifest: tier label, profile binding, pins, ports, envelope |",
         "| static | any time | the pod spec; `kubescape scan` controls | what was declared |",
         "| runtime | while the container runs | node-agent + the tier ContainerProfile (SBoB) | processes, files, DNS, capabilities, network edges the profile does not declare |",
         "| wire | while traffic flows | Pixie protocol tracers | the request itself: source, destination, port, path, encrypted or not |", "",
         "## Preconditions for a verdict", "",
         "* every pod carries `app.kubernetes.io/tier` and `kubescape.io/user-defined-profile` naming a profile that exists in its namespace (an unbound pod is unwatched)",
         "* the tier profile declares the edges the architecture prescribes by label selector — otherwise allowed traffic alerts and the platform, not the application, owns the finding",
         f"* pods are older than the warm-up ({SPEC.get('warmup_s', 210)} s) before network rules are judged",
         "* the application was put under realistic traffic (`harness/load.sh`: its own k6 suite or generator, else the browser stand-in) — an unexercised edge cannot be COMPLIANT; requests tagged `X-Test-Case` name the use case in the proof",
         "* a kubescape scan is supplied for the static controls, or those ADRs stay NOT_OBSERVED", "",
         "## The decision set", "",
         "| ADR | summary | decision | enforced by |", "|---|---|---|---|"]
    for a in SPEC["adrs"]:
        n = a["id"].split("-")[1]
        L.append(f"| [{n}]({n}-{slug(a['summary'])}.md) | {a['summary']} | {a['title']} | {', '.join(a.get('enforced_by', []))} |")
    L += ["", "## Prescribed edges", "",
          "Traffic on these edges is never a violation of a tier ADR. A profile that alerts on one has a gap: that is a violation of ADR-0005 owned by the platform (`owner=platform`), because allowed traffic alerting means the profile was not declared as the architecture prescribes.", "",
          "```", *[f"{EDGE_WORDS.get(a, a)} -> {EDGE_WORDS.get(b, b)}" for a, b in SPEC.get("topology", [])], "```", "",
          "## Discounts", "", "| name | what | effect |", "|---|---|---|"]
    seen = {}
    for d in SPEC.get("discounts", []):
        seen.setdefault(d["note"], []).append(d)
    for note, ds in seen.items():
        d = ds[0]
        L.append(f"| {' / '.join(x['name'] for x in ds)} | {note} | " + ("NOT_OBSERVED (cannot be attributed)" if d.get("unattributed") else f"counted=false, owner={d.get('owner', 'application')}") + " |")
    L += ["", "## Producing a verdict", "", "```bash",
          "export ADR_CH=http://ingest_writer:changeme-ingest@<clickhouse>:8123",
          "./harness/loop.sh <N> <namespace> <manifest>      # apply, wait for warm-up, drive, scan, evaluate, write forensic_db.adr_findings",
          "python3 compliance/adr_kpi.py <namespace> --since <epoch> --scan /tmp/AllControls-<namespace>.json --out kpi.json",
          "python3 compliance/adr_mcp.py                       # the same evaluator as an MCP server for the coding agent",
          "```", "", "*Generated by `compliance/adr_docs.py`.*", ""]
    return "\n".join(L)


def slug(title):
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60].rstrip("-")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=os.path.join(HERE, "..", "adr")); a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for f in os.listdir(a.out):  # previous generation: file names derive from the summary
        if re.match(r"\d{4}-.*\.md$", f):
            os.remove(os.path.join(a.out, f))
    for adr in SPEC["adrs"]:
        n = adr["id"].split("-")[1]
        path = os.path.join(a.out, f"{n}-{slug(adr['summary'])}.md")
        open(path, "w").write(render_adr(adr)); print("wrote", path)
    open(os.path.join(a.out, "README.md"), "w").write(render_readme()); print("wrote README.md")


if __name__ == "__main__":
    main()
