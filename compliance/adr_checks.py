#!/usr/bin/env python3
"""
Checks for ADR-0008..0015 (the "vibe-monolith to production" set).

Each check returns (findings, observed) where observed says whether the check had
anything to look at — so the KPI can tell COMPLIANT from NOT_OBSERVED. Findings use the
review.py shape (adr, source, evidence_class, workload, decision_broken, observed, fix).

Sources: kubectl (pods, templates, services, ingresses, netpols), a live HTTP probe
tagged User-Agent adr-evaluator (so its own rows are excluded from the wire check),
ClickHouse http_events/pgsql_events (Pixie export: encrypted flag, path, status),
and adr_arch (classification + content + behaviour).
"""
import json, re, subprocess, urllib.error, urllib.request

UA = "adr-evaluator/1"
MUTABLE_TAGS = {"latest", "main", "master", "dev", "stable", "edge", "nightly"}
PLAINTEXT_PORTS = {80, 8000, 8080, 3000, 5432, 6379, 3306, 27017}
APP_TIERS = ("backend", "middleware")


def kget(args, items=True):
    o = json.loads(subprocess.run(["kubectl"] + args + ["-o", "json"], capture_output=True, text=True).stdout or "{}")
    return o.get("items", []) if items else o


def node_addresses():
    """Every address a kubelet probe can arrive from (cilium router IPs + node IPs)."""
    out = set()
    for n in kget(["get", "ciliumnodes"]) + kget(["get", "nodes"]):
        out |= {a.get("ip") or a.get("address") for a in n.get("spec", {}).get("addresses", []) + n.get("status", {}).get("addresses", [])}
    return out - {None}


def probe_targets(ns_):
    """pod name -> {(path, port)} the pod itself asks the kubelet to hit (httpGet/tcpSocket probes)."""
    out = {}
    for p in ns_.pods:
        for c in p["spec"]["containers"]:
            named = {pt.get("name"): pt.get("containerPort") for pt in c.get("ports", []) or []}
            for k in ("livenessProbe", "readinessProbe", "startupProbe"):
                pr = c.get(k) or {}
                hg, ts = pr.get("httpGet"), pr.get("tcpSocket")
                if hg or ts:
                    port = (hg or ts).get("port")
                    port = named.get(port, port)
                    out.setdefault(p["metadata"]["name"], set()).add((hg.get("path", "/") if hg else "", port))
    return out


def probe(ip, port, path="/", method="GET", headers=None, scheme="http"):
    """status, bytes, headers — never raises. None status = unreachable (a NetworkPolicy
    that denies the evaluator's vantage is the usual, and correct, reason)."""
    import adr_arch
    req = urllib.request.Request(f"{scheme}://{ip}:{port}{path}", method=method,
                                 headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5, context=adr_arch._NOVERIFY if scheme == "https" else None) as r:
            return r.status, len(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, 0, dict(e.headers)
    except Exception as e:
        return None, 0, {"error": str(e)}


def f(adr, workload, broken, observed, fix, source="static", **kw):
    return {"adr": adr, "source": source, "evidence_class": "declared" if source == "static" else "observed",
            "workload": workload, "decision_broken": broken, "observed": observed, "fix": fix, **kw}


class Namespace:
    def __init__(self, ns):
        self.ns = ns
        self.pods = [p for p in kget(["-n", ns, "get", "pods"]) if p["status"].get("phase") == "Running"]
        self.templates, self.declared = {}, {}
        for kind in ("deploy", "sts", "ds"):
            for w in kget(["-n", ns, "get", kind]):
                self.templates[w["metadata"]["name"]] = w["spec"]["template"]
                # what the author wrote, before admission mutated it (kyverno autogen labels the
                # template too, so the live object cannot tell declared from assigned)
                la = w["metadata"].get("annotations", {}).get("kubectl.kubernetes.io/last-applied-configuration")
                self.declared[w["metadata"]["name"]] = json.loads(la)["spec"]["template"] if la else None
        self.svcs = kget(["-n", ns, "get", "svc"])
        self.ingresses = kget(["-n", ns, "get", "ingress"])
        self.netpols = kget(["-n", ns, "get", "netpol"])

    def owner(self, pod):
        """Deployment/StatefulSet/DaemonSet name a pod descends from (by name prefix)."""
        for name in sorted(self.templates, key=len, reverse=True):
            if pod["metadata"]["name"].startswith(name + "-"):
                return name
        return None

    def tier(self, pod):
        return pod["metadata"].get("labels", {}).get("app.kubernetes.io/tier")

    def http_port(self, pod):
        ports = [pt.get("containerPort") for c in pod["spec"]["containers"] for pt in c.get("ports", []) or []]
        return next((p for p in ports if p in (80, 8080, 3000, 8000, 5000, 9000, 443, 8443)), ports[0] if ports else None)

    def scheme(self, pod, port):
        import adr_arch
        return adr_arch.scheme_of(pod, port)

    def vantages(self, pod):
        """Where to send a request for this pod from: the pod itself, then — when a
        NetworkPolicy keeps the evaluator out — each frontend pod, which proxies the
        backend the way the platform ingress does. Yields (ip, port, scheme, via)."""
        yield pod["status"]["podIP"], self.http_port(pod), self.scheme(pod, self.http_port(pod)), None
        if self.netpols and self.tier(pod) in APP_TIERS:
            for fe in self.pods:
                if self.tier(fe) == "frontend" and self.http_port(fe):
                    yield fe["status"]["podIP"], self.http_port(fe), self.scheme(fe, self.http_port(fe)), fe["metadata"]["name"]


# ---------------------------------------------------------------- ADR-0008 / 0009

def check_0008(arch):
    out, seen = [], 0
    for w in arch:
        if w.get("content") and "error" not in w["content"]:
            seen += 1
        if w["verdict"] == "SINGLE_TIER_APPLICATION_IN_PRESENTATION_TIER":
            c, b = w["content"], w["behaviour"]
            out.append(f("ADR-0008", w["pod"], "the presentation tier serves the whole application",
                         f"{c['inline_js_bytes']//1024} KB client JS, {c['functions']} functions, solvers "
                         f"{c['defined_solvers'][:4]}, datasets {c['datasets']}, "
                         f"{c['markers'].get('money',0)} pricing refs; {c['markers'].get('backend_calls',0)} backend calls; "
                         f"{b['egress_events']} egress events",
                         "split: nginx shell (tier=frontend) -> API (tier=backend, 8000/8080) -> store (tier=database); "
                         "move the datasets to the store; the shell's fetch() to the API is the egress ADR-0001 expects",
                         source="content", verdict=w["verdict"]))
        elif w["verdict"] == "COMPUTATION_IN_PRESENTATION_TIER":
            c = w["content"]; m = c["markers"]
            out.append(f("ADR-0008", w["pod"], "the presentation tier still computes",
                         f"{c['inline_js_bytes']//1024} KB client JS across {list(c.get('script_bytes', {}).keys())}; "
                         f"{m.get('numeric_solvers',0)} solver, {m.get('simulation',0)} simulation, {m.get('money',0)} pricing markers; "
                         f"solvers defined in the shell: {c['defined_solvers'][:8]}",
                         "move every solver/integrator/sweep behind the API (the browser renders, it does not compute); "
                         "constants from GET /api/constants; drop the engine scripts from the shell",
                         source="content", verdict=w["verdict"]))
    return out, seen > 0


def check_0009(ns_, arch):
    out = []
    for w in arch:
        cls = w["classification"]
        if not cls["custom_image"] or not cls["tier"] or cls["tier"] == "unclassified":
            continue
        pod = next(p for p in ns_.pods if p["metadata"]["name"] == w["pod"])
        owner = ns_.owner(pod)
        src = ns_.declared.get(owner)
        if src is None:
            continue  # no last-applied: cannot tell declared from assigned
        declared = src.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/tier")
        if not declared:
            out.append(f("ADR-0009", owner or w["pod"], "tier was guessed from the container port",
                         f"image {cls['images'][0]} matched no known component; tier={cls['tier']} assigned by "
                         f"{cls['matched_by']} ({cls['ports']}); manifest declares no app.kubernetes.io/tier",
                         "declare app.kubernetes.io/tier in the pod template (frontend|backend|database); "
                         "platform: remove the containerPort fallback from kyverno/02-label-tiers.yaml",
                         source="admission"))
    return out, len(arch) > 0


# ---------------------------------------------------------------- ADR-0010 authN

HEALTH_PATHS = {"/health", "/healthz", "/readyz", "/livez", "/api/health"}


def idp_token(ns):
    """A platform-minted bearer for this namespace (Secret idp-client, written by idp-client.sh).
    None when the platform has not provisioned a client — then only the negative probes run."""
    import base64
    r = subprocess.run(["kubectl", "-n", ns, "get", "secret", "idp-client", "-o", "json"], capture_output=True, text=True)
    sec = (json.loads(r.stdout or "{}").get("data") or {}) if r.returncode == 0 else {}
    if not sec:
        return None
    d = {k: base64.b64decode(v).decode() for k, v in sec.items()}
    # the evaluator runs on a node, where <svc>.<ns>.svc does not resolve: swap in the ClusterIP
    url = d["token_endpoint"]
    m = re.match(r"(https?://)([^/:]+)\.([^/:.]+)\.svc(?:\.cluster\.local)?(:\d+)?(/.*)?$", url)
    if m:
        ip = kget(["-n", m.group(3), "get", "svc", m.group(2)], items=False).get("spec", {}).get("clusterIP")
        if ip:
            url = f"{m.group(1)}{ip}{m.group(4) or ''}{m.group(5) or ''}"
    scope = "openid urn:zitadel:iam:org:project:id:" + d.get("project_id", "") + ":aud" if d.get("project_id") else "openid"
    try:
        req = urllib.request.Request(url, data=f"grant_type=client_credentials&scope={scope}".encode(),
                                     headers={"Host": "localhost:8080", "User-Agent": UA,
                                              "Authorization": "Basic " + base64.b64encode(f"{d['client_id']}:{d['client_secret']}".encode()).decode()})
        return json.loads(urllib.request.urlopen(req, timeout=10).read()).get("access_token")
    except Exception:
        return None


def check_0010(ns_, arch):
    """Three probes per backend route the shell calls: no token (expect 401), a garbage
    token (expect 401), a platform-minted token (expect < 400). Probing "/" alone proved
    nothing — an API that 404s on "/" passed as if it authenticated."""
    out, probed = [], 0
    paths = sorted({pp for w in arch for pp in ((w.get("content") or {}).get("api_paths") or [])} - HEALTH_PATHS)
    token = idp_token(ns_.ns)
    for p in ns_.pods:
        if ns_.tier(p) not in APP_TIERS:
            continue
        who = ns_.owner(p) or p["metadata"]["name"]
        open_paths, garbage_ok, valid_bad, via, ip, port, scheme = [], [], [], None, None, None, None
        for ip, port, scheme, via in ns_.vantages(p):
            if not port:
                continue
            reach = [probe(ip, port, path, scheme=scheme)[0] for path in (paths or ["/"])[:3]]
            if any(st is not None for st in reach):
                break
        else:
            continue  # nothing answered from any vantage: NOT_OBSERVED for this pod
        if via:
            out.append(f("ADR-0010", who, "backend not reachable from the evaluator; probed through the frontend",
                         f"direct {ns_.scheme(p, ns_.http_port(p))}://{p['status']['podIP']}:{ns_.http_port(p)} unreachable (NetworkPolicy); using {via}:{port}",
                         "nothing to fix — this is ADR-0015 working", source="probe", counted=False, owner="platform"))
        for path in (paths or ["/"])[:8]:
            st, n, _ = probe(ip, port, path, scheme=scheme)
            if st is None or st == 404:
                continue
            probed += 1
            if st < 400:
                open_paths.append(f"{path}->{st}")
                continue
            st2, _, _ = probe(ip, port, path, headers={"Authorization": "Bearer not.a.token"}, scheme=scheme)
            if st2 is not None and st2 < 400:
                garbage_ok.append(f"{path}->{st2}")
            if token:
                st3, _, _ = probe(ip, port, path, headers={"Authorization": f"Bearer {token}"}, scheme=scheme)
                if st3 is None or (st3 >= 400 and st3 not in (404, 405)):  # 404/405: not a GET route, auth passed
                    valid_bad.append(f"{path}->{st3}")
        if open_paths:
            out.append(f("ADR-0010", who, "backend answers without a bearer token",
                         f"GET {scheme}://{ip}:{port} without Authorization: {', '.join(open_paths)}; expected 401",
                         "validate platform-IdP (Zitadel OIDC) bearer tokens on every route: issuer, audience, JWKS; 401 otherwise",
                         source="probe"))
        if garbage_ok:
            out.append(f("ADR-0010", who, "backend accepts an invalid token",
                         f"Authorization: Bearer <garbage>: {', '.join(garbage_ok)}; expected 401",
                         "verify signature/issuer/audience/expiry against the IdP JWKS", source="probe"))
        if valid_bad:
            out.append(f("ADR-0010", who, "backend rejects the platform IdP's token",
                         f"Bearer minted by the platform IdP (client_credentials): {', '.join(valid_bad)}; expected < 400",
                         "accept iss http://localhost:8080 (reach it at http://zitadel.zitadel.svc:8080 with Host: localhost:8080), "
                         "JWKS /oauth/v2/keys, aud = the project id", source="probe"))
    # frontend side: calls a backend but carries no auth
    for w in arch:
        c = w.get("content") or {}
        m = c.get("markers", {})
        if w["classification"]["tier"] == "frontend" and m.get("backend_calls", 0) > 0 and m.get("auth", 0) == 0:
            out.append(f("ADR-0010", w["pod"], "frontend calls the backend without authenticating",
                         f"{m['backend_calls']} fetch/XHR call sites, 0 OIDC/bearer markers in served code",
                         "authorization-code + PKCE against the platform IdP; send Authorization: Bearer on every API call",
                         source="content"))
    return out, probed > 0


# ---------------------------------------------------------------- ADR-0011 TLS

def check_0011(ns_, ch, since, until):
    out = []
    sql = f"""
    SELECT 'http' proto, pod, local_port, remote_addr, req_method || ' ' || req_path what, resp_status, count() c
    FROM forensic_db.http_events
    WHERE namespace = '{ns_.ns}' AND encrypted = 0 AND time_ BETWEEN fromUnixTimestamp64Nano({since}000000000) AND fromUnixTimestamp64Nano({until}000000000)
      AND req_headers NOT LIKE '%{UA}%' AND req_path NOT IN ('/healthz','/readyz','/livez')
      AND remote_addr NOT IN ('127.0.0.1','::1')
    GROUP BY ALL
    UNION ALL
    SELECT 'pgsql', pod, local_port, remote_addr, substring(req, 1, 60), 0, count()
    FROM forensic_db.pgsql_events
    WHERE namespace = '{ns_.ns}' AND encrypted = 0 AND time_ BETWEEN fromUnixTimestamp64Nano({since}000000000) AND fromUnixTimestamp64Nano({until}000000000)
      AND remote_addr NOT IN ('127.0.0.1','::1')
    GROUP BY ALL
    FORMAT JSONEachRow"""
    rows = [json.loads(l) for l in ch(sql).splitlines()]
    # kubelet probes arrive from the node's router IP on the path the pod itself declares;
    # they are not application traffic and TLS on them is the platform's choice, not the app's
    node_ips = node_addresses()
    probe_paths = {pod: {path for path, _ in pp} for pod, pp in probe_targets(ns_).items()}
    live = {p["metadata"]["name"] for p in ns_.pods}
    rows = [r for r in rows if r["pod"].split("/")[-1] in live]  # a departed pod's wire is not the running code's
    rows = [r for r in rows if not (r["remote_addr"] in node_ips and r["proto"] == "http"
                                     and r["what"].split(" ", 1)[-1] in probe_paths.get(r["pod"].split("/")[-1], ()))]
    total = ch(f"SELECT count() FROM forensic_db.http_events WHERE namespace='{ns_.ns}' AND time_ BETWEEN fromUnixTimestamp64Nano({since}000000000) AND fromUnixTimestamp64Nano({until}000000000) FORMAT TSV").strip()
    for r in rows:
        pod = r["pod"].split("/")[-1]
        out.append(f("ADR-0011", pod, "plaintext on the wire",
                     f"{r['proto']} {r['what']} -> {pod}:{r['local_port']} from {r['remote_addr']} ({r['c']} req, encrypted=0"
                     + (f", status {r['resp_status']}" if r["proto"] == "http" else "") + ")",
                     "serve TLS from a platform-issued certificate (cert-manager); clients verify; postgres ssl=on hostssl-only",
                     source="pixie", table=f"forensic_db.{r['proto']}_events"))
    for s in ns_.svcs:
        if s["spec"].get("type") in ("NodePort", "LoadBalancer"):
            pl = [p["port"] for p in s["spec"].get("ports", []) if p.get("port") in PLAINTEXT_PORTS]
            if pl:
                out.append(f("ADR-0011", s["metadata"]["name"], "plaintext port exposed outside the cluster",
                             f"Service type={s['spec']['type']} ports {pl}", "ClusterIP + Ingress with tls:"))
    for i in ns_.ingresses:
        if not i["spec"].get("tls"):
            out.append(f("ADR-0011", i["metadata"]["name"], "Ingress without TLS", "spec.tls absent",
                         "add spec.tls with a cert-manager issued secret"))
    return out, int(total or 0) > 0


# ---------------------------------------------------------------- ADR-0012 metrics

def check_0012(ns_, ch, since, until):
    out, probed = [], 0
    for p in ns_.pods:
        if ns_.tier(p) not in APP_TIERS + ("database",):
            continue
        owner = ns_.owner(p) or p["metadata"]["name"]
        names = [pt.get("name") for c in p["spec"]["containers"] for pt in c.get("ports", []) or []]
        if "metrics" not in names:
            out.append(f("ADR-0012", owner, "no dedicated metrics port",
                         f"containerPorts named {names}; none named metrics",
                         "expose metrics on a second containerPort named metrics; add a ServiceMonitor/PodMonitor"))
        port = ns_.http_port(p)
        if port and ns_.tier(p) in APP_TIERS:
            st, n, _ = None, 0, None
            for ip, vport, scheme, via in ns_.vantages(p):
                st, n, _ = probe(ip, vport, "/metrics", scheme=scheme)
                if st is not None:
                    break
            if st is not None:
                probed += 1
            if st == 200:
                out.append(f("ADR-0012", owner, "/metrics served on the application port",
                             f"GET {scheme}://{ip}:{vport}/metrics -> 200 ({n} B)" + (f" via {via}" if via else ""),
                             "404 /metrics on the application port; serve it on the metrics port only", source="probe"))
    sql = f"""SELECT pod, remote_addr, count() c FROM forensic_db.http_events
    WHERE namespace='{ns_.ns}' AND req_path='/metrics' AND resp_status=200 AND req_headers NOT LIKE '%{UA}%'
      AND time_ BETWEEN fromUnixTimestamp64Nano({since}000000000) AND fromUnixTimestamp64Nano({until}000000000)
    GROUP BY ALL FORMAT JSONEachRow"""
    mon = {p["status"]["podIP"] for p in kget(["-n", "monitoring", "get", "pods"])}
    # the kubelet probing a declared /metrics probe path from the node's router IP is not a scrape
    node_ips = node_addresses()
    probed_metrics = {pod for pod, pp in probe_targets(ns_).items() if any(path == "/metrics" for path, _ in pp)}
    for r in (json.loads(l) for l in ch(sql).splitlines()):
        if r["remote_addr"] in node_ips and r["pod"].split("/")[-1] in probed_metrics:
            continue
        if r["remote_addr"] not in mon:
            out.append(f("ADR-0012", r["pod"].split("/")[-1], "metrics scraped by something other than the platform",
                         f"GET /metrics 200 x{r['c']} from {r['remote_addr']} (not in namespace monitoring)",
                         "NetworkPolicy: metrics port from namespace monitoring only", source="pixie"))
    return out, probed > 0 or any(ns_.tier(p) in APP_TIERS + ("database",) for p in ns_.pods)


# ---------------------------------------------------------------- ADR-0014 pins

def check_0014(ns_):
    out = []
    for name, tpl in ns_.templates.items():
        for c in tpl["spec"]["containers"]:
            img, pol = c["image"], c.get("imagePullPolicy", "IfNotPresent")
            tag = img.rsplit(":", 1)[-1] if ":" in img.split("/")[-1] else None
            if "@sha256:" not in img:
                why = "no tag" if tag is None else f"tag :{tag}" + (" (mutable)" if tag in MUTABLE_TAGS else "")
                out.append(f("ADR-0014", name, "image is not pinned by digest", f"{c['name']}: {img} ({why}), imagePullPolicy={pol}",
                             f"image: {img.split('@')[0]}@sha256:<digest>; imagePullPolicy: IfNotPresent; sign with cosign"))
            elif pol == "Always":
                out.append(f("ADR-0014", name, "pull policy Always on a pinned image", f"{c['name']}: {img}", "imagePullPolicy: IfNotPresent"))
    # what actually ran vs what was asked
    for p in ns_.pods:
        for cs in p["status"].get("containerStatuses", []):
            if "@sha256:" not in cs.get("image", "") and "@sha256:" in cs.get("imageID", ""):
                out[-1:] and out[-1].update(running_digest=cs["imageID"].split("@")[-1][:19])
    return out, len(ns_.templates) > 0


# ---------------------------------------------------------------- ADR-0015 ingress/netpol

def check_0015(ns_):
    out = []
    for s in ns_.svcs:
        if s["spec"].get("type") in ("NodePort", "LoadBalancer"):
            nps = [p.get("nodePort") for p in s["spec"].get("ports", [])]
            out.append(f("ADR-0015", s["metadata"]["name"], "workload opens its own ingress",
                         f"Service type={s['spec']['type']} nodePorts {nps}", "type: ClusterIP; Ingress via the platform ingress class"))
    for name, tpl in ns_.templates.items():
        if tpl["spec"].get("hostNetwork"):
            out.append(f("ADR-0015", name, "hostNetwork", "spec.hostNetwork=true", "remove hostNetwork"))
        hp = [pt["hostPort"] for c in tpl["spec"]["containers"] for pt in c.get("ports", []) or [] if pt.get("hostPort")]
        if hp:
            out.append(f("ADR-0015", name, "hostPort", f"hostPorts {hp}", "remove hostPort; use a Service"))
    if ns_.pods and not ns_.netpols:
        out.append(f("ADR-0015", ns_.ns, "no NetworkPolicy in the namespace",
                     f"{len(ns_.pods)} running pods, 0 NetworkPolicy objects",
                     "default-deny ingress+egress; allow ingress-controller->frontend, frontend->backend, backend->database, "
                     "backend->IdP, monitoring->metrics, all->DNS"))
    return out, len(ns_.pods) > 0


def run(ns, arch, ch, since, until):
    """{adr: (findings, observed)} for ADR-0008..0015 except 0013 (static controls via review.py)."""
    n = Namespace(ns)
    return {
        "ADR-0008": check_0008(arch),
        "ADR-0009": check_0009(n, arch),
        "ADR-0010": check_0010(n, arch),
        "ADR-0011": check_0011(n, ch, since, until),
        "ADR-0012": check_0012(n, ch, since, until),
        "ADR-0014": check_0014(n),
        "ADR-0015": check_0015(n),
    }
