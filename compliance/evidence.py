#!/usr/bin/env python3
"""
Evidence adapters: everything the ADR engine can look at, normalised into flat events.

One adapter per source; every event is a dict with fixed field names so adrs.yaml can filter
on them without Python. Sources:

  pod       one per Running pod: tier, profile binding, age, how the tier was assigned
  spec      one per container: image pin, ports, securityContext, probes, resources, automount
  svc / ingress / netpol   the namespace's network objects (netpol also has one namespace-level row)
  profile   one per ContainerProfile stored in the namespace (GET each: LIST nulls .spec)
  secret    one per Secret of the namespace: who references it (env / volume), shared, cross-tier, age
  rbac      one per ServiceAccount a running pod uses: its bindings resolved to rules (admin, wildcards, secrets, exec, escalate)
  runtime   one per distinct node-agent detection (forensic_db.kubescape_logs) on a live pod,
            with the peer resolved: pod/tier/kind, prescribed edge, pod age at the event
  wire      Pixie http_events / pgsql_events / conn_stats, aggregated per flow, peers resolved
  scan      kubescape scan failures grouped by fix path (declared evidence)
  probe     the evaluator's own HTTP requests (no token / garbage token / platform token, /metrics)
  content   what a page-serving pod serves: code size, solvers defined, datasets, api paths, auth markers

Discounts (kubelet probe, evaluator, prescribed edge, departed peer, exec-started, tracer) are
declared in adrs.yaml and applied by the engine; this module only computes the facts they need.
"""
import base64, collections, datetime, json, os, re, ssl, subprocess, urllib.error, urllib.parse, urllib.request

CH = os.environ.get("ADR_CH", "")           # http://ingest_writer:changeme-ingest@<clickhouse>:8123
TABLE = "forensic_db.kubescape_logs"
UA = "adr-evaluator/1"                      # the wire adapter drops the evaluator's own requests by this tag
RIG = os.environ.get("ADR_RIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TRACER_PARENTS = {"pem"}                    # Pixie PEM: processes it spawns are not the application's
MUTABLE_TAGS = {"latest", "main", "master", "dev", "stable", "edge", "nightly"}
PLAINTEXT_PORTS = {80, 8000, 8080, 3000, 5432, 6379, 3306, 27017}
HEALTH_PATHS = {"/health", "/healthz", "/readyz", "/livez", "/api/health"}
HTTP_PORTS = (80, 8080, 3000, 8000, 5000, 9000, 443, 8443)
SECRET_ENV = re.compile(r"(PASS|PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|CLIENT_SECRET|DSN|CONNECTION_?STRING)", re.I)
DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_MODULE", "NET_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "BPF", "DAC_READ_SEARCH", "SYS_BOOT", "NET_RAW", "ALL"}
METADATA_IP = "169.254.169.254"
# Paths a rule watches (R0010 sensitive files, R0008 environ, R0006 the token): a profile wildcard
# above one of them is acceptable only when the profile also subtracts it.
PROTECTED_PATHS = ["/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/root/.ssh/id_rsa", "/proc/1/environ"]
TOKEN_PATHS = ["/var/run/secrets/kubernetes.io/serviceaccount/token", "/run/secrets/kubernetes.io/serviceaccount/token"]
# platform-granted exceptions: ConfigMap <ADR_EXCEPTIONS_NS>/<ADR_EXCEPTIONS_NAME>, data key "<namespace>/<workload>" (or "<namespace>/*"),
# value "ADR-0018=<reason>; ADR-0016=<reason>". Only the platform writes it; the application cannot exempt itself.
EXCEPTIONS_NS = os.environ.get("ADR_EXCEPTIONS_NS", "sbob-library")
EXCEPTIONS_NAME = os.environ.get("ADR_EXCEPTIONS_NAME", "adr-exceptions")
INGRESS_NAMESPACES = {"traefik", "ingress-nginx", "istio-system", "istio-ingress", "envoy-gateway-system", "nginx-gateway", "kong", "tailscale", "tailscale-system"}
# content markers (regexes over the client code a frontend serves) come from adrs.yaml
# (content_markers) so the ADR declares them; these are the fallback.
CODE_MARKERS = {
    "client_state":    r"\b(localStorage|sessionStorage|indexedDB)\b",
    "backend_calls":   r"\b(fetch\(|XMLHttpRequest|WebSocket|EventSource|axios)\b",
    "auth":            r"\b(Authorization|Bearer|login|signin|oauth|openid|jwt|csrf)\b",
}
_NOVERIFY = ssl.create_default_context(); _NOVERIFY.check_hostname = False; _NOVERIFY.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------- plumbing

def ch(sql):
    u = urllib.parse.urlparse(CH)
    q = urllib.parse.urlencode({"user": u.username, "password": u.password})
    req = urllib.request.Request(f"{u.scheme}://{u.hostname}:{u.port}/?{q}", data=sql.encode())
    return urllib.request.urlopen(req, timeout=120).read().decode()


def ch_rows(sql):
    return [json.loads(l) for l in ch(sql + " FORMAT JSONEachRow").splitlines() if l.strip()]


def kget(args, items=True):
    r = subprocess.run(["kubectl"] + args + ["-o", "json"], capture_output=True, text=True)
    o = json.loads(r.stdout or "{}")
    return o.get("items", []) if items else o


def ts(v):
    if not v:
        return None
    v = v.replace("Z", "+00:00")
    if "." in v:  # trim sub-microsecond digits python cannot parse
        head, tail = v.split(".", 1)
        frac = re.match(r"\d+", tail).group(0)
        v = f"{head}.{frac[:6]}{tail[len(frac):]}"
    return datetime.datetime.fromisoformat(v).timestamp()


def http(url, method="GET", headers=None, timeout=5):
    """status, bytes, headers, body — never raises; status None = unreachable."""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_NOVERIFY if url.startswith("https") else None) as r:
            body = r.read()
            return r.status, len(body), dict(r.headers), body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, 0, dict(e.headers), ""
    except Exception as e:
        return None, 0, {"error": str(e)}, ""


# ---------------------------------------------------------------- the snapshot

class Evidence:
    def __init__(self, ns, since, until, scan=None, live=True, warmup_s=210, markers=None):
        self.ns, self.since, self.until, self.scan_path, self.warmup_s = ns, since, until, scan, warmup_s
        self.markers = markers or CODE_MARKERS
        self.events = {k: [] for k in ("pod", "spec", "svc", "ingress", "netpol", "profile", "secret", "rbac",
                                       "runtime", "wire", "scan", "scan_present", "probe", "content", "metrics")}
        self.notes = []
        self._cluster()
        self._exceptions()
        self._pods()
        self._network_objects()
        self._profiles()
        self._secrets()
        self._rbac()
        self._runtime()
        self._wire()
        self._scan()
        if live:
            self._content()
            self._probes()
            self._metrics()

    @classmethod
    def static(cls, ns):
        """The cluster-side snapshot only (pods, specs, network objects, exceptions): no ClickHouse, no probes.
        Used by the traffic driver and load.sh to find the application's entry point."""
        ev = cls.__new__(cls)
        ev.ns, ev.since, ev.until, ev.scan_path, ev.warmup_s = ns, 0, int(datetime.datetime.now().timestamp()), None, 0
        ev.markers, ev.notes = CODE_MARKERS, []
        ev.events = {k: [] for k in ("pod", "spec", "svc", "ingress", "netpol", "profile", "secret", "rbac",
                                     "runtime", "wire", "scan", "scan_present", "probe", "content", "metrics")}
        ev._cluster(); ev._exceptions(); ev._pods(); ev._network_objects()
        return ev

    # ---- cluster-wide lookups
    def _cluster(self):
        self.node_ips, self.pod_cidrs = set(), []
        for n in kget(["get", "ciliumnodes"]):
            self.node_ips |= {a.get("ip") for a in n.get("spec", {}).get("addresses", [])}
            self.pod_cidrs += n.get("spec", {}).get("ipam", {}).get("podCIDRs", []) or []
        for n in kget(["get", "nodes"]):
            self.node_ips |= {a.get("address") for a in n.get("status", {}).get("addresses", [])}
        self.node_ips -= {None}
        self.evaluator_ips = set(subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split())
        # every pod in the cluster: peer resolution across namespaces (IdP, monitoring, ingress …)
        self.all_pods = {}
        for p in kget(["get", "pods", "-A"]):
            ip = p.get("status", {}).get("podIP")
            if ip and p["status"].get("phase") == "Running":
                self.all_pods[ip] = {"pod": p["metadata"]["name"], "ns": p["metadata"]["namespace"],
                                     "tier": p["metadata"].get("labels", {}).get("app.kubernetes.io/tier")}

    def in_pod_cidr(self, ip):
        import ipaddress
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in ipaddress.ip_network(c) for c in self.pod_cidrs)

    def peer(self, ip, port=None):
        """kind, pod, tier, namespace for an address the application talked to."""
        if not ip:
            return "", None, None, None
        if ip == METADATA_IP:
            return "metadata", None, None, None
        if ip in self.evaluator_ips:
            return "evaluator", None, None, None
        if ip in self.node_ips:
            return "node", None, None, None
        if ip in self.pod_ip:
            m = self.pod_ip[ip]
            return "pod", m["pod"], m["tier"], self.ns
        if ip in self.all_pods:
            m = self.all_pods[ip]
            return ("ingress" if m["ns"] in INGRESS_NAMESPACES else "pod"), m["pod"], f"ns:{m['ns']}", m["ns"]
        if self.in_pod_cidr(ip):
            return ("departed" if self.departed else "unknown"), None, None, None
        return "external", None, None, None

    # ---- platform-granted exceptions
    def _exceptions(self):
        self.exceptions = {}
        cm = kget(["-n", EXCEPTIONS_NS, "get", "configmap", EXCEPTIONS_NAME], items=False)
        for key, val in (cm.get("data") or {}).items():
            d = {}
            for part in str(val).split(";"):
                if "=" in part:
                    k, v = part.split("=", 1); d[k.strip()] = v.strip()
            self.exceptions[key.strip()] = d
        if self.exceptions:
            self.notes.append(f"platform exceptions read from {EXCEPTIONS_NS}/{EXCEPTIONS_NAME}: {sorted(self.exceptions)}")

    # ---- pods and containers
    def _pods(self):
        self.pods = [p for p in kget(["-n", self.ns, "get", "pods"]) if p["status"].get("phase") == "Running"]
        self.pod_ip, self.pod_meta = {}, {}
        self.templates, self.declared = {}, {}
        for kind in ("deploy", "sts", "ds"):
            for w in kget(["-n", self.ns, "get", kind]):
                self.templates[w["metadata"]["name"]] = w["spec"]["template"]
                la = w["metadata"].get("annotations", {}).get("kubectl.kubernetes.io/last-applied-configuration")
                self.declared[w["metadata"]["name"]] = json.loads(la)["spec"]["template"] if la else None
        profiles = {p["metadata"]["name"] for p in kget(["-n", self.ns, "get", "containerprofiles.spdx.softwarecomposition.kubescape.io"])}
        self.profile_names = profiles
        rules = self.kyverno_image_rules()
        for p in self.pods:
            md, st, sp = p["metadata"], p["status"], p["spec"]
            lb = md.get("labels", {})
            name, tier, prof = md["name"], lb.get("app.kubernetes.io/tier"), lb.get("kubescape.io/user-defined-profile")
            owner = self.owner(name)
            start = ts(st.get("startTime"))
            imgs = ",".join(c["image"] for c in sp["containers"])
            by_image = [r for r, rx in rules if re.match(rx, imgs)]
            decl = self.declared.get(owner) if owner else None
            declared_tier = ((decl or {}).get("metadata", {}).get("labels", {}) or {}).get("app.kubernetes.io/tier") if decl else None
            if declared_tier:
                assigned_by = "declared"
            elif by_image:
                assigned_by = "image"
            elif tier == "unclassified":
                assigned_by = "unclassified"
            elif tier:
                assigned_by = "port"
            else:
                assigned_by = "none"
            probe_ports = set()
            for c in sp["containers"]:
                named = {pt.get("name"): pt.get("containerPort") for pt in c.get("ports", []) or []}
                for k in ("livenessProbe", "readinessProbe", "startupProbe"):
                    pr = c.get(k) or {}
                    hg, tcp = pr.get("httpGet"), pr.get("tcpSocket")
                    if hg or tcp:
                        port = (hg or tcp).get("port")
                        probe_ports.add(str(named.get(port, port)))
            exc = {**self.exceptions.get(f"{self.ns}/*", {}), **self.exceptions.get(f"{self.ns}/{owner or name}", {})}
            ev = {"pod": name, "workload": owner or name, "tier": tier, "profile": prof, "bound": prof in profiles,
                  "service_account": sp.get("serviceAccountName", "default"), "exceptions": exc,
                  "ip": st.get("podIP"), "node": sp.get("nodeName"), "start": start,
                  "age_s": int(self.until - start) if start else None, "warm": bool(start) and (self.until - start) >= self.warmup_s,
                  "declared_known": decl is not None, "declared_tier": declared_tier, "assigned_by": assigned_by,
                  "image_known": bool(by_image), "images": imgs.split(","), "probe_ports": sorted(probe_ports),
                  "http_port": self.http_port(p), "labels": lb}
            self.events["pod"].append(ev)
            self.pod_ip[ev["ip"]] = ev
            self.pod_meta[name] = ev
            running = {cs["name"]: cs for cs in st.get("containerStatuses", [])}
            vols = {v["name"]: v for v in sp.get("volumes", []) or []}
            for c in sp["containers"]:
                sc = c.get("securityContext") or {}
                psc = sp.get("securityContext") or {}
                caps_add = (sc.get("capabilities") or {}).get("add") or []
                img = c["image"]
                last = img.split("/")[-1]
                tag = last.split(":", 1)[1].split("@")[0] if ":" in last.split("@")[0] else None
                res = c.get("resources") or {}
                caps = (sc.get("capabilities") or {}).get("drop") or []
                self.events["spec"].append({
                    "pod": name, "workload": owner or name, "container": c["name"], "tier": tier,
                    "image": img, "pinned": "@sha256:" in img, "tag": tag, "mutable_tag": tag in MUTABLE_TAGS or tag is None,
                    "pull_policy": c.get("imagePullPolicy", "IfNotPresent"),
                    "running_digest": (running.get(c["name"], {}).get("imageID", "").split("@")[-1] if "@" in running.get(c["name"], {}).get("imageID", "") else None),
                    "port_names": [pt.get("name") for pt in c.get("ports", []) or []],
                    "ports": [pt.get("containerPort") for pt in c.get("ports", []) or []],
                    "has_metrics_port": any((pt.get("name") or "") == "metrics" for cc in sp["containers"] for pt in cc.get("ports", []) or []),  # per pod: a sidecar exporter counts
                    "host_ports": [pt["hostPort"] for pt in c.get("ports", []) or [] if pt.get("hostPort")],
                    "host_network": bool(sp.get("hostNetwork")),
                    "run_as_non_root": sc.get("runAsNonRoot", psc.get("runAsNonRoot")),
                    "run_as_user": sc.get("runAsUser", psc.get("runAsUser")),
                    "allow_priv_esc": sc.get("allowPrivilegeEscalation"),
                    "read_only_root": sc.get("readOnlyRootFilesystem"),
                    "caps_drop_all": "ALL" in caps,
                    "seccomp": (sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type"),
                    "automount_sa": sp.get("automountServiceAccountToken", True),
                    "has_liveness": bool(c.get("livenessProbe")), "has_readiness": bool(c.get("readinessProbe")),
                    "exec_probe": any((c.get(k) or {}).get("exec") for k in ("livenessProbe", "readinessProbe", "startupProbe")),
                    "privileged": bool(sc.get("privileged")), "host_pid": bool(sp.get("hostPID")), "host_ipc": bool(sp.get("hostIPC")),
                    "caps_add": caps_add, "caps_add_dangerous": sorted(set(caps_add) & DANGEROUS_CAPS),
                    "host_path_mounts": [f"{m['mountPath']}<-{vols[m['name']]['hostPath']['path']}" for m in c.get("volumeMounts", []) or []
                                         if m.get("name") in vols and vols[m["name"]].get("hostPath")],
                    "runtime_socket": any(re.search(r"(docker|containerd|crio)\.sock", vols[m["name"]]["hostPath"]["path"]) for m in c.get("volumeMounts", []) or []
                                          if m.get("name") in vols and vols[m["name"]].get("hostPath")),
                    "env_literal_secrets": [e["name"] for e in c.get("env", []) or [] if SECRET_ENV.search(e.get("name", "")) and "value" in e and e["value"]],
                    "env_secret_refs": sorted({(e.get("valueFrom") or {}).get("secretKeyRef", {}).get("name") for e in c.get("env", []) or []
                                               if (e.get("valueFrom") or {}).get("secretKeyRef")} |
                                              {(ef.get("secretRef") or {}).get("name") for ef in c.get("envFrom", []) or [] if ef.get("secretRef")}),
                    "secret_volumes": sorted({vols[m["name"]]["secret"]["secretName"] for m in c.get("volumeMounts", []) or []
                                              if m.get("name") in vols and vols[m["name"]].get("secret")}),
                    "service_account": sp.get("serviceAccountName", "default"), "exceptions": exc,
                    "writable_mounts": [m["mountPath"] for m in c.get("volumeMounts", []) or [] if not m.get("readOnly")],
                    "image_overlays": [m["mountPath"] for m in c.get("volumeMounts", []) or [] if not m.get("readOnly")
                                       and re.match(r"^/(usr|bin|sbin|lib|lib64|opt|app|srv|etc)(/|$)", m["mountPath"])],
                    "has_requests": bool((res.get("requests") or {}).get("cpu")) and bool((res.get("requests") or {}).get("memory")),
                    "has_limits": bool((res.get("limits") or {}).get("cpu")) and bool((res.get("limits") or {}).get("memory")),
                })

    def owner(self, pod_name):
        for name in sorted(self.templates, key=len, reverse=True):
            if pod_name.startswith(name + "-"):
                return name
        return None

    def http_port(self, pod):
        ports = [pt.get("containerPort") for c in pod["spec"]["containers"] for pt in c.get("ports", []) or []]
        return next((p for p in ports if p in HTTP_PORTS), ports[0] if ports else None)

    def scheme_of(self, pod, port):
        for c in pod["spec"]["containers"]:
            for pt in c.get("ports", []) or []:
                if pt.get("containerPort") == port and (pt.get("name") or "").lower() in ("https", "tls", "ssl"):
                    return "https"
            for k in ("livenessProbe", "readinessProbe", "startupProbe"):
                hg = (c.get(k) or {}).get("httpGet") or {}
                if hg.get("port") == port and hg.get("scheme") == "HTTPS":
                    return "https"
        return "https" if port in (443, 8443) else "http"

    # ---- services, ingresses, network policies
    def _network_objects(self):
        for s in kget(["-n", self.ns, "get", "svc"]):
            ports = [p.get("port") for p in s["spec"].get("ports", [])]
            self.events["svc"].append({
                "name": s["metadata"]["name"], "type": s["spec"].get("type", "ClusterIP"), "ports": ports,
                "node_ports": [p.get("nodePort") for p in s["spec"].get("ports", []) if p.get("nodePort")],
                "plaintext_ports": [p for p in ports if p in PLAINTEXT_PORTS],
                "exposed": s["spec"].get("type") in ("NodePort", "LoadBalancer"),
                "selector": s["spec"].get("selector") or {}})
        frontend_svcs = set()
        for e in self.events["svc"]:
            sel = e["selector"]
            if sel and any(all(p["labels"].get(k) == v for k, v in sel.items()) and p["tier"] == "frontend" for p in self.events["pod"]):
                frontend_svcs.add(e["name"])
        objs = []
        for i in kget(["-n", self.ns, "get", "ingress"]):
            sp = i["spec"]
            objs.append({"kind": "Ingress", "name": i["metadata"]["name"], "tls": bool(sp.get("tls")),
                         "hosts": [r.get("host") for r in sp.get("rules", []) if r.get("host")],
                         "services": [pa["backend"]["service"]["name"] for r in sp.get("rules", []) for pa in (r.get("http") or {}).get("paths", []) if (pa.get("backend") or {}).get("service")]})
        for i in kget(["-n", self.ns, "get", "ingressroutes.traefik.io"]):
            sp = i["spec"]
            objs.append({"kind": "IngressRoute", "name": i["metadata"]["name"], "tls": bool(sp.get("tls")) or "websecure" in (sp.get("entryPoints") or []),
                         "hosts": sorted({h for r in sp.get("routes", []) for h in re.findall(r"Host\(`([^`]+)`\)", r.get("match", ""))}),
                         "services": [sv["name"] for r in sp.get("routes", []) for sv in r.get("services", [])]})
        gateways = {}
        for g in kget(["get", "gateways.gateway.networking.k8s.io", "-A"]):
            gateways[(g["metadata"]["namespace"], g["metadata"]["name"])] = any(l.get("protocol") == "HTTPS" for l in g["spec"].get("listeners", []))
        for i in kget(["-n", self.ns, "get", "httproutes.gateway.networking.k8s.io"]):
            sp = i["spec"]
            parents = [(pr.get("namespace", self.ns), pr.get("name")) for pr in sp.get("parentRefs", [])]
            objs.append({"kind": "HTTPRoute", "name": i["metadata"]["name"], "tls": any(gateways.get(pr, False) for pr in parents) or None,
                         "hosts": sp.get("hostnames", []), "services": [b["name"] for r in sp.get("rules", []) for b in r.get("backendRefs", [])]})
        # a Service exposed through the tailscale operator is the platform ingress on this platform (tailnet endpoint,
        # MagicDNS name, TLS when the Service port itself is TLS); no Ingress object is involved
        for sv in kget(["-n", self.ns, "get", "svc"]):
            ann = sv["metadata"].get("annotations") or {}
            if ann.get("tailscale.com/expose") == "true" or ann.get("tailscale.com/hostname"):
                ports = sv["spec"].get("ports", [])
                tls = any(p.get("port") in (443, 8443) or (p.get("name") or "").lower() in ("https", "tls") for p in ports)
                host = ann.get("tailscale.com/hostname") or sv["metadata"]["name"]
                lb = [i.get("hostname") for i in (sv.get("status", {}).get("loadBalancer", {}).get("ingress") or []) if i.get("hostname")]
                objs.append({"kind": "TailscaleService", "name": sv["metadata"]["name"], "tls": tls, "hosts": lb or [host],
                             "services": [sv["metadata"]["name"]], "exposed_on": "tailnet",
                             "tags": [t for t in (ann.get("tailscale.com/tags") or "").split(",") if t.strip()]})
        for o in objs:
            o["fronts_frontend"] = any(sv in frontend_svcs for sv in o["services"])
            o["scope"] = "object"
            self.events["ingress"].append(o)
        fronting = [o for o in objs if o["fronts_frontend"]]
        self.events["ingress"].append({"kind": "namespace", "name": self.ns, "scope": "namespace", "objects": len(objs),
                                       "fronts_frontend": bool(fronting), "tls": all(o["tls"] for o in fronting) if fronting else None,
                                       "hosts": sorted({h for o in fronting for h in o["hosts"]}), "frontend_services": sorted(frontend_svcs)})
        pols = kget(["-n", self.ns, "get", "netpol"])
        deny_in = deny_out = False
        for np_ in pols:
            sp = np_["spec"]; types = sp.get("policyTypes") or ["Ingress"]
            all_pods = not sp.get("podSelector")
            di = all_pods and "Ingress" in types and not sp.get("ingress")
            do = all_pods and "Egress" in types and not sp.get("egress")
            deny_in, deny_out = deny_in or di, deny_out or do
            self.events["netpol"].append({"name": np_["metadata"]["name"], "scope": "policy", "selects_all": all_pods,
                                          "policy_types": types, "default_deny_ingress": di, "default_deny_egress": do,
                                          "ingress_rules": len(sp.get("ingress") or []), "egress_rules": len(sp.get("egress") or [])})
        import ipaddress
        meta = ipaddress.ip_address(METADATA_IP)
        allows_meta = False
        for np_ in pols:
            for rule in (np_["spec"].get("egress") or []):
                tos = rule.get("to") or []
                if not tos:
                    allows_meta = True  # allow-all egress rule
                for t in tos:
                    ib = t.get("ipBlock")
                    if ib and meta in ipaddress.ip_network(ib["cidr"], strict=False) and not any(meta in ipaddress.ip_network(x, strict=False) for x in ib.get("except", [])):
                        allows_meta = True
        self.events["netpol"].append({"name": self.ns, "scope": "namespace", "policies": len(pols), "pods": len(self.pods),
                                      "default_deny_ingress": deny_in, "default_deny_egress": deny_out,
                                      "default_deny": deny_in and deny_out,
                                      "metadata_api_blocked": deny_out and not allows_meta})

    # ---- profiles and the admission policy
    @staticmethod
    def _covers(pattern, path):
        """True when a profile path (⋯ = one segment, * = any rest) matches a concrete path."""
        rx = "^" + "/".join(".*" if s == "*" else "[^/]+" if s == "⋯" else re.escape(s) for s in pattern.split("/")) + "$"
        return re.match(rx, path) is not None

    def _profiles(self):
        wild = re.compile(r"^(/etc|/run|/var/run)/(⋯|\*)$|^/(⋯|\*)$")
        for name in sorted(self.profile_names):
            full = kget(["-n", self.ns, "get", "containerprofiles.spdx.softwarecomposition.kubescape.io", name], items=False)
            spec = full.get("spec", {}) or {}
            opens = [o.get("path", "") for o in spec.get("opens", []) or []]
            subtracted = [o.get("path", "") for o in (spec.get("subtract") or {}).get("opens", []) or []]
            toks = [p for p in opens if "serviceaccount" in p]
            tier = name[5:] if name.startswith("tier-") else None
            watched = PROTECTED_PATHS + ([] if tier == "backend" else TOKEN_PATHS)
            exposed = {w: [q for q in watched if self._covers(w, q) and not any(self._covers(s, q) for s in subtracted)]
                       for w in opens if wild.search(w)}
            exposed = {w: qs for w, qs in exposed.items() if qs}
            self.events["profile"].append({
                "name": name, "tier": tier,
                "opens": len(opens), "execs": len(spec.get("execs", []) or []), "subtracted_opens": len(subtracted),
                "wildcard_paths": sorted(exposed), "wildcards": len(exposed),
                "unsubtracted_paths": sorted({q for qs in exposed.values() for q in qs}),
                "token_paths": toks, "token_concrete": all(p.endswith("/token") for p in toks) if toks else None,
                "has_egress": bool(spec.get("egress")), "has_ingress": bool(spec.get("ingress")),
                "signed": bool((full.get("metadata", {}).get("annotations") or {}).get("kubescape.io/signature"))})

    def kyverno_image_rules(self):
        if hasattr(self, "_kyv"):
            return self._kyv
        self._kyv, self._kyv_port_rules = [], []
        pol = kget(["get", "clusterpolicy", "assign-workload-tier"], items=False)
        rules = pol.get("spec", {}).get("rules", [])
        if not rules:  # fall back to the rig's file
            try:
                import yaml
                for f in sorted(os.listdir(os.path.join(RIG, "kyverno"))):
                    if f.startswith("02"):
                        for doc in yaml.safe_load_all(open(os.path.join(RIG, "kyverno", f))):
                            rules += (doc or {}).get("spec", {}).get("rules", [])
            except Exception:
                pass
        for r in rules:
            keys = " ".join(str(pc.get("key", "")) for pc in (r.get("preconditions") or {}).get("all", []))
            if "ports" in keys and "image" not in r.get("name", ""):
                self._kyv_port_rules.append(r.get("name"))
                continue
            m = re.search(r"regex_match\('([^']+)',\s*imgs\)", keys)
            if m and "by-image" in r.get("name", ""):
                self._kyv.append((r.get("name"), m.group(1)))
        return self._kyv

    # ---- Secrets of the namespace: who references them, how, how old
    def _secrets(self):
        refs = {}
        for e in self.events["spec"]:
            for n in e["env_secret_refs"]:
                refs.setdefault(n, {"workloads": set(), "tiers": set(), "env": True, "volume": False})["workloads"].add(e["workload"]); refs[n]["tiers"].add(e["tier"])
            for n in e["secret_volumes"]:
                r = refs.setdefault(n, {"workloads": set(), "tiers": set(), "env": False, "volume": True}); r["workloads"].add(e["workload"]); r["tiers"].add(e["tier"]); r["volume"] = True
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        for sec in kget(["-n", self.ns, "get", "secrets"]):
            t = sec.get("type", "")
            if t.startswith("helm.sh/") or t == "kubernetes.io/service-account-token":
                continue
            name = sec["metadata"]["name"]
            r = refs.get(name, {"workloads": set(), "tiers": set(), "env": False, "volume": False})
            age = int((now - (ts(sec["metadata"].get("creationTimestamp")) or now)) / 86400)
            self.events["secret"].append({"name": name, "type": t, "age_days": age, "keys": sorted((sec.get("data") or {}).keys()),
                                          "referenced_by": sorted(r["workloads"]), "ref_count": len(r["workloads"]), "shared": len(r["workloads"]) > 1,
                                          "tiers": sorted(x for x in r["tiers"] if x), "cross_tier": len({x for x in r["tiers"] if x}) > 1,
                                          "via_env": r["env"], "via_volume": r["volume"], "referenced": bool(r["workloads"])})

    # ---- RBAC: what each running pod's ServiceAccount can do
    def _rbac(self):
        roles = {("Role", r["metadata"]["name"]): r.get("rules", []) for r in kget(["-n", self.ns, "get", "roles"])}
        roles.update({("ClusterRole", r["metadata"]["name"]): r.get("rules", []) for r in kget(["get", "clusterroles"])})
        bindings = []
        for b in kget(["-n", self.ns, "get", "rolebindings"]):
            bindings.append((b, False))
        for b in kget(["get", "clusterrolebindings"]):
            bindings.append((b, True))
        sas = {}
        for p in self.events["pod"]:
            sas.setdefault(p["service_account"], set()).add(p["workload"])
        for sa, workloads in sorted(sas.items()):
            ev = {"service_account": sa, "workloads": sorted(workloads), "workload": ", ".join(sorted(workloads)), "is_default": sa == "default",
                  "bindings": [], "cluster_scoped": False, "admin": False, "wildcard_verbs": False, "wildcard_resources": False,
                  "secrets_read": False, "exec": False, "escalate": False, "delete": False, "rules": 0}
            for b, cluster in bindings:
                if not any(sub.get("kind") == "ServiceAccount" and sub.get("name") == sa and sub.get("namespace", self.ns) == self.ns for sub in b.get("subjects") or []):
                    continue
                rr = b["roleRef"]; ev["bindings"].append(f"{'ClusterRoleBinding' if cluster else 'RoleBinding'}/{b['metadata']['name']}->{rr['kind']}/{rr['name']}")
                ev["cluster_scoped"] |= cluster
                ev["admin"] |= rr["name"] in ("cluster-admin", "admin", "edit")
                for rule in roles.get((rr["kind"], rr["name"]), []):
                    ev["rules"] += 1
                    verbs, res = set(rule.get("verbs", [])), set(rule.get("resources", []))
                    ev["wildcard_verbs"] |= "*" in verbs
                    ev["wildcard_resources"] |= "*" in res or "*" in set(rule.get("apiGroups", []) or [])
                    ev["secrets_read"] |= ("secrets" in res or "*" in res) and bool(verbs & {"get", "list", "watch", "*"})
                    ev["exec"] |= bool(res & {"pods/exec", "pods/portforward", "pods/attach"}) or ("*" in res and bool(verbs & {"create", "*"}))
                    ev["escalate"] |= bool(verbs & {"escalate", "bind", "impersonate"}) or (("*" in res) and ("*" in verbs))
                    ev["delete"] |= bool(verbs & {"delete", "deletecollection"}) or "*" in verbs
            ev["has_bindings"] = bool(ev["bindings"])
            ev["overscoped"] = ev["admin"] or ev["wildcard_verbs"] or ev["wildcard_resources"] or ev["secrets_read"] or ev["exec"] or ev["escalate"]
            self.events["rbac"].append(ev)

    # ---- runtime detections
    def _runtime(self):
        self.raw_rows = 0
        self.rules_seen = []
        self.departed = set()
        self.cluster_name = os.environ.get("ADR_CLUSTER") or subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True).stdout.strip()
        if not CH:
            self.notes.append("ADR_CH unset: no runtime evidence")
            return
        rows = ch_rows(f"""
            SELECT RuleID, event_time, hostname, message, BaseRuntimeMetadata brm, RuntimeK8sDetails k8s, RuntimeProcessDetails proc
            FROM {TABLE}
            WHERE event_time BETWEEN {self.since * 10**9} AND {self.until * 10**9}
              AND JSONExtractString(RuntimeK8sDetails, 'namespace') = '{self.ns}'
            ORDER BY event_time""")
        self.raw_rows = len(rows)
        self.rules_seen = sorted({r["RuleID"] for r in rows})
        self.cluster_name = next((json.loads(r["k8s"] or "{}").get("clusterName") for r in rows if r.get("k8s")), None) or self.cluster_name
        for r in rows:
            for k in ("brm", "k8s", "proc"):
                r[k] = json.loads(r[k] or "{}")
        self.departed = {r["k8s"].get("podName") for r in rows if r["k8s"].get("podName")} - set(self.pod_meta)
        seen = {}
        for r in rows:
            k8s, brm, pt = r["k8s"], r["brm"], (r["proc"].get("processTree") or {})
            pod = k8s.get("podName")
            meta = self.pod_meta.get(pod)
            if not meta:
                continue  # a pod that is gone: not the code running now
            when = ts(brm.get("timestamp")) or int(r["event_time"]) / 1e9
            if meta["start"] and when < meta["start"]:
                continue  # predates the pod it is attributed to
            args = brm.get("arguments") or {}
            idf = brm.get("identifiers") or {}
            rule = r["RuleID"]
            key = (rule, pod, r["message"])
            if key in seen:
                seen[key]["count"] += 1
                seen[key]["last"] = brm.get("timestamp")
                continue
            peer_ip, peer_port, direction = None, None, ""
            if rule in ("R0011", "R0012"):
                peer_ip, peer_port = args.get("ip") or (idf.get("network") or {}).get("dstIP"), args.get("port") or (idf.get("network") or {}).get("dstPort")
                direction = "egress" if rule == "R0011" else "ingress"
            kind, ppod, ptier, pns = self.peer(peer_ip, peer_port)
            if direction == "egress" and str(peer_port) == "53":
                kind, ptier = "dns", "dns"
            ev = {
                "rule": rule, "rule_name": brm.get("alertName"), "severity": brm.get("severity"),
                "pod": pod, "workload": meta["workload"], "container": k8s.get("containerName"), "tier": meta["tier"],
                "node": r["hostname"], "profile": (brm.get("profileMetadata") or {}).get("name"),
                "image": k8s.get("image"), "image_digest": k8s.get("imageDigest"),
                "process": pt.get("comm") or (idf.get("process") or {}).get("name"), "pcomm": pt.get("pcomm"),
                "cmdline": pt.get("cmdline"), "pid": pt.get("pid"),
                "message": r["message"], "timestamp": brm.get("timestamp"), "last": brm.get("timestamp"),
                "event_time": int(r["event_time"]), "uid": brm.get("uniqueID"), "count": 1,
                "pod_age_s": int(when - meta["start"]) if meta["start"] else None,
                "direction": direction, "peer_ip": peer_ip, "peer_port": str(peer_port) if peer_port is not None else None,
                "peer_kind": kind, "peer_pod": ppod, "peer_tier": ptier, "peer_ns": pns,
                "kubelet_probe": kind == "node" and str(peer_port) in meta["probe_ports"],
                "domain": args.get("domain"), "path": args.get("path"), "exec": args.get("exec"),
                "capability": args.get("capability"), "exceptions": meta["exceptions"],
            }
            if direction:
                a, b = (ev["tier"], ptier) if direction == "egress" else (ptier, ev["tier"])
                ev["edge"] = [a, b]
            seen[key] = ev
        self.events["runtime"] = list(seen.values())

    # ---- Pixie wire rows
    def _wire(self):
        if not CH:
            return
        s, u = self.since, self.until
        sql = f"""
        SELECT 'http' proto, pod, trace_role, remote_addr, local_port, encrypted, req_method method, req_path path, resp_status status,
               count() c, max(req_headers LIKE '%{UA}%') evaluator, max(req_headers LIKE '%adr-driver/%') driver,
               anyIf(extract(req_headers, '"[Xx]-[Tt]est-[Cc]ase":"([^"]+)"'), req_headers LIKE '%est-%ase%') test_case
        FROM forensic_db.http_events WHERE namespace='{self.ns}' AND time_ BETWEEN fromUnixTimestamp64Nano({s}000000000) AND fromUnixTimestamp64Nano({u}000000000)
        GROUP BY ALL
        UNION ALL
        SELECT 'pgsql', pod, trace_role, remote_addr, local_port, encrypted, '', substring(req,1,40), 0, count(), 0, 0, ''
        FROM forensic_db.pgsql_events WHERE namespace='{self.ns}' AND time_ BETWEEN fromUnixTimestamp64Nano({s}000000000) AND fromUnixTimestamp64Nano({u}000000000)
        GROUP BY ALL
        UNION ALL
        SELECT 'conn', pod, trace_role, remote_addr, remote_port, ssl, '', '', 0, count(), 0, 0, ''
        FROM forensic_db.conn_stats WHERE namespace='{self.ns}' AND time_ BETWEEN fromUnixTimestamp64Nano({s}000000000) AND fromUnixTimestamp64Nano({u}000000000)
        GROUP BY ALL"""
        try:
            rows = ch_rows(sql)
        except Exception as e:
            self.notes.append(f"wire evidence unavailable: {e}")
            return
        for r in rows:
            pod = r["pod"].split("/")[-1]
            meta = self.pod_meta.get(pod)
            if not meta:
                continue
            ip = r["remote_addr"]
            if ip in ("127.0.0.1", "::1"):
                continue
            kind, ppod, ptier, pns = self.peer(ip)
            if kind not in ("pod", "ingress"):   # a proxied request keeps the client's User-Agent; the hop is still pod->pod
                if int(r["driver"] or 0):
                    kind = "driver"      # the browser stand-in / k6: application traffic, from outside the cluster pods
                elif int(r["evaluator"] or 0):
                    kind = "evaluator"
            server = int(r["trace_role"]) == 2
            src_pod, src_tier, dst_pod, dst_tier = (ppod, ptier, pod, meta["tier"]) if server else (pod, meta["tier"], ppod, ptier)
            self.events["wire"].append({
                "proto": r["proto"], "pod": pod, "workload": meta["workload"], "tier": meta["tier"], "role": "server" if server else "client",
                "src_pod": src_pod, "src_tier": src_tier, "dst_pod": dst_pod, "dst_tier": dst_tier,
                "remote_ip": ip, "remote_kind": kind, "remote_ns": pns, "port": int(r["local_port"]),
                "encrypted": int(r["encrypted"]), "method": r["method"], "path": r["path"], "status": int(r["status"]), "count": int(r["c"]),
                "kubelet_probe": kind == "node" and server and str(r["local_port"]) in meta["probe_ports"],
                "health_path": r["path"] in HEALTH_PATHS,
                "via_ingress": kind == "ingress", "egress_external": (not server) and kind == "external",
                "test_case": r.get("test_case") or "", "exceptions": meta["exceptions"],
                "edge": [src_tier, dst_tier],
            })

    # ---- kubescape scan (declared)
    def _scan(self):
        self.scan_present = False
        self.events["scan_present"] = [{"name": "kubescape scan", "present": False, "path": self.scan_path}]
        p = self.scan_path
        if not p or not os.path.exists(p):
            self.notes.append("no kubescape scan supplied: static controls not evaluated")
            return
        try:
            data = json.load(open(p))
        except Exception as e:
            self.notes.append(f"scan not readable: {e}")
            return
        self.scan_present = True
        self.events["scan_present"] = [{"name": "kubescape scan", "present": True, "path": p}]
        mine = {self.ns} | set(self.templates)
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        grouped = {}
        for r in (data if isinstance(data, list) else data.get("results", [])):
            short = r.get("resourceID", "").split("/")[-1]
            if short not in mine:
                continue
            for c in r.get("controls", []):
                if c.get("status", {}).get("status") != "failed":
                    continue
                for rule in c.get("rules", []):
                    for path in rule.get("paths") or []:
                        fp = path.get("fixPath") or {}
                        fpath, fval = fp.get("path"), fp.get("value")
                        if not fpath:
                            fpath, fval = path.get("failedPath"), "<remove>"
                        if not fpath:
                            continue
                        key = re.sub(r"\[\d+\]", "[*]", fpath)
                        g = grouped.setdefault((c.get("controlID"), key), {"control": c.get("controlID"), "name": c.get("name", ""),
                                                                        "path": key, "values": set(), "resources": set(), "severity": c.get("severity", "Low")})
                        g["values"].add(str(fval)); g["resources"].add(short)
        for g in grouped.values():
            vals = {v for v in g["values"] if v not in ("None", "")}
            self.events["scan"].append({
                "control": g["control"], "name": g["name"], "path": g["path"], "severity": g["severity"],
                "resources": sorted(g["resources"]), "workload": ", ".join(sorted(g["resources"])),
                "value": sorted(vals)[0] if vals and "YOUR_VALUE" not in vals and vals != {"<remove>"} else None,
                "action": "remove" if vals == {"<remove>"} else "set",
                "agent_can_apply": bool(vals) and "YOUR_VALUE" not in vals and vals != {"<remove>"},
            })
        self.events["scan"].sort(key=lambda e: (sev_rank.get(e["severity"], 9), e["control"]))

    # ---- served content (page-serving pods)
    def _content(self):
        for p in self.pods:
            meta = self.pod_meta[p["metadata"]["name"]]
            port = meta["http_port"]
            if not port or meta["tier"] not in ("frontend", None, "unclassified"):
                continue
            scheme = self.scheme_of(p, port)
            st, n, hdr, body = http(f"{scheme}://{meta['ip']}:{port}/", timeout=10)
            # a page is what the server says is HTML, or what looks like it (fragments without <html> included)
            is_html = (hdr.get("Content-Type", "") or "").lower().startswith("text/html") or any(t in (body or "").lower() for t in ("<html", "<!doctype", "<script"))
            if st is None or not body or not is_html:
                self.events["content"].append({"pod": meta["pod"], "workload": meta["workload"], "tier": meta["tier"], "serves_page": False, "status": st})
                continue
            scripts = "".join(re.findall(r"<script[^>]*>(.*?)</script>", body, re.S))
            ext = re.findall(r'<script[^>]+src="([^"]+)"', body)
            loaded = {}
            for src in ext:
                if "://" not in src:
                    _, _, _, b = http(f"{scheme}://{meta['ip']}:{port}/{src.lstrip('/')}", timeout=10)
                    loaded[src] = b or ""
            scripts += "".join(loaded.values())
            markers = {k: len(re.findall(rx, scripts)) for k, rx in self.markers.items()}
            fns = re.findall(r"function\s+([A-Za-z_]\w*)", scripts)
            api_paths = sorted({m for m in re.findall(r"['\"`](/api/[A-Za-z0-9_/.-]*)['\"`]", scripts)})
            self.events["content"].append({
                "pod": meta["pod"], "workload": meta["workload"], "tier": meta["tier"], "serves_page": True, "status": st,
                "bytes": len(body), "js_bytes": len(scripts), "js_kb": len(scripts) // 1024, "scripts": list(loaded),
                "functions": len(set(fns)), "api_paths": api_paths, "n_api_paths": len(api_paths),
                **{f"marker_{k}": v for k, v in markers.items()},
                "backend_calls": markers.get("backend_calls", 0), "auth_markers": markers.get("auth", 0), "client_state": markers.get("client_state", 0),
            })

    # ---- component load from the metrics ports (the counters the ADRs' metrics ports expose)
    COUNTERS = {"http_requests_total": "requests", "nginx_http_requests_total": "requests", "http_server_requests_total": "requests",
                "redis_commands_processed_total": "commands", "pg_stat_database_xact_commit": "commits", "process_cpu_seconds_total": "cpu_s"}

    def _metrics(self):
        for p in self.pods:
            meta = self.pod_meta[p["metadata"]["name"]]
            ports = [pt.get("containerPort") for c in p["spec"]["containers"] for pt in c.get("ports", []) or [] if (pt.get("name") or "") == "metrics"]
            for port in ports:
                st, n, _, body = http(f"http://{meta['ip']}:{port}/metrics", timeout=5)
                counters = {}
                for line in (body or "").splitlines():
                    if line.startswith("#") or not line.strip():
                        continue
                    name = re.split(r"[ {]", line, 1)[0]
                    if name in self.COUNTERS:
                        try:
                            counters[self.COUNTERS[name]] = counters.get(self.COUNTERS[name], 0.0) + float(line.rsplit(" ", 1)[-1])
                        except ValueError:
                            pass
                self.events["metrics"].append({"pod": meta["pod"], "workload": meta["workload"], "tier": meta["tier"], "port": port,
                                               "status": st, "series": sum(1 for l in (body or "").splitlines() if l and not l.startswith("#")),
                                               **{k: int(v) for k, v in counters.items()}})

    # ---- the evaluator's own probes
    def idp_token(self):
        r = subprocess.run(["kubectl", "-n", self.ns, "get", "secret", "idp-client", "-o", "json"], capture_output=True, text=True)
        sec = (json.loads(r.stdout or "{}").get("data") or {}) if r.returncode == 0 else {}
        if not sec:
            return None, "no idp-client secret in the namespace: platform-token probe skipped"
        d = {k: base64.b64decode(v).decode() for k, v in sec.items()}
        url = d["token_endpoint"]
        m = re.match(r"(https?://)([^/:]+)\.([^/:.]+)\.svc(?:\.cluster\.local)?(:\d+)?(/.*)?$", url)
        if m:  # <svc>.<ns>.svc does not resolve from a node: swap in the ClusterIP
            ip = kget(["-n", m.group(3), "get", "svc", m.group(2)], items=False).get("spec", {}).get("clusterIP")
            if ip:
                url = f"{m.group(1)}{ip}{m.group(4) or ''}{m.group(5) or ''}"
        scope = "openid urn:zitadel:iam:org:project:id:" + d.get("project_id", "") + ":aud" if d.get("project_id") else "openid"
        try:
            req = urllib.request.Request(url, data=f"grant_type=client_credentials&scope={scope}".encode(),
                                         headers={"Host": "localhost:8080", "User-Agent": UA,
                                                  "Authorization": "Basic " + base64.b64encode(f"{d['client_id']}:{d['client_secret']}".encode()).decode()})
            return json.loads(urllib.request.urlopen(req, timeout=10).read()).get("access_token"), "platform token minted"
        except Exception as e:
            return None, f"platform token not minted: {e}"

    def vantages(self, meta, pod):
        port = meta["http_port"]
        yield meta["ip"], port, self.scheme_of(pod, port), None
        if len(self.events["netpol"]) > 1 and meta["tier"] in ("backend", "middleware"):
            for fe in self.pods:
                fm = self.pod_meta[fe["metadata"]["name"]]
                if fm["tier"] == "frontend" and fm["http_port"]:
                    yield fm["ip"], fm["http_port"], self.scheme_of(fe, fm["http_port"]), fm["pod"]

    def _probes(self):
        paths = sorted({pp for c in self.events["content"] for pp in c.get("api_paths", [])} - HEALTH_PATHS)
        token, token_note = None, None
        for p in self.pods:
            meta = self.pod_meta[p["metadata"]["name"]]
            if meta["tier"] not in ("backend", "middleware", "database") or not meta["http_port"]:
                continue
            if meta["tier"] == "database":
                continue
            if token is None and token_note is None:
                token, token_note = self.idp_token()
                self.notes.append(token_note)
            chosen = None
            for ip, port, scheme, via in self.vantages(meta, p):
                if any(http(f"{scheme}://{ip}:{port}{path}")[0] is not None for path in (paths or ["/"])[:3]):
                    chosen = (ip, port, scheme, via); break
            base = {"pod": meta["pod"], "workload": meta["workload"], "tier": meta["tier"]}
            if not chosen:
                self.events["probe"].append({**base, "reachable": False, "path": None, "auth": "none", "status": None, "via": None})
                continue
            ip, port, scheme, via = chosen
            for path in (paths or ["/"])[:8] + ["/metrics"]:
                st, n, _, _ = http(f"{scheme}://{ip}:{port}{path}")
                self.events["probe"].append({**base, "reachable": True, "url": f"{scheme}://{ip}:{port}{path}", "path": path,
                                             "auth": "none", "status": st, "bytes": n, "via": via, "route": st not in (None, 404)})
                if path == "/metrics" or st in (None, 404) or st < 400:
                    continue
                st2, _, _, _ = http(f"{scheme}://{ip}:{port}{path}", headers={"Authorization": "Bearer not.a.token"})
                self.events["probe"].append({**base, "reachable": True, "url": f"{scheme}://{ip}:{port}{path}", "path": path,
                                             "auth": "garbage", "status": st2, "via": via, "route": True})
                if token:
                    st3, _, _, _ = http(f"{scheme}://{ip}:{port}{path}", headers={"Authorization": f"Bearer {token}"})
                    self.events["probe"].append({**base, "reachable": True, "url": f"{scheme}://{ip}:{port}{path}", "path": path,
                                                 "auth": "valid", "status": st3, "via": via, "route": True})

    # ---- summary for the report
    def source_summary(self):
        return {"clickhouse": urllib.parse.urlparse(CH).hostname if CH else None, "table": TABLE,
                "window": {"from": self.since, "to": self.until, "seconds": self.until - self.since},
                "rows": self.raw_rows, "rules_seen": getattr(self, "rules_seen", []),
                "wire_rows": sum(e["count"] for e in self.events["wire"]),
                "test_cases": sorted({e["test_case"] for e in self.events["wire"] if e.get("test_case")}),
                "component_load": [{k: e.get(k) for k in ("workload", "tier", "port", "status", "series", "requests", "commands", "commits") if e.get(k) is not None} for e in self.events["metrics"]],
                "edges_seen": sorted({f"{e['src_tier']}->{e['dst_tier']}" for e in self.events["wire"] if e.get("src_tier") and e.get("dst_tier") and e["remote_kind"] in ("pod", "driver", "ingress")}),
                "static": "static controls from " + self.scan_path if self.scan_present else "no kubescape scan supplied",
                "warmup_s": self.warmup_s, "notes": self.notes,
                "counts": {k: len(v) for k, v in self.events.items()}}
