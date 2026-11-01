#!/usr/bin/env python3
"""
ADR compliance KPI from ClickHouse.

Same evaluator as the rig's review.py (ADR_MAP, corroboration, folding, liveness
filter), different source: forensic_db.kubescape_logs instead of alertmanager. The
rows node-agent wrote through dx -> AE are the evidence; nothing is read from logs.

    ./adr_kpi.py vibe-app --since 1792712100 --out kpi.json

Status per ADR:
  VIOLATED      at least one observed finding (or a failed mechanical check)
  COMPLIANT     no finding, and the sensor was demonstrably watching the namespace
  NOT_OBSERVED  no finding, but no row from the namespace in the window either
"""
import argparse, collections, datetime, importlib.util, json, os, re, subprocess, sys, time
import urllib.parse, urllib.request

RIG = os.environ.get("ADR_RIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CH = os.environ["ADR_CH"]  # http://ingest_writer:changeme-ingest@<clickhouse-host>:8123
TABLE = "forensic_db.kubescape_logs"
PLATFORM_PARENTS = {"pem"}  # Pixie PEM
EVALUATOR_IPS = set(subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split())

ADRS = [
    ("ADR-0001", "Tiers are strictly layered; the presentation tier never reaches the data tier", "runtime R0011+R0012"),
    ("ADR-0002", "The data tier never initiates outbound connections", "runtime R0011"),
    ("ADR-0003", "The presentation tier holds no cluster credentials", "runtime R0006/R0010 (+ C-0034 static)"),
    ("ADR-0004", "Images are immutable at runtime; nothing is installed after build", "runtime R0001/R0005/R0011"),
    ("ADR-0005", "Every workload declares its tier; an undeclared one is quarantined", "kyverno admission + runtime on tier-unclassified"),
    ("ADR-0006", "Workloads run as non-root", "runtime R0004 (+ C-0013/16/17/46 static)"),
    ("ADR-0007", "A profile may not wildcard above a path another rule protects", "mechanical check of stored ContainerProfiles"),
    # proposed set: vibe-monolith -> production
    ("ADR-0008", "The presentation tier serves presentation only", "content probe + runtime (zero egress, R0002)"),
    ("ADR-0009", "A tier is declared, never guessed", "admission: pod label vs manifest, kyverno regexes"),
    ("ADR-0010", "Every backend request is authenticated by the platform IdP (ZITADEL)", "live probe 401 + content OIDC markers"),
    ("ADR-0011", "No plaintext on the wire", "Pixie http_events/pgsql_events encrypted=0 (+ static Service/Ingress)"),
    ("ADR-0012", "Metrics on a dedicated port, scraped only by the platform", "live probe /metrics + static port named metrics + http_events"),
    ("ADR-0013", "Every workload declares its envelope: resources, probes, securityContext", "static C-0004/9/50/268-271, C-0018/56, C-0055/210/211"),
    ("ADR-0014", "Images are pinned by digest, signed; no latest", "static image string (+ C-0236/C-0237)"),
    ("ADR-0015", "Ingress is the platform's: no NodePort/hostPort, NetworkPolicy present", "static Service type, hostPort, netpol count (+ C-0030/C-0260/C-0044)"),
]
STATIC_ONLY = {"ADR-0013"}  # evaluated from the kubescape scan alone
WILDCARD = re.compile(r"^(/etc|/run|/var/run)/(⋯|\*)$|^/(⋯|\*)$")


def load_review():
    here = os.path.dirname(os.path.abspath(__file__))
    path = next(p for p in (os.path.join(RIG, "review.py"), os.path.join(here, "review.py")) if os.path.exists(p))
    spec = importlib.util.spec_from_file_location("review", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ch(sql):
    u = urllib.parse.urlparse(CH)
    q = urllib.parse.urlencode({"user": u.username, "password": u.password})
    req = urllib.request.Request(f"{u.scheme}://{u.hostname}:{u.port}/?{q}", data=sql.encode())
    return urllib.request.urlopen(req, timeout=60).read().decode()


def rows(ns, since, until):
    sql = f"""
    SELECT RuleID, event_time, hostname, message,
           BaseRuntimeMetadata AS brm, RuntimeK8sDetails AS k8s, RuntimeProcessDetails AS proc
    FROM {TABLE}
    WHERE event_time BETWEEN {since * 10**9} AND {until * 10**9}
      AND JSONExtractString(RuntimeK8sDetails, 'namespace') = '{ns}'
    ORDER BY event_time FORMAT JSONEachRow"""
    out = []
    for line in ch(sql).splitlines():
        r = json.loads(line)
        for k in ("brm", "k8s", "proc"):
            r[k] = json.loads(r[k] or "{}")
        out.append(r)
    return out


def as_alert(r):
    """kubescape_logs row -> the alertmanager shape review.runtime_findings consumes."""
    brm, k8s, pt = r["brm"], r["k8s"], (r["proc"].get("processTree") or {})
    return {
        "labels": {
            "namespace": k8s.get("namespace"), "rule_id": r["RuleID"],
            "rule_name": brm.get("alertName"), "severity": str(brm.get("severity", "")),
            "pod_name": k8s.get("podName"), "container_name": k8s.get("containerName"),
            "node_name": r["hostname"], "comm": pt.get("comm"), "pid": str(pt.get("pid", "")),
        },
        "annotations": {"message": r["message"]},
        "startsAt": brm.get("timestamp"),
        "_ref": {
            "unique_id": brm.get("uniqueID"), "event_time": int(r["event_time"]),
            "profile": (brm.get("profileMetadata") or {}).get("name"),
            "tier": (k8s.get("podLabels") or {}).get("app.kubernetes.io/tier"),
            "image": k8s.get("image"), "image_digest": k8s.get("imageDigest"),
            "cmdline": pt.get("cmdline"), "pcomm": pt.get("pcomm"), "comm": pt.get("comm"),
        },
    }


def attach_evidence(findings, alerts):
    idx = collections.defaultdict(list)
    for a in alerts:
        l = a["labels"]
        idx[(l["rule_id"], l["pod_name"], a["annotations"]["message"])].append(a["_ref"])
    for f in findings:
        refs = idx.get((f["rule"], f["workload"], f["observed"]), [])
        f["evidence"] = {"table": TABLE, "rows": len(refs), "profile": refs[0]["profile"] if refs else None,
                         "image": refs[0]["image"] if refs else None,
                         "first": refs[0]["unique_id"] if refs else None,
                         "last": refs[-1]["unique_id"] if refs else None,
                         "cmdline": refs[0]["cmdline"] if refs else None, "parent": refs[0]["pcomm"] if refs else None}
        # The tracer (Pixie PEM) execs `<runtime> --version` inside a container to pick its
        # uprobes. A process whose parent is the tracer is the platform's, not the app's.
        # An exec probe enters the container through runc; runc's own capability use
        # (CAP_SYS_ADMIN) and file reads are the probe's, not the service's.
        if f["rule"] in ("R0004", "R0002") and refs and str(refs[0]["comm"]).startswith("runc:["):
            f["cause"] = "kubelet exec probe (runc entering the container)"
            f["fix"] = "the exec probe enters the container through runc, which uses CAP_SYS_ADMIN and reads /proc; use a tcpSocket or httpGet probe instead"
        # A process whose parent is the container runtime's shim was started by `kubectl exec`
        # or an exec probe — the manifest's probe, not the image's entrypoint.
        if f["rule"] == "R0001" and refs and refs[0]["pcomm"] == "containerd-shim":
            f["cause"] = "started by exec (kubelet exec probe or kubectl exec), parent containerd-shim"
            f["fix"] = "if this is a probe: use tcpSocket/httpGet instead of exec; if it was kubectl exec: nothing to fix in the image"
        if f["rule"] == "R0001" and refs and refs[0]["pcomm"] in PLATFORM_PARENTS:
            f["owner"] = "platform"
            f["counted"] = False
            f["note"] = f"parent process is {refs[0]['pcomm']} (the tracer); not the application's behaviour"
    return findings


def kget(args):
    return json.loads(subprocess.run(["kubectl"] + args + ["-o", "json"], capture_output=True, text=True).stdout or "{}")


def admission(ns):
    """ADR-0005: every live pod carries a tier and is bound to a profile that exists."""
    pods = kget(["-n", ns, "get", "pods"]).get("items", [])
    profiles = {p["metadata"]["name"] for p in
                kget(["-n", ns, "get", "containerprofiles.spdx.softwarecomposition.kubescape.io"]).get("items", [])}
    undeclared, unbound, quarantined, governed = [], [], [], []
    for p in pods:
        lb = p["metadata"].get("labels", {})
        tier, prof = lb.get("app.kubernetes.io/tier"), lb.get("kubescape.io/user-defined-profile")
        name = p["metadata"]["name"]
        if not tier:
            undeclared.append(name)
        elif prof not in profiles:
            unbound.append({"pod": name, "profile": prof})
        else:
            governed.append(name)
            if tier == "unclassified":
                quarantined.append(name)
    return undeclared, unbound, quarantined, governed, len(pods)


def profile_review(ns):
    """ADR-0007: read back what the cluster stored, not the files."""
    bad, checked = [], []
    for p in kget(["-n", ns, "get", "containerprofiles.spdx.softwarecomposition.kubescape.io"]).get("items", []):
        name = p["metadata"]["name"]
        # LIST nulls .spec on this storage; GET each object.
        full = kget(["-n", ns, "get", "containerprofiles.spdx.softwarecomposition.kubescape.io", name])
        checked.append(name)
        for o in full.get("spec", {}).get("opens", []) or []:
            if WILDCARD.search(o.get("path", "")):
                bad.append({"profile": name, "path": o["path"]})
    return bad, checked


def evaluate(namespace, since, until, scan=None):
    """scan: optional kubescape JSON (scan.sh output) for the static controls."""
    class A: pass
    a = A(); a.namespace, a.since, a.until = namespace, since, until
    rv = load_review()
    raw = rows(a.namespace, a.since, a.until)
    alerts = [as_alert(r) for r in raw]
    health = rv.workload_health(a.namespace)
    rt, pods = rv.runtime_findings(a.namespace, alerts)
    # Flows the evaluator itself caused (its probes into backend/metrics ports) are
    # not the application's behaviour; drop R0012 whose peer is this host.
    rt = [f for f in rt if not (f.get("rule") == "R0012" and rv.peer_of(f.get("observed"))[0] in EVALUATOR_IPS)]
    # A peer that is no pod now but was one in this window (a pod of this namespace that
    # departed — a rollout) is the old replica talking, not an unknown caller. Keep the
    # finding as a note, not a violation; the IP cannot be tied to the departed pod, so say so.
    departed = {r["k8s"].get("podName") for r in raw if r["k8s"].get("podName")} - {v["pod"] for v in pods.values()}
    kept = []
    import adr_checks
    node_ips = adr_checks.node_addresses()
    probe_ports = {pod: {port for _, port in pp} for pod, pp in adr_checks.probe_targets(adr_checks.Namespace(a.namespace)).items()}
    for f in rt:
        peer, pport = rv.peer_of(f.get("observed"))[:2]
        if f.get("rule") == "R0012" and peer in node_ips and str(pport) in {str(x) for x in probe_ports.get(f["workload"], ())}:
            f["owner"], f["counted"] = "platform", False
            f["cause"] = "kubelet probe from the node's router IP on a port this pod declares as a probe target"
            f["note"] = "the tier profile does not list the probe port — platform (bobctl) learns it; nothing for the application to change"
            kept.append(f); continue
        if f.get("rule") == "R0012" and peer and peer not in pods and departed:
            f["note"] = f"peer {peer} is not a live pod; {len(departed)} pod(s) of this namespace departed in the window ({', '.join(sorted(departed)[:3])}) — rollover traffic, not counted"
            f["counted"] = False
        kept.append(f)
    rt = kept
    rt = attach_evidence(rt, alerts)
    rt = rv.fold_external_egress(rv.dedupe(rv.corroborate(rt, pods)))
    rt.sort(key=lambda f: (0 if f.get("corroborated_by") else 1, f["adr"]))

    undeclared, unbound, quarantined, governed, npods = admission(a.namespace)
    wild, checked = profile_review(a.namespace)
    watched = len(raw) > 0 and npods > 0 and len(governed) == npods

    st, scan_note = [], "no kubescape scan supplied; static controls not evaluated"
    if scan and os.path.exists(scan):
        owners = {a.namespace} | {w["metadata"]["name"] for k in ("deploy", "sts", "ds")
                                  for w in kget(["-n", a.namespace, "get", k]).get("items", [])}
        st, scan_note = rv.compliance_findings(scan, a.namespace, owners)
        st = [f for f in rv.cross_link(st, rt) if f["adr"] != "—"]
        scan_note = scan_note or f"static controls from {scan}"

    by_adr = collections.defaultdict(list)
    for f in rt + st:
        by_adr[f["adr"]].append(f)

    # ADR-0008..0015: architecture verdict + mechanical checks (adr_checks)
    import adr_arch, adr_checks
    arch = adr_arch.architecture(a.namespace, raw, st)
    checks = adr_checks.run(a.namespace, arch, ch, a.since, a.until)
    observed = {}
    for aid, (fs_, seen) in checks.items():
        by_adr[aid].extend(fs_)
        observed[aid] = seen

    adrs = []
    for aid, title, how in ADRS:
        fs = by_adr.get(aid, [])
        note = None
        if aid in STATIC_ONLY and not st:
            note = scan_note
        if aid == "ADR-0005":
            for p in undeclared:
                fs.append({"adr": aid, "source": "admission", "evidence_class": "declared",
                           "workload": p, "decision_broken": "pod carries no app.kubernetes.io/tier label",
                           "observed": f"{p} admitted without a tier label", "fix": "label the workload with app.kubernetes.io/tier"})
            for u in unbound:
                fs.append({"adr": aid, "source": "admission", "evidence_class": "declared",
                           "workload": u["pod"], "decision_broken": "pod points at a profile that does not exist in its namespace",
                           "observed": f"{u['pod']} -> kubescape.io/user-defined-profile={u['profile']} (absent)",
                           "fix": "the workload is unwatched: wait for clone-tier-sbobs or fix the label"})
            if quarantined:
                note = f"quarantined (tier=unclassified, narrow profile): {', '.join(quarantined)}"
        if aid == "ADR-0007":
            for w in wild:
                fs.append({"adr": aid, "source": "profile", "evidence_class": "declared",
                           "workload": w["profile"], "decision_broken": "profile wildcards above a protected path",
                           "observed": f"{w['profile']}: opens {w['path']}", "fix": "narrow the open to the concrete files; bobctl re-collapse"})
            note = f"profiles read back: {', '.join(checked)}"
        if aid in ("ADR-0003", "ADR-0006") and not st:
            note = scan_note
        counted = [x for x in fs if x.get("counted", True)]
        if counted:
            status = "VIOLATED"
        elif aid in checks:
            status = "COMPLIANT" if observed[aid] else "NOT_OBSERVED"
        elif aid in STATIC_ONLY:
            status = "COMPLIANT" if st or (scan and os.path.exists(scan)) else "NOT_OBSERVED"
        elif aid in ("ADR-0005", "ADR-0007") or watched:
            status = "COMPLIANT"
        else:
            status = "NOT_OBSERVED"
        adrs.append({"id": aid, "title": title, "verified_by": how, "status": status,
                     "violations": len(counted), "findings": fs, **({"note": note} if note else {})})

    counts = collections.Counter(x["status"] for x in adrs)
    report = {
        "schema": "adr-kpi/v1",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "cluster": (raw[0]["k8s"].get("clusterName") if raw else None),
        "namespace": a.namespace,
        "source": {"clickhouse": urllib.parse.urlparse(CH).hostname, "table": TABLE,
                   "window": {"from": a.since, "to": a.until}, "rows": len(raw),
                   "rules_seen": sorted({r["RuleID"] for r in raw}), "static": scan_note},
        "_rows": raw,
        "summary": {"adrs": len(adrs), "violated": counts["VIOLATED"], "compliant": counts["COMPLIANT"],
                    "not_observed": counts["NOT_OBSERVED"],
                    "coverage": {"pods": npods, "governed": len(governed), "watched": watched}},
        "kpis": [{"kpi": x["id"], "status": x["status"], "compliant": x["status"] == "COMPLIANT",
                  "violations": x["violations"]} for x in adrs],
        "adrs": adrs,
        "architecture": arch,
        "workloads": [{"pod": m["pod"], "ip": ip, "tier": m["tier"]} for ip, m in pods.items()],
        "broken_before_anything_else": health,
    }
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("namespace")
    ap.add_argument("--since", type=int, default=int(time.time()) - 3600, help="epoch seconds")
    ap.add_argument("--until", type=int, default=int(time.time()))
    ap.add_argument("--out", default="kpi.json")
    ap.add_argument("--scan", help="kubescape scan JSON (scan.sh output)")
    a = ap.parse_args()
    report = evaluate(a.namespace, a.since, a.until, a.scan)
    report.pop("_rows")
    json.dump(report, open(a.out, "w"), indent=2)
    print(f"{a.namespace}  rows={report['source']['rows']}  " +
          "  ".join(f"{x['id']}={x['status']}({x['violations']})" for x in report["adrs"]))
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
