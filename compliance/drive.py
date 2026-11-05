#!/usr/bin/env python3
"""
drive.py <namespace> [rounds]   — exercise the application the way a browser would, so the
prescribed edges carry traffic before the ADRs are judged (COMPLIANT needs observed flows).

Takes the path a browser would: through the platform ingress controller (HTTPS, the host the
ingress/gateway object declares) when one fronts the frontend; otherwise the frontend Service;
only as a last resort the pod IP — and says which. GET /, every same-origin script, every /api
path the page references. Tagged User-Agent adr-driver/1: these rows ARE application traffic
and count (wire remote_kind=driver); only the evaluator's probes (adr-evaluator/1) are discounted.
"""
import os, re, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence

UA = "adr-driver/1"


def get(url, host=None, resolve=None):
    """GET via curl (SNI + Host for the ingress path). Returns status, body."""
    cmd = ["curl", "-sk", "-A", UA, "-m", "15", "-w", "\n%{http_code}", url]
    if host:
        cmd += ["-H", f"Host: {host}"]
    if resolve:
        cmd += ["--resolve", resolve]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    body, _, code = out.rpartition("\n")
    return (int(code) if code.isdigit() else None), body


def main():
    ns, rounds = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3
    ev = evidence.Evidence.__new__(evidence.Evidence)
    ev.ns, ev.since, ev.until, ev.scan_path, ev.warmup_s = ns, 0, int(time.time()), None, 0
    ev.events = {k: [] for k in ("pod", "spec", "svc", "ingress", "netpol", "profile", "runtime", "wire", "scan", "scan_present", "probe", "content")}
    ev.markers = evidence.CODE_MARKERS
    ev.notes = []
    ev._cluster(); ev._pods(); ev._network_objects()
    nsrow = next(e for e in ev.events["ingress"] if e["scope"] == "namespace")
    targets = []   # (base_url, host header, resolve, label)
    if nsrow["fronts_frontend"] and nsrow["hosts"]:
        ctl = None
        for sv in evidence.kget(["get", "svc", "-A"]):
            if sv["metadata"]["namespace"] in evidence.INGRESS_NAMESPACES and any(p.get("port") == 443 for p in sv["spec"].get("ports", [])):
                ctl = sv["spec"].get("clusterIP"); break
        for h in nsrow["hosts"]:
            targets.append((f"https://{h}", None, f"{h}:443:{ctl}" if ctl else None, f"ingress {h} via {ctl}"))
    if not targets:
        for sv in ev.events["svc"]:
            if sv["name"] in nsrow["frontend_services"] and sv["ports"]:
                ip = next(s["spec"].get("clusterIP") for s in evidence.kget(["-n", ns, "get", "svc"]) if s["metadata"]["name"] == sv["name"])
                targets.append((f"http://{ip}:{sv['ports'][0]}", None, None, f"Service {sv['name']} (no ingress object)"))
    if not targets:
        for p in ev.pods:
            meta = ev.pod_meta[p["metadata"]["name"]]
            if meta["tier"] == "frontend" and meta["http_port"]:
                targets.append((f"{ev.scheme_of(p, meta['http_port'])}://{meta['ip']}:{meta['http_port']}", None, None, f"pod {meta['pod']} (no ingress, no Service)"))
    hits = 0
    for base, host, resolve, label in targets:
        print(f"path: {label}")
        for _ in range(rounds):
            st, body = get(base + "/", host, resolve); hits += 1
            print(f"GET {base}/ -> {st} {len(body)}B")
            if not body:
                continue
            paths = [s for s in re.findall(r'<script[^>]+src="([^"]+)"', body) if "://" not in s]
            paths += sorted({m for m in re.findall(r"['\"`](/api/[A-Za-z0-9_/.-]*)['\"`]", body)})
            for s in paths:
                st, b = get(f"{base}/{s.lstrip('/')}", host, resolve); hits += 1
                print(f"GET {base}/{s.lstrip('/')} -> {st} {len(b)}B")
                if s.endswith(".js") and b:
                    for m in sorted({m for m in re.findall(r"['\"`](/api/[A-Za-z0-9_/.-]*)['\"`]", b)}):
                        st, _ = get(f"{base}{m}", host, resolve); hits += 1
                        print(f"GET {base}{m} -> {st}")
            time.sleep(1)
    print(f"{hits} requests")


if __name__ == "__main__":
    main()
