#!/usr/bin/env python3
"""
drive.py <namespace> [rounds]   — exercise the application the way a browser would, so the
prescribed edges carry traffic before the ADRs are judged (COMPLIANT needs observed flows).

For every page-serving pod (tier=frontend): GET /, every same-origin script, and every /api
path the page references, through the frontend (as the browser does). Tagged User-Agent
adr-driver/1: these rows ARE application traffic (browser -> frontend -> backend -> database)
and count; only the evaluator's own probes (adr-evaluator/1) are discounted.
"""
import os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence

UA = "adr-driver/1"


def main():
    ns, rounds = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3
    ev = evidence.Evidence.__new__(evidence.Evidence)
    ev.ns, ev.since, ev.until, ev.scan_path, ev.warmup_s = ns, 0, int(time.time()), None, 0
    ev.events = {k: [] for k in ("pod", "spec", "svc", "ingress", "netpol", "profile", "policy", "runtime", "wire", "scan", "scan_present", "probe", "content")}
    ev.markers, ev.definition_markers = evidence.CODE_MARKERS, evidence.DEFINITION_MARKERS
    ev.notes = []
    ev._cluster(); ev._pods()
    hits = 0
    for p in ev.pods:
        meta = ev.pod_meta[p["metadata"]["name"]]
        if meta["tier"] != "frontend" or not meta["http_port"]:
            continue
        base = f"{ev.scheme_of(p, meta['http_port'])}://{meta['ip']}:{meta['http_port']}"
        for _ in range(rounds):
            st, n, _, body = evidence.http(base + "/", headers={"User-Agent": UA}, timeout=10)
            hits += 1
            print(f"GET {base}/ -> {st} {n}B")
            if not body:
                continue
            paths = [s for s in re.findall(r'<script[^>]+src="([^"]+)"', body) if "://" not in s]
            paths += sorted({m for m in re.findall(r"['\"`](/api/[A-Za-z0-9_/.-]*)['\"`]", body)})
            for s in paths:
                st, n, _, b = evidence.http(f"{base}/{s.lstrip('/')}", headers={"User-Agent": UA}, timeout=10)
                hits += 1
                print(f"GET {base}/{s.lstrip('/')} -> {st} {n}B")
                if s.endswith(".js") and b:  # api paths referenced from loaded scripts
                    for m in sorted({m for m in re.findall(r"['\"`](/api/[A-Za-z0-9_/.-]*)['\"`]", b)}):
                        st, n, _, _ = evidence.http(f"{base}{m}", headers={"User-Agent": UA}, timeout=10)
                        hits += 1
                        print(f"GET {base}{m} -> {st} {n}B")
            time.sleep(1)
    print(f"{hits} requests")


if __name__ == "__main__":
    main()
