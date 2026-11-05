#!/usr/bin/env python3
"""
Generic ADR evaluator: adrs.yaml predicates over evidence.Evidence events.

  python3 engine.py <namespace> [--since EPOCH] [--until EPOCH] [--scan FILE] [--out kpi.json] [--no-live]

Report schema adr-kpi/v2: per ADR a status (VIOLATED | COMPLIANT | NOT_OBSERVED), the findings
(each with counted / note / owner), and a proof: one line per observed-predicate plus the
violated-predicate scope. Nothing per-ADR is in this file.
"""
import argparse, collections, datetime, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yaml
import evidence

SPEC_PATH = os.environ.get("ADR_SPEC", os.path.join(os.path.dirname(os.path.abspath(__file__)), "adrs.yaml"))
RESERVED = {"source", "broken", "fix", "owner", "min", "max", "what", "counted", "note", "name", "show", "group_by",
            "tiers", "unattributed", "min_age_s"}


def load_spec(path=SPEC_PATH):
    return yaml.safe_load(open(path))


# ---------------------------------------------------------------- filters

def _match_value(have, want):
    if isinstance(want, dict):
        for op, arg in want.items():
            if op == "not":
                if have in (arg if isinstance(arg, list) else [arg]):
                    return False
            elif op == "in":
                if have not in arg:
                    return False
            elif op == "gt":
                if have is None or not have > arg: return False
            elif op == "ge":
                if have is None or not have >= arg: return False
            elif op == "lt":
                if have is None or not have < arg: return False
            elif op == "le":
                if have is None or not have <= arg: return False
            elif op == "regex":
                if have is None or not re.search(arg, str(have)): return False
            elif op == "empty":
                if bool(have) == bool(arg): return False
            else:
                raise ValueError(f"unknown filter op {op}")
        return True
    if isinstance(want, list):
        return have in want
    return have == want


def matches(ev, pred):
    for k, want in pred.items():
        if k in RESERVED:
            continue
        if not _match_value(ev.get(k), want):
            return False
    return True


# ---------------------------------------------------------------- rendering

def render(ev, pred):
    """What was observed, from the event: the filter keys the predicate used plus `show`."""
    src = pred["source"]
    if src == "runtime":
        head = ev.get("message") or ""
        extra = [f"{k}={ev.get(k)}" for k in pred.get("show", []) if ev.get(k) not in (None, "", [])]
        tail = f" x{ev['count']}" if ev.get("count", 1) > 1 else ""
        return head + tail + (f" [{', '.join(extra)}]" if extra else "")
    keys = [k for k in pred if k not in RESERVED] + list(pred.get("show", []))
    seen, parts = set(), []
    for k in keys:
        if k in seen or k not in ev:
            continue
        seen.add(k)
        v = ev[k]
        if isinstance(v, (list, dict)):
            v = json.dumps(v)
        parts.append(f"{k}={v}")
    return ", ".join(parts)


def subject(ev, src):
    return ev.get("workload") or ev.get("pod") or ev.get("name") or ev.get("container") or src


# ---------------------------------------------------------------- the engine

class Engine:
    def __init__(self, spec, ev: evidence.Evidence):
        self.spec, self.ev = spec, ev
        topo = [tuple(e) for e in spec.get("topology", [])]
        for e in ev.events["runtime"]:
            edge = e.get("edge")
            e["edge_prescribed"] = bool(edge) and any((a in ("*", edge[0])) and (b in ("*", edge[1])) for a, b in topo)
        self._apply_discounts()

    def _apply_discounts(self):
        for d in self.spec.get("discounts", []):
            for src in d.get("source", []):
                for e in self.ev.events.get(src, []):
                    if e.get("discount"):
                        continue
                    if matches(e, d):
                        e["discount"] = d["name"]
                        e["note"] = d.get("note", "")
                        e["owner"] = d.get("owner", "application")
                        e["unattributed"] = bool(d.get("unattributed"))

    def coverage(self, pred):
        pods = self.ev.events["pod"]
        tiers = pred.get("tiers")
        mine = [p for p in pods if not tiers or p["tier"] in tiers]
        min_age = pred.get("min_age_s", self.spec.get("warmup_s", 210))
        governed = [p for p in mine if p["bound"] and p["tier"]]
        warm = [p for p in governed if p["age_s"] is not None and p["age_s"] >= min_age]
        alive = self.ev.raw_rows > 0
        ok = bool(mine) and len(governed) == len(mine) and len(warm) == len(mine) and alive
        youngest = min((p["age_s"] for p in mine if p["age_s"] is not None), default=None)
        txt = (f"{pred.get('what', 'coverage')}: {len(governed)}/{len(mine)} pod(s) governed"
               + (f" (tiers {', '.join(sorted({p['tier'] for p in mine if p['tier']}))})" if mine else " (no pods in these tiers)")
               + (f", youngest {youngest}s vs warm-up {min_age}s" if youngest is not None else "")
               + f", sensor rows in window: {self.ev.raw_rows}")
        return ok, txt

    def observed(self, pred):
        if pred["source"] == "coverage":
            return self.coverage(pred)
        evs = [e for e in self.ev.events.get(pred["source"], []) if matches(e, pred)]
        n = sum(e.get("count", 1) for e in evs) if pred["source"] in ("wire",) else len(evs)
        ok = n >= pred.get("min", 1) and (pred.get("max") is None or n <= pred["max"])
        txt = f"{pred.get('what', pred['source'])}: {n}"
        gb = pred.get("group_by")
        if gb and evs:
            c = collections.Counter(tuple(json.dumps(e.get(k)) if isinstance(e.get(k), (list, dict)) else e.get(k) for k in gb) for e in evs)
            txt += " [" + "; ".join(" ".join(f"{k}={v}" for k, v in zip(gb, key)) + f" ×{m}" for key, m in sorted(c.items(), key=lambda x: -x[1])[:8]) + "]"
        if not ok:
            txt += f" (needs ≥{pred.get('min', 1)})"
        return ok, txt

    def findings(self, adr):
        out = []
        for pred in adr.get("violated", []):
            src = pred["source"]
            for e in self.ev.events.get(src, []):
                if not matches(e, pred):
                    continue
                counted = pred.get("counted", True) and not e.get("discount")
                exc = (e.get("exceptions") or {}).get(adr["id"]) if isinstance(e.get("exceptions"), dict) else None
                if exc and counted:
                    counted = False
                    e = {**e, "discount": "platform_exception", "note": f"platform-granted exception ({evidence.EXCEPTIONS_NS}/{evidence.EXCEPTIONS_NAME}): {exc}", "owner": "platform"}
                f = {"adr": adr["id"], "source": src,
                     "evidence_class": "observed" if src in ("runtime", "wire", "probe", "content") else "declared",
                     "workload": subject(e, src), "container": e.get("container"), "tier": e.get("tier"),
                     "rule": e.get("rule"), "rule_name": e.get("rule_name"), "severity": e.get("severity"),
                     "process": e.get("process"), "node": e.get("node"),
                     "decision_broken": pred["broken"], "observed": render(e, pred), "fix": pred["fix"],
                     "owner": e.get("owner") or pred.get("owner", "application"),
                     "counted": counted, "note": e.get("note", "") if e.get("discount") else ("" if counted else pred.get("note", "informational, not counted")),
                     "unattributed": bool(e.get("unattributed")),
                     "timestamp": e.get("timestamp"), "count": e.get("count", 1),
                     "evidence": self._ref(e, src)}
                out.append(f)
        # dedupe identical findings (same ADR, subject, text)
        seen, uniq = set(), []
        for f in out:
            k = (f["decision_broken"], f["workload"], f["observed"])
            if k not in seen:
                seen.add(k); uniq.append(f)
        uniq.sort(key=lambda f: (not f["counted"], f["evidence_class"] != "observed", f["workload"]))
        return uniq

    def _ref(self, e, src):
        if src == "runtime":
            return {"table": evidence.TABLE, "rows": e.get("count", 1), "profile": e.get("profile"), "image": e.get("image"),
                    "uniqueID": e.get("uid"), "first": e.get("timestamp"), "last": e.get("last")}
        if src == "wire":
            return {"table": f"forensic_db.{e['proto']}_events" if e["proto"] != "conn" else "forensic_db.conn_stats", "rows": e.get("count", 1)}
        if src == "scan":
            return {"scan": self.ev.scan_path, "control": e.get("control"), "resources": e.get("resources")}
        return {"source": src}

    def evaluate(self):
        adrs = []
        for a in self.spec["adrs"]:
            fs = self.findings(a)
            counted = [f for f in fs if f["counted"]]
            proof_lines, all_ok = [], True
            for pred in a.get("observed", []):
                ok, txt = self.observed(pred)
                all_ok = all_ok and ok
                proof_lines.append(("✓ " if ok else "✗ ") + txt)
            if counted:
                status = "VIOLATED"
            elif any(f["unattributed"] for f in fs):
                status = "NOT_OBSERVED"
                proof_lines.append("✗ evidence present that cannot be attributed to a live pod")
            elif all_ok:
                status = "COMPLIANT"
            else:
                status = "NOT_OBSERVED"
            disc = collections.Counter(f["note"].split(";")[0][:60] for f in fs if not f["counted"])
            if fs:
                proof_lines.append(f"findings: {len(counted)} counted, {len(fs) - len(counted)} discounted"
                                   + (" (" + "; ".join(f"{n}× {k}" for k, n in disc.items()) + ")" if disc else ""))
            adrs.append({"id": a["id"], "summary": a["summary"], "title": a["title"],
                         "verified_by": ", ".join(a.get("enforced_by", [])),
                         "status": status, "proof": " | ".join(proof_lines), "violations": len(counted), "findings": fs})
        counts = collections.Counter(x["status"] for x in adrs)
        pods = self.ev.events["pod"]
        return {
            "schema": "adr-kpi/v2",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "cluster": self.ev.cluster_name,
            "namespace": self.ev.ns,
            "source": self.ev.source_summary(),
            "summary": {"adrs": len(adrs), "violated": counts["VIOLATED"], "compliant": counts["COMPLIANT"],
                        "not_observed": counts["NOT_OBSERVED"],
                        "coverage": {"pods": len(pods), "governed": sum(1 for p in pods if p["bound"] and p["tier"]),
                                     "warm": sum(1 for p in pods if p["warm"]), "watched": self.ev.raw_rows > 0}},
            "kpis": [{"kpi": x["id"], "summary": x["summary"], "status": x["status"], "compliant": x["status"] == "COMPLIANT",
                      "violations": x["violations"]} for x in adrs],
            "adrs": adrs,
            "workloads": [{k: p[k] for k in ("pod", "workload", "tier", "profile", "bound", "ip", "node", "age_s", "warm",
                                             "declared_tier", "assigned_by", "image_known", "images")} for p in pods],
            "content": self.ev.events["content"],
            "broken_before_anything_else": [f"{p['pod']}: unbound profile {p['profile']}" for p in pods if not p["bound"]]
                                           + [f"{p['pod']}: no tier label" for p in pods if not p["tier"]],
        }


def evaluate(namespace, since, until, scan=None, live=True, spec_path=SPEC_PATH):
    spec = load_spec(spec_path)
    ev = evidence.Evidence(namespace, since, until, scan=scan, live=live, warmup_s=spec.get("warmup_s", 210),
                           markers=spec.get("content_markers"))
    return Engine(spec, ev).evaluate()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("namespace")
    ap.add_argument("--since", type=int, default=int(time.time()) - 3600)
    ap.add_argument("--until", type=int, default=int(time.time()))
    ap.add_argument("--scan")
    ap.add_argument("--out")
    ap.add_argument("--no-live", action="store_true", help="skip HTTP probes and page reads")
    a = ap.parse_args()
    r = evaluate(a.namespace, a.since, a.until, a.scan, live=not a.no_live)
    print(f"{a.namespace}  " + "  ".join(f"{x['id']}={x['status']}({x['violations']})" for x in r["adrs"]))
    if a.out:
        json.dump(r, open(a.out, "w"), indent=1, default=str)
        print("wrote", a.out)


if __name__ == "__main__":
    main()
