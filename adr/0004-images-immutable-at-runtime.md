# ADR-0004 — Images are immutable at runtime; nothing is installed after build

**Status:** accepted  
**Applies to:** every tier  
**Enforced by:** sbob.execs

## Decision

No package manager and no general-purpose fetch tool executes inside a running container, and nothing that was not part of the container image is executed. Every dependency is resolved at build time and baked into the image.

## Why

Installing at runtime makes the running image unknowable and gives an attacker the tooling they would otherwise have to bring. The decisive signal is drift: a binary executed that the image does not contain. A process the tier profile does not list (a package manager, a fetch tool) is the second signal; it is the noisiest of the set (lowest severity), so the finding names the binary and the engine discounts processes started by exec probes and by the tracer.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **coverage** — every pod carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **a binary that is not part of the container image was executed (drift)** — the runtime sensor saw R1001 — tier not unclassified.
* **a process ran that is not part of the image's declared behaviour** — the runtime sensor saw a process the profile does not list was launched — tier not unclassified.

## How to fix

* a binary that is not part of the container image was executed (drift): nothing is written and executed at runtime; move the installation into the image build
* a process ran that is not part of the image's declared behaviour: if it is a package manager or fetch tool, move the work into the image build

## Reproduce without the tooling

```bash
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0001', 'R1001') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| runtime | R1001 | a binary that is not part of the container image was executed (drift) |
| runtime | R0001 | a process ran that is not part of the image's declared behaviour |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
