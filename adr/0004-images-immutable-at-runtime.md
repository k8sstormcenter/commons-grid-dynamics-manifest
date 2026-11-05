# ADR-0004 — Images are immutable at runtime; nothing is installed after build

**Status:** accepted  
**Applies to:** every tier  
**Enforced by:** kyverno.validate, sbob.execs

## Decision

The container image is mounted read-only (readOnlyRootFilesystem: true) and no writable volume overlays an image path; writable state lives in named emptyDir mounts. No package manager and no general-purpose fetch tool executes inside a running container, and nothing that was not part of the container image is executed. Every dependency is resolved at build time and baked into the image.

## Why

Installing at runtime makes the running image unknowable and gives an attacker the tooling they would otherwise have to bring. The static half is how the image is mounted: read-only, with no writable volume on top of its directories, so there is nowhere to install to. The runtime half is what ran anyway. The decisive runtime signal is drift: a binary executed that the image does not contain. A process the tier profile does not list (a package manager, a fetch tool) is the second signal; it is the noisiest of the set (lowest severity), so the finding names the binary and the engine discounts processes started by exec probes and by the tracer.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **coverage** — every pod carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.
* **containers' root filesystem mode and volume mounts read from the pod spec** — at least 1: a container in the pod spec.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **a binary that is not part of the container image was executed (drift)** — the runtime sensor saw a binary that is not part of the container image was executed — tier not unclassified.
* **a process ran that is not part of the image's declared behaviour** — the runtime sensor saw a process the profile does not list was launched — tier not unclassified.
* **a process was executed from a mounted volume, not from the image** — the runtime sensor saw a process was executed from a mounted volume — tier not unclassified.
* **the image is mounted writable (root filesystem not read-only)** — a container in the pod spec — readOnlyRootFilesystem not true.
* **a writable volume overlays an image path** — a container in the pod spec — a writable volume mounted over an image path.

## How to fix

* a binary that is not part of the container image was executed (drift): nothing is written and executed at runtime; move the installation into the image build
* a process ran that is not part of the image's declared behaviour: if it is a package manager or fetch tool, move the work into the image build
* a process was executed from a mounted volume, not from the image: nothing executable lives on a volume; ship it in the image
* the image is mounted writable (root filesystem not read-only): set securityContext.readOnlyRootFilesystem = true; writable paths as named emptyDir mounts
* a writable volume overlays an image path: mount volumes read-only, or outside the image's directories (/usr, /bin, /lib, /opt, /app, /etc)

## Reproduce without the tooling

```bash
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0001', 'R1001', 'R1004') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| runtime | R1001 | a binary that is not part of the container image was executed (drift) |
| runtime | R0001 | a process ran that is not part of the image's declared behaviour |
| runtime | R1004 | a process was executed from a mounted volume, not from the image |
| spec | readOnlyRootFilesystem not true | the image is mounted writable (root filesystem not read-only) |
| spec | a writable volume mounted over an image path | a writable volume overlays an image path |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
