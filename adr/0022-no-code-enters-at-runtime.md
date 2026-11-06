# ADR-0022 — Nothing is downloaded, installed or compiled after the container starts; the image is the only source of code

**Status:** proposed  
**Applies to:** every pod in an application namespace  
**Enforced by:** sbob.exec, sbob.egress, netpol

## Decision

The image is the only source of code. Nothing is downloaded, installed or compiled after the container starts; no package manager, downloader or compiler runs; no egress reaches a package registry or code host.

## Why

A supply chain that is verified at build time is undone by one pip install at runtime. The runtime sensor reports every process that is not in the profile and every egress to an unexpected address; the names of package managers and registries are enough to tell the two cases apart.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **coverage** — every pod carries a tier label, is bound to a profile that exists, is older than the warm-up (210 s), and the sensor reported at least one event for the namespace in the window.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **a package manager, downloader or compiler ran inside the container** — the runtime sensor saw a process the profile does not list was launched or a process ran with arguments the profile does not list — process ~ ^(pip3?|npm|npx|yarn|pnpm|apk|apt|apt-get|dpkg|yum|dnf|gem|cargo|go|curl|wget|git|make|gcc|cc)$.
* **egress to a package or code source at runtime** — the runtime sensor saw an outbound connection the tier profile does not allow — peer external, domain ~ (pypi|pythonhosted|npmjs|yarnpkg|rubygems|crates\.io|proxy\.golang|github\.com|githubusercontent|alpinelinux|debian\.org|ubuntu\.com|docker\.io|ghcr\.io|quay\.io).
* **egress to an external address that is not a declared processor or platform service** *(informational, not counted)* — the runtime sensor saw an outbound connection the tier profile does not allow — peer external, domain empty, not a kubelet probe.

## How to fix

* a package manager, downloader or compiler ran inside the container: install at build time; the runtime image carries no package manager
* egress to a package or code source at runtime: no runtime fetches; vendor at build time
* egress to an external address that is not a declared processor or platform service: default-deny egress; allow only the prescribed edges

## Reproduce without the tooling

```bash
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0001', 'R0011', 'R0040') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| runtime | R0001 / R0040 | a package manager, downloader or compiler ran inside the container |
| runtime | R0011 | egress to a package or code source at runtime |
| runtime | R0011 | egress to an external address that is not a declared processor or platform service |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
