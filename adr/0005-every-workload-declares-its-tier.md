# ADR-0005 — Every workload declares its tier; an undeclared one is quarantined

**Status:** accepted  
**Applies to:** every pod in an application namespace  
**Enforced by:** kyverno.mutate, clone-tier-sbobs

## Decision

A workload declares its tier in its manifest, or admission assigns one from an image it recognises; either way the pod is bound to that tier's profile. A pod that declares no tier and whose image is not recognised is labelled tier=unclassified and bound to a deliberately narrow profile: DNS egress only, no ingress. Quarantine, not exemption — an unclassified workload that does anything on the network produces a finding whose fix is "tell the platform what this is".

## Why

A workload without a profile is unwatched, and unwatched looks exactly like clean. Admission is a webhook, so the author cannot bypass it, and the classification is visible on the pod's labels immediately. The profile attaches at container start; network enforcement needs the warm-up.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **pods checked at admission (tier label + profile binding)** — at least 1: a running pod.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **pod carries no app.kubernetes.io/tier label** — a running pod — no tier label.
* **an unrecognised image was given a real tier instead of tier=unclassified (admission port fallback)** *(owner: platform)* — a running pod — tier assigned by port.
* **pod points at a profile that does not exist in its namespace (unwatched)** — a running pod — its profile missing in the namespace.
* **the profile binding points nowhere; the container is unwatched** — the runtime sensor saw a profile binding that resolves to nothing.
* **an unclassified workload acted outside the quarantine baseline** — the runtime sensor saw a process the profile does not list was launched or an outbound connection the tier profile does not allow or an inbound connection the tier profile does not allow — tier unclassified.
* **the tier profile does not declare an edge the architecture prescribes, so allowed traffic alerts (platform gap)** *(owner: platform)* — the runtime sensor saw an outbound connection the tier profile does not allow or an inbound connection the tier profile does not allow — on a prescribed edge.

## How to fix

* pod carries no app.kubernetes.io/tier label: label the workload with app.kubernetes.io/tier
* an unrecognised image was given a real tier instead of tier=unclassified (admission port fallback): platform: remove the port-based rules from the admission policy so an unrecognised image lands in quarantine; application: declare app.kubernetes.io/tier
* pod points at a profile that does not exist in its namespace (unwatched): wait for clone-tier-sbobs or fix the kubescape.io/user-defined-profile label
* the profile binding points nowhere; the container is unwatched: platform: clone the tier profile into the namespace
* an unclassified workload acted outside the quarantine baseline: label the workload with app.kubernetes.io/tier so it gets a profile that fits it
* the tier profile does not declare an edge the architecture prescribes, so allowed traffic alerts (platform gap): platform: declare the inter-tier edge (podSelector app.kubernetes.io/tier) in the tier profile egress/ingress (bobctl)

## Notes

Alerts are not de-duplicated by the sensor; the engine collapses identical events and reports the count. File rules fire well before network rules, so "some findings but no network findings" is the signature of a container that is not warm yet, not of a clean posture.

## Reproduce without the tooling

```bash
# pod
kubectl -n <ns> get pods -o custom-columns='POD:.metadata.name,TIER:.metadata.labels.app\.kubernetes\.io/tier,PROFILE:.metadata.labels.kubescape\.io/user-defined-profile,START:.status.startTime'
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0001', 'R0011', 'R0012', 'R1017') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| pod | no tier label | pod carries no app.kubernetes.io/tier label |
| pod | tier assigned by port | an unrecognised image was given a real tier instead of tier=unclassified (admission port fallback) |
| pod | its profile missing in the namespace | pod points at a profile that does not exist in its namespace (unwatched) |
| runtime | R1017 | the profile binding points nowhere; the container is unwatched |
| runtime | R0001 / R0011 / R0012 | an unclassified workload acted outside the quarantine baseline |
| runtime | R0011 / R0012 | the tier profile does not declare an edge the architecture prescribes, so allowed traffic alerts (platform gap) |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
