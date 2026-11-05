# ADR-0018 — Workloads are unprivileged, touch no host path, load no kernel module and cannot reach the cloud metadata API

**Status:** proposed  
**Applies to:** every workload; the namespace's NetworkPolicy  
**Enforced by:** kyverno.validate, netpol, sbob.capabilities

## Decision

No workload is privileged, mounts a host path (least of all the container runtime socket), shares the host PID or IPC namespace, adds a dangerous capability, or loads a kernel module. The cloud metadata API (169.254.169.254) is unreachable from application pods by NetworkPolicy. A pod that genuinely requires one of these declares it on the pod with adr.platform/exceptions: "ADR-0018=<reason>"; the finding then stays as a note, not counted.

## Why

Each of these is a step from a container to the node or the cloud account: a privileged container or a host path is the node; a kernel module is the kernel; the metadata API is the cloud credentials of the node. The pod spec declares the first four; the runtime sensor sees a module load; the NetworkPolicy and the wire show whether the metadata API is reachable and whether it was reached.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **containers' securityContext, capabilities and volumes read from the pod spec** — at least 1: a container in the pod spec.
* **the namespace's egress policy checked against the metadata API address** — at least 1: the namespace's NetworkPolicy set — namespace-wide.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **privileged container** — a container in the pod spec — privileged.
* **a host path is mounted into the container** — a container in the pod spec — a hostPath mounted.
* **the container runtime socket is mounted** — a container in the pod spec — the container runtime socket mounted.
* **hostPID shared** — a container in the pod spec — hostPID.
* **hostIPC shared** — a container in the pod spec — hostIPC.
* **a dangerous capability is added** — a container in the pod spec — a dangerous capability added.
* **the container tried to load a kernel module** — the runtime sensor saw a kernel module load was attempted.
* **egress to the cloud metadata API (169.254.169.254) is not blocked by NetworkPolicy** — the namespace's NetworkPolicy set — namespace-wide, the metadata API not blocked.
* **the cloud metadata API was reached** — a captured flow — to the cloud metadata API.
* **privileged container, host path, runtime socket or host namespace flagged by the static scan** — the static scan flagged a privileged container or a hostPath mount or a mounted container runtime socket or a shared host PID/IPC namespace or host network access.

## How to fix

* privileged container: remove securityContext.privileged; grant a single capability if one is truly needed
* a host path is mounted into the container: no hostPath volumes; use emptyDir, PVC or a projected volume
* the container runtime socket is mounted: never mount docker/containerd/crio sockets
* hostPID shared: remove hostPID
* hostIPC shared: remove hostIPC
* a dangerous capability is added: drop ALL; add nothing from SYS_ADMIN, SYS_MODULE, NET_ADMIN, SYS_PTRACE, SYS_RAWIO, BPF, NET_RAW
* the container tried to load a kernel module: no module loading from a workload; this is the node's job
* egress to the cloud metadata API (169.254.169.254) is not blocked by NetworkPolicy: default-deny egress plus explicit allows; never an allow covering 169.254.169.254
* the cloud metadata API was reached: block 169.254.169.254 by NetworkPolicy; use workload identity instead of instance credentials
* privileged container, host path, runtime socket or host namespace flagged by the static scan: remove the privilege / host mount / host namespace

## Reproduce without the tooling

```bash
# spec
kubectl -n <ns> get pods -o json | jq '.items[].spec.containers[] | {name, image, imagePullPolicy, ports, securityContext, resources, livenessProbe, readinessProbe}'
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R1002') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
# netpol
kubectl -n <ns> get netpol -o yaml
# wire
clickhouse-client -q "SELECT pod, remote_addr, local_port, encrypted, req_path, count() FROM forensic_db.http_events WHERE namespace='<ns>' AND time_ > now()-INTERVAL 1 HOUR GROUP BY ALL"
# scan
kubescape scan framework AllControls --include-namespaces <ns> --format json --output /tmp/AllControls-<ns>.json
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| spec | privileged | privileged container |
| spec | a hostPath mounted | a host path is mounted into the container |
| spec | the container runtime socket mounted | the container runtime socket is mounted |
| spec | hostPID | hostPID shared |
| spec | hostIPC | hostIPC shared |
| spec | a dangerous capability added | a dangerous capability is added |
| runtime | R1002 | the container tried to load a kernel module |
| netpol | namespace-wide, the metadata API not blocked | egress to the cloud metadata API (169.254.169.254) is not blocked by NetworkPolicy |
| wire | captured flow *→* | the cloud metadata API was reached |
| scan | C-0057 / C-0048 / C-0074 / C-0038 / C-0041 | privileged container, host path, runtime socket or host namespace flagged by the static scan |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
