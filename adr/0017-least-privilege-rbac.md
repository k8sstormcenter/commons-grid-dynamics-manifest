# ADR-0017 — A workload's ServiceAccount holds only the permissions its code uses; nothing is bound to default

**Status:** proposed  
**Applies to:** every workload ServiceAccount, Role, RoleBinding and ClusterRoleBinding  
**Enforced by:** rbac-review, kyverno.validate

## Decision

Every workload runs under its own ServiceAccount, and that ServiceAccount is bound only to the verbs and resources the code actually calls. No administrative role, no wildcard verbs or resources, no reading of Secrets through the API, no exec/attach/portforward, no escalate/bind/ impersonate, and no cluster-scoped binding for a namespaced workload. Nothing is bound to the default ServiceAccount. A workload that does not call the API has no bindings at all.

## Why

RBAC is what a stolen token buys. The bindings are resolved per running pod, from its ServiceAccount through every RoleBinding and ClusterRoleBinding to the rules, so the finding names the binding to fix. The runtime sensor corroborates: a workload calling the API outside its profile is either an undeclared dependency or an intrusion.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **ServiceAccounts of the running pods resolved through their bindings to rules** — at least 1: a workload ServiceAccount's bindings.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **an administrative role (cluster-admin, admin, edit) is bound to a workload ServiceAccount** — a workload ServiceAccount's bindings — an administrative role.
* **wildcard verbs in a role bound to a workload** — a workload ServiceAccount's bindings — wildcard verbs.
* **wildcard resources or apiGroups in a role bound to a workload** — a workload ServiceAccount's bindings — wildcard resources.
* **the workload can read Secrets through the API** — a workload ServiceAccount's bindings — can read Secrets.
* **the workload can exec/attach/portforward into pods** — a workload ServiceAccount's bindings — exec/attach/portforward.
* **the workload can escalate, bind or impersonate** — a workload ServiceAccount's bindings — escalate/bind/impersonate.
* **permissions are bound to the default ServiceAccount** — a workload ServiceAccount's bindings — the default ServiceAccount, with bindings.
* **a namespaced workload holds a cluster-scoped binding** — a workload ServiceAccount's bindings — cluster-scoped binding.
* **the workload called the Kubernetes API outside its profile** — the runtime sensor saw the Kubernetes API was called outside the profile.
* **over-scoped RBAC flagged by the static scan** — the static scan flagged an administrative role or listing Secrets or exec into containers or delete capabilities or portforward privileges or impersonation or deleting events or access to Secrets or wildcards in roles or pod creation rights or bind/impersonate/escalate.

## How to fix

* an administrative role (cluster-admin, admin, edit) is bound to a workload ServiceAccount: bind a Role with the verbs and resources the code actually calls
* wildcard verbs in a role bound to a workload: list the verbs explicitly
* wildcard resources or apiGroups in a role bound to a workload: list the resources explicitly
* the workload can read Secrets through the API: mount the one Secret it needs; no get/list/watch on secrets
* the workload can exec/attach/portforward into pods: remove pods/exec, pods/attach, pods/portforward
* the workload can escalate, bind or impersonate: remove escalate/bind/impersonate verbs
* permissions are bound to the default ServiceAccount: give the workload its own ServiceAccount; leave default with nothing
* a namespaced workload holds a cluster-scoped binding: bind a namespaced Role; cluster-wide access is the platform's
* the workload called the Kubernetes API outside its profile: if the call is legitimate declare it in the profile and the Role; otherwise remove it
* over-scoped RBAC flagged by the static scan: reduce the role to the verbs and resources the workload uses

## Reproduce without the tooling

```bash
# rbac
kubectl -n <ns> get rolebindings -o wide; kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.namespace=="<ns>") | {name:.metadata.name, role:.roleRef.name}'
# runtime
clickhouse-client -q "SELECT RuleID, message FROM forensic_db.kubescape_logs WHERE JSONExtractString(RuntimeK8sDetails,'namespace')='<ns>' AND RuleID IN ('R0007') AND event_time > toUnixTimestamp64Nano(now64()-INTERVAL 1 HOUR)"
# scan
kubescape scan framework AllControls --include-namespaces <ns> --format json --output /tmp/AllControls-<ns>.json
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| rbac | an administrative role | an administrative role (cluster-admin, admin, edit) is bound to a workload ServiceAccount |
| rbac | wildcard verbs | wildcard verbs in a role bound to a workload |
| rbac | wildcard resources | wildcard resources or apiGroups in a role bound to a workload |
| rbac | can read Secrets | the workload can read Secrets through the API |
| rbac | exec/attach/portforward | the workload can exec/attach/portforward into pods |
| rbac | escalate/bind/impersonate | the workload can escalate, bind or impersonate |
| rbac | the default ServiceAccount, with bindings | permissions are bound to the default ServiceAccount |
| rbac | cluster-scoped binding | a namespaced workload holds a cluster-scoped binding |
| runtime | R0007 | the workload called the Kubernetes API outside its profile |
| scan | C-0035 / C-0015 / C-0002 / C-0007 / C-0063 / C-0065 / C-0031 / C-0186 / C-0187 / C-0188 / C-0191 | over-scoped RBAC flagged by the static scan |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
