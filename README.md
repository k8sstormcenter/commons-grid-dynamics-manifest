https://youtu.be/3N9fNF6sQIQ

<img width="1146" height="646" alt="Screenshot 2026-11-06 at 00 19 20" src="https://github.com/user-attachments/assets/b59d2a41-074b-4c70-bece-47bbf4d037c8" />


The stack used herein is installed by following the TL;DR section in https://github.com/k8sstormcenter/soc

The additional (PoC) components are under /platform:

| file | what |
|---|---|
| `platform/platform-ca.yaml` | the platform CA (`ClusterIssuer platform-ca`) the workloads get their TLS certificates from (ADR-0011) |
| `platform/idp-client.sh <ns>` | provisions the namespace's client on the platform IdP (ZITADEL); the evaluator probes ADR-0010 with it |
| `platform/adr-probe.sh` | the evaluator's in-cluster probe helper |
| `platform/dx-ktls-openssl.yaml` | the TLS tap: DaemonSet `honey/dx-ktls-openssl`, SSL_read/SSL_write uprobes on the libssl of every pod in `DX_KTLS_NAMESPACES`; bodies land in ClickHouse `forensic_db.dx_kubelet_stream` (`source='openssl'`) with personal data replaced by `<pii:class>` markers at ingest, 24 h TTL. This is what ADR-0024/0027/0028 (personal data on the wire, pseudonymisation at rest) are evaluated from. |

Our setup uses an intelligent LLM on the target cluster to act as a deployment controller AND to relay the MCP's findings to the citizen-coder. This allows the citizen-coder-agent to ask question about the cluster setup, e.g. which `storageClass` is available or `where is the IDP`. 

These problems should possibly solved in a more grown-up, enterprise-grade solution and we trust that platform-engineers have their methods.


## Warning - this is not production ready code
Please switch off the TLS tap especially, after you are done:

```sh
kubectl -n honey delete ds dx-ktls-openssl
```

It produces large data volumes (about 20 M rows a day under load, kept 24 h) and is not integrated in the soc stack at the moment; the image comes from the `feat/ktls-piiclass` branch of the dx repository. If you find it useful, leave an issue or comment on LinkedIn, so we can maybe include it in a more mature build.
