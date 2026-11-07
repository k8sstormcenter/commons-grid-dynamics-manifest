https://youtu.be/3N9fNF6sQIQ

<img width="1146" height="646" alt="Screenshot 2026-11-06 at 00 19 20" src="https://github.com/user-attachments/assets/b59d2a41-074b-4c70-bece-47bbf4d037c8" />


The stack used herein is installed by following the TL;DR section in https://github.com/k8sstormcenter/soc

The additional (PoC) components are under /platform 

Our setup uses an intelligent LLM on the target cluster to act as `flux` or `keptn` AND to relay the MCP's findings to the citizen-coder. This allows the citizen-coder-agent to ask question about the cluster setup, e.g. which `storageClass` is available or `where is the IDP`. 

These problems should possibly solved in a more grown-up, enterprise-grade solution and we trust that platform-engineers have their methods.


## Warning - this is not production ready code
Please switch off the `tls tap` especially, after you are done. It produces large datavolumes and is not integrated in the soc stack at the moment. If you find it useful, leave an issue or comment on LinkedIn, so we can maybe include it in a more mature build.
