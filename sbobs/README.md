# Tier profiles

The platform binds every workload to one profile per tier (frontend, backend, database,
middleware, unclassified). The admission policy picks the tier; it cannot know the application,
so the profiles are generic: each allows any process and any file, and keeps only the detections
that matter on every application of that tier.

| what still alerts | where it comes from |
|---|---|
| calls to a tier it may not reach, calls from a tier that may not reach it | the base's network edges |
| capabilities beyond the base's short list (a container that starts as root and drops) | the base's capabilities |
| installing or fetching software, network and cluster tools at runtime | `fragments/subtract-runtime-tooling.yaml` |
| password and sudo files, SSH keys, process environments, runtime sockets | `fragments/subtract-sensitive-files.yaml` |
| the ServiceAccount token, in every tier except backend | `fragments/subtract-cluster-credentials.yaml` |

A subtract entry alerts even where the base's wildcard would allow it.

`compose.sh` builds `cp-tier-*.yaml` from `fragments/` with `bobctl compose`. Apply only
`cp-tier-*.yaml` to the `sbob-library` namespace; `fragments/` are inputs, not profiles.
