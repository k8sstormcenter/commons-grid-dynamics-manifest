# commons-grid-dynamics-manifest

Kubernetes manifests for the Commons Grid Dynamics simulator (a static page served by nginx).

```sh
kubectl apply -f https://raw.githubusercontent.com/k8sstormcenter/commons-grid-dynamics-manifest/main/deploy.yaml
kubectl -n commons-grid rollout status deploy/commons-grid-dynamics
kubectl -n commons-grid get svc commons-grid-dynamics        # NodePort
# or: kubectl -n commons-grid port-forward svc/commons-grid-dynamics 8080:80
```

Image: `ghcr.io/k8sstormcenter/commons-grid-dynamics:latest` (linux/amd64 + linux/arm64).
Source code: `k8sstormcenter/commons-grid-dynamics`.

| file | what |
|---|---|
| `deploy.yaml` | the app, NodePort service |
| `deploy-pinned.yaml` | the app, image pinned to commit `9ab1489587f7030ef70dbc3b67e170e8bd9f027f` |
| `deploy-runtime.yaml` | the app with redis and postgres sidecars, reverse-proxied on 6379/5432 |
| `deploy-privileged.yaml` | debug deployment with node log and docker socket access |
| `deploy-iter1.yaml` | iteration 1: frontend (nginx) / backend (node API on 8000) / database (redis), tier labels, digest-pinned images, ClusterIP services |
| `deploy-iter2.yaml` | iteration 2: same three tiers with requests/limits, probes, non-root + read-only + drop ALL + RuntimeDefault, no SA token; nginx-unprivileged; no npm install at start; solvers, literature and UI state behind the API |
