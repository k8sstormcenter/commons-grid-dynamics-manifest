# commons-grid-dynamics-manifest

Kubernetes manifest for the Commons Grid Dynamics simulator (a static page served by nginx).

```sh
kubectl apply -f https://raw.githubusercontent.com/k8sstormcenter/commons-grid-dynamics-manifest/main/deploy.yaml
kubectl -n commons-grid rollout status deploy/commons-grid-dynamics
# open http://<any-node-ip>:30080   (or: kubectl -n commons-grid port-forward svc/commons-grid-dynamics 8080:80)
```

Image: `ghcr.io/k8sstormcenter/commons-grid-dynamics:latest` (public, linux/amd64 + linux/arm64).
Source code: `k8sstormcenter/commons-grid-dynamics` (private).

This is a deliberately plain "citizen coder" deployment used as a test fixture for edge4
ADR-compliance checks: `latest` tag, no resource requests/limits, no securityContext,
no probes, no NetworkPolicy, stock `nginx:latest` base image running as root on port 80.
