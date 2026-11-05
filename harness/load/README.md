# Realistic traffic for the fix-and-verify loop

The runtime ADRs (tier layering, data-tier egress, plaintext on the wire, metrics scraping, authentication)
can only be judged on traffic. The harness refuses to pass them on silence: without traffic they are
`NOT_OBSERVED`, and the proof says which edge saw nothing. `harness/load.sh <ns> [seconds]` puts
traffic on the application before every evaluation, choosing in this order:

| source | who supplies it | when |
|---|---|---|
| `deploy-loadgen.yaml` (repo root) | the citizen coder: a Deployment in namespace `<app>-load` that runs the k6 suite continuously against the ingress host | iteration ≥ 1 |
| `load/k6.js` (repo root) | the citizen coder: a k6 script derived from the functional/integration test-suite, run in-cluster as a Job | iteration 0 |
| `compliance/drive.py` | the harness: GET `/`, the page's scripts and `/api` paths, the browser's path | fallback |

## The ask to the citizen coder (sent with the iteration-0 feedback)

1. **Iteration 0:** turn the functional/integration tests into `load/k6.js` (template: `harness/load/k6-example.js`).
   Each request carries `User-Agent: adr-driver/k6` and `X-Test-Case: <use case>`; every use case of the
   application appears at least once; everything goes through the platform ingress host (`BASE_URL`), never a pod IP.
2. **Iteration 1 and later:** ship `deploy-loadgen.yaml`: a Deployment (image `grafana/k6`, the script in a ConfigMap)
   in namespace `<app>-load` that runs the same suite continuously, so the application is always under
   realistic load while it is judged.
3. **Runtime tests:** keep adding use cases to the suite as functional tests — one `X-Test-Case` per use case.
   The compliance proof reports, per prescribed edge, which use cases exercised it; a use case that never
   reaches the database tier, or reaches it from the frontend, is visible by name.

The human in the loop can write functional tests with the application's business owner; each becomes one
named use case in the suite and one line of evidence in the proof.
