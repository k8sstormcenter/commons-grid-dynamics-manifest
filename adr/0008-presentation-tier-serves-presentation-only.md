# ADR-0008 — The presentation tier serves presentation only

**Status:** proposed
**Applies to:** `tier=frontend`

## Context

A vibe-coded application arrives as one container: a stock web server image with the whole
product baked into `index.html`. On the first such fixture the page was 195 KB, of which 178 KB
was inline JavaScript — random number generators, Runge-Kutta and Dormand-Prince integrators, a
Newton solver, an eigenvalue routine, Monte-Carlo ensembles, and three embedded datasets
(`PRESETS`, `PACKAGES`, `ABUSES`) carrying the pricing, dues and enforcement parameters the
product is actually about. State lived in `localStorage`. There was not a single `fetch()`.

Admission classified it `tier=frontend` because it listened on port 80. Every tier ADR then
passed: nothing crossed a tier boundary, because there was only one tier. The scheme in
[ADR-0001](0001-strict-tier-layering.md) and [ADR-0002](0002-data-tier-does-not-initiate-egress.md)
is a statement about boundaries, and a monolith has none to violate.

This is the failure mode to expect from AI-assisted authoring: the model's cheapest correct answer
to "make me a simulator" is a single HTML file. It is also the hardest shape to secure — the
business logic, the data and the user all sit in the same trust domain, which is the browser.

## Decision

A `tier=frontend` workload serves the shell of the application: markup, styling, static assets,
and the client code needed to call a `tier=backend` API. It does not contain the application's
computation, its datasets, or its state.

Concretely, for what the frontend pod serves on its port:

* inline or bundled code is bounded — a shell, not an engine (the limit is set per platform; the
  rig uses 50 KB inline / 100 named functions as the point where a page stops being a shell)
* no numerical-solver, simulation or statistics routines in client code
* no datasets with business content (prices, tariffs, customer/member tables) in the served assets
* no application state in browser storage beyond UI preferences
* the client code calls at least one backend endpoint; the frontend profile therefore declares
  egress to `tier=backend`, and that egress is observed at runtime

## Verified by

**Content probe** — `GET /` on the frontend pod's port, measured: total bytes, inline-script
bytes, named functions, solver/statistics/simulation identifiers, embedded array-of-object
datasets, money/pricing tokens, `localStorage`/`sessionStorage`, `fetch`/`XMLHttpRequest`
occurrences. The probe reports counts, not opinions; the thresholds are the decision.

**Runtime, corroborating** — a frontend that never calls a backend produces no egress at all: zero
`R0011` from the pod *and* a profile with `egress: null`. One of those alone is normal; both
together on a workload whose page carries the engine is the monolith signature.

**Runtime, supporting** — `R0002` on `/usr/share/nginx/html/*` against the stock `tier-frontend`
profile: custom content inside a stock-server image. Weak on its own (any customised page fires
it); it confirms the image is not what its name says.

## Evidence emitted

```
ADR-0008 VIOLATED   SINGLE_TIER_APPLICATION_IN_PRESENTATION_TIER
  observed  content   commons-grid-dynamics/web serves 178 KB inline JS, 76 named functions,
                      solvers: rk4, dp45, newton, eigenvalues; datasets: PRESETS, PACKAGES, ABUSES;
                      187 pricing tokens; localStorage; 0 fetch()
  observed  runtime   0 egress events from the pod; profile tier-frontend egress: null
  supporting R0002    nginx opened /usr/share/nginx/html/index.html (not in baseline)
  fix       keep nginx as the shell; move the engine into a tier=backend service on 8000/8080;
            move PRESETS/PACKAGES/ABUSES into a tier=database store the backend reads;
            the shell calls the backend over HTTP — that call is the egress ADR-0001 expects
```

## Consequences

* A split application produces *more* findings in the short term — the new frontend→backend
  egress has to be declared in the frontend profile, the backend's ingress likewise. That is the
  point: boundaries that exist can be checked.
* The content probe is a heuristic on served bytes. It is deliberately conservative (several
  independent markers must agree) and reports its counts so a reviewer can disagree with the
  threshold rather than with the measurement.
