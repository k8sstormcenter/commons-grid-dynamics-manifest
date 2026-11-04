# ADR-0008 — The presentation tier serves presentation only

**Status:** proposed  
**Applies to:** tier=frontend  
**Enforced by:** content-probe

## Decision

A tier=frontend workload serves the shell of the application: markup, styling, static assets and the client code needed to call a tier=backend API. Concretely: at most 50 KB of client code (inline plus the scripts the page loads); no numerical-solver, simulation or statistics routines defined in client code; no business datasets embedded in served assets; no application state in browser storage; and at least one backend call, so the frontend→backend edge exists.

## Why

The generated monolith ships the whole application as one page: engine, data and state in the browser, no backend, no authentication and nothing to observe at runtime. The content probe measures the page; the thresholds are the decision. A solver the page merely names (a route, a tab label) is a call; only a solver the page defines counts.

## How it is checked

`COMPLIANT` needs every item below (see [README](README.md#how-to-read-an-adr) for how statuses are decided):

* **frontend page and its scripts read** — at least 1: the page the frontend serves — tier frontend, serving a page.

## What a violation looks like

Each matching event is a finding with the observed event, the decision it broke and the fix; discounted events stay as notes (`counted=false`).

* **the page ships more client code than a shell (limit 50 KB)** — the page the frontend serves — tier frontend, serving a page, client code bytes > 51200.
* **the presentation tier defines numerical solvers/simulation routines** — the page the frontend serves — tier frontend, solvers defined in the page > 0.
* **business data is embedded in the page** — the page the frontend serves — tier frontend, datasets embedded in the page > 0.
* **application state is kept in the browser** — the page the frontend serves — tier frontend, browser-storage uses > 0.
* **the shell calls no backend** — the page the frontend serves — tier frontend, serving a page, backend call sites 0.

Markers counted in the served client code (declared in `compliance/adrs.yaml`, app-neutral):

* `numeric_solvers` (a function with such a name is computation): `\b(rk4|dp45|runge|kutta|jacobian|eigen(value|vector)s?|newton|solve(Linear|Ode|Ivp)|integrat(e|or)|monte ?carlo|ensemble)\b`
* `statistics` (a function with such a name is computation): `\b(gauss(ian)?|poisson|gamma|lognormal|binom(ial)?|gini|quantile|variance)\b`
* `simulation` (a function with such a name is computation): `\b(simulat(e|ion|or)|sweep|timestep)\b`
* `client_state`: `\b(localStorage|sessionStorage|indexedDB)\b`
* `backend_calls`: `\b(fetch\(|XMLHttpRequest|WebSocket|EventSource|axios)\b`
* `auth`: `\b(Authorization|Bearer|login|signin|oauth|openid|jwt|csrf)\b`

## How to fix

* the page ships more client code than a shell (limit 50 KB): the browser renders, it does not compute; move the engine behind the API
* the presentation tier defines numerical solvers/simulation routines: move every solver/integrator/sweep behind a tier=backend API (8000/8080)
* business data is embedded in the page: move the datasets into a tier=database store the backend reads
* application state is kept in the browser: persist state via the backend into the data tier
* the shell calls no backend: the shell's fetch() to the API is the egress ADR-0001 expects

## Reproduce without the tooling

```bash
# content
curl -s http://<frontend-pod-ip>:<port>/ | grep -o '<script[^>]*src="[^"]*"'   # then fetch each script and grep for the markers listed above
```

## Mechanical mapping

| source | key | decision broken |
|---|---|---|
| content | tier frontend, serving a page, client code bytes > 51200 | the page ships more client code than a shell (limit 50 KB) |
| content | tier frontend, solvers defined in the page > 0 | the presentation tier defines numerical solvers/simulation routines |
| content | tier frontend, datasets embedded in the page > 0 | business data is embedded in the page |
| content | tier frontend, browser-storage uses > 0 | application state is kept in the browser |
| content | tier frontend, serving a page, backend call sites 0 | the shell calls no backend |

*Generated from `compliance/adrs.yaml` and `compliance/adr_text.yaml` by `compliance/adr_docs.py`. Edit those, not this file.*
