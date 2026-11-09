// k6 script convention for the ADR harness — derive it from the functional/integration test-suite.
//   k6 run -e BASE_URL=https://<ingress-host> -e DURATION=120s load/k6.js   (the harness sets both)
// Rules the evidence engine relies on:
//   * User-Agent "adr-driver/k6": the wire evidence counts these rows as application traffic (the browser stand-in)
//   * X-Test-Case: <use case>: every request names the functional use case it belongs to; the compliance proof
//     then says which use cases exercised each prescribed edge (frontend->backend, backend->database, ...)
//   * go through the platform ingress (BASE_URL is the ingress host), never a pod IP or NodePort
import http from 'k6/http';
import { check, group, sleep } from 'k6';

export const options = {
  scenarios: {
    browse:   { executor: 'constant-vus', vus: 2, duration: __ENV.DURATION || '120s', exec: 'browse' },
    simulate: { executor: 'constant-vus', vus: 1, duration: __ENV.DURATION || '120s', exec: 'simulate' },
  },
};
const BASE = __ENV.BASE_URL;
const hdr = (useCase, extra) => ({ headers: Object.assign({ 'User-Agent': 'adr-driver/k6', 'X-Test-Case': useCase }, extra || {}) });

export function browse() {            // use case: a visitor opens the application
  group('open-page', () => {
    const r = http.get(`${BASE}/`, hdr('open-page'));
    check(r, { 'page 200': (res) => res.status === 200 });
    for (const src of (r.body.match(/<script[^>]+src="([^"]+)"/g) || []).map((m) => m.replace(/.*src="([^"]+)".*/, '$1'))) {
      if (!src.includes('://')) http.get(`${BASE}/${src.replace(/^\//, '')}`, hdr('open-page'));
    }
  });
  sleep(1);
}

export function simulate() {          // use case: run a simulation through the API (replace with the suite's real flows)
  group('run-simulation', () => {
    const c = http.get(`${BASE}/api/constants`, hdr('run-simulation'));
    check(c, { 'constants 200/401': (res) => res.status === 200 || res.status === 401 });
    http.post(`${BASE}/api/simulate`, JSON.stringify({}), hdr('run-simulation', { 'Content-Type': 'application/json' }));
  });
  sleep(2);
}
