import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://commons-grid-dynamics.commons-grid.svc';
const DURATION = __ENV.DURATION || '60s';

// Per-minute rates (each iteration issues the requests noted below):
//   frontend:    1 request/iteration  x 5/s  = 300 frontend req/min
//   runs:        3 API calls (3 DB)   x 4/s  = 720 backend req/min, 720 DB commands/min
//   simulations: 3 API calls (3 DB)   x 2/s  = 360 backend req/min, 360 DB commands/min
export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    frontend: {
      executor: 'constant-arrival-rate', exec: 'frontend',
      rate: 5, timeUnit: '1s', duration: DURATION, preAllocatedVUs: 5, maxVUs: 20,
    },
    runs: {
      executor: 'constant-arrival-rate', exec: 'runs',
      rate: 4, timeUnit: '1s', duration: DURATION, preAllocatedVUs: 5, maxVUs: 30,
    },
    simulations: {
      executor: 'constant-arrival-rate', exec: 'simulations',
      rate: 2, timeUnit: '1s', duration: DURATION, preAllocatedVUs: 4, maxVUs: 20,
    },
  },
};

function headers(testCase) {
  return {
    'User-Agent': 'adr-driver/k6',
    'X-Test-Case': testCase,
    'Content-Type': 'application/json',
  };
}

export function frontend() {
  const r = http.get(`${BASE_URL}/`, { headers: headers('frontend-page') });
  check(r, { 'frontend page 200': (x) => x.status === 200 });
}

export function runs() {
  const body = JSON.stringify({ name: 'k6 run', params: { N: 10, M: 5, P: 2, hpc: 20 } });
  const created = http.post(`${BASE_URL}/api/runs`, body, { headers: headers('save-run') });
  check(created, { 'run saved': (x) => x.status === 201 });

  const list = http.get(`${BASE_URL}/api/runs`, { headers: headers('list-runs') });
  check(list, { 'runs listed': (x) => x.status === 200 });

  const id = created.status === 201 ? created.json('id') : 1;
  const loaded = http.get(`${BASE_URL}/api/runs/${id}`, { headers: headers('load-run') });
  check(loaded, { 'run loaded': (x) => x.status === 200 || x.status === 404 });
}

export function simulations() {
  const body = JSON.stringify({ name: 'k6 simulation', body: { params: { N: 10, M: 5, P: 2, hpc: 20 } } });
  const created = http.post(`${BASE_URL}/api/simulations`, body, { headers: headers('save-simulation') });
  check(created, { 'simulation saved': (x) => x.status === 201 });

  const list = http.get(`${BASE_URL}/api/simulations`, { headers: headers('list-simulations') });
  check(list, { 'simulations listed': (x) => x.status === 200 });

  const id = created.status === 201 ? created.json('id') : 1;
  const loaded = http.get(`${BASE_URL}/api/simulations/${id}`, { headers: headers('load-simulation') });
  check(loaded, { 'simulation loaded': (x) => x.status === 200 || x.status === 404 });
}
