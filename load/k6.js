import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';

const BASE_URL = __ENV.BASE_URL || 'http://commons-grid-dynamics.commons-grid.svc';
const DURATION = __ENV.DURATION || '60s';

// Identity: the load namespace's own IdP client (client_credentials). Values come from the
// Secret commons-grid-load/idp-client; nothing secret is stored in this repo.
const IDP_TOKEN_ENDPOINT = __ENV.IDP_TOKEN_ENDPOINT || '';
const IDP_CLIENT_ID = __ENV.IDP_CLIENT_ID || '';
const IDP_CLIENT_SECRET = __ENV.IDP_CLIENT_SECRET || '';
const IDP_PROJECT_ID = __ENV.IDP_PROJECT_ID || '';
const IDP_HOST_HEADER = __ENV.IDP_HOST_HEADER || 'localhost:8080';

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

// Mint an access token with client_credentials. Tokens live about 12 h; a VU re-mints on a 401.
function mintToken() {
  const r = http.post(IDP_TOKEN_ENDPOINT, {
    grant_type: 'client_credentials',
    scope: 'openid urn:zitadel:iam:org:project:id:' + IDP_PROJECT_ID + ':aud',
  }, {
    headers: {
      Authorization: 'Basic ' + encoding.b64encode(IDP_CLIENT_ID + ':' + IDP_CLIENT_SECRET),
      Host: IDP_HOST_HEADER,
      'User-Agent': 'adr-driver/k6',
      'X-Test-Case': 'mint-token',
    },
  });
  check(r, { 'token minted': (x) => x.status === 200 });
  return r.status === 200 ? r.json('access_token') : '';
}

export function setup() {
  const token = mintToken();
  if (!token) throw new Error('could not mint an access token from the IdP');
  return { token: token };
}

let vuToken = '';

function headers(testCase, data) {
  if (!vuToken) vuToken = data.token;
  return {
    'User-Agent': 'adr-driver/k6',
    'X-Test-Case': testCase,
    'Content-Type': 'application/json',
    Authorization: 'Bearer ' + vuToken,
  };
}

// Authenticated API call; on 401 the VU mints a fresh token and retries once.
function api(method, path, body, testCase, data) {
  const url = BASE_URL + path;
  let r = http.request(method, url, body, { headers: headers(testCase, data) });
  if (r.status === 401) {
    vuToken = mintToken() || vuToken;
    r = http.request(method, url, body, { headers: headers(testCase, data) });
  }
  return r;
}

export function frontend() {
  const r = http.get(`${BASE_URL}/`, { headers: { 'User-Agent': 'adr-driver/k6', 'X-Test-Case': 'frontend-page' } });
  check(r, { 'frontend page 200': (x) => x.status === 200 });
}

export function runs(data) {
  const body = JSON.stringify({ name: 'k6 run', params: { N: 10, M: 5, P: 2, hpc: 20 } });
  const created = api('POST', '/api/runs', body, 'save-run', data);
  check(created, { 'run saved': (x) => x.status === 201 });

  const list = api('GET', '/api/runs', null, 'list-runs', data);
  check(list, { 'runs listed': (x) => x.status === 200 });

  const id = created.status === 201 ? created.json('id') : 1;
  const loaded = api('GET', `/api/runs/${id}`, null, 'load-run', data);
  check(loaded, { 'run loaded': (x) => x.status === 200 || x.status === 404 });
}

export function simulations(data) {
  const body = JSON.stringify({ name: 'k6 simulation', body: { params: { N: 10, M: 5, P: 2, hpc: 20 } } });
  const created = api('POST', '/api/simulations', body, 'save-simulation', data);
  check(created, { 'simulation saved': (x) => x.status === 201 });

  const list = api('GET', '/api/simulations', null, 'list-simulations', data);
  check(list, { 'simulations listed': (x) => x.status === 200 });

  const id = created.status === 201 ? created.json('id') : 1;
  const loaded = api('GET', `/api/simulations/${id}`, null, 'load-simulation', data);
  check(loaded, { 'simulation loaded': (x) => x.status === 200 || x.status === 404 });
}
