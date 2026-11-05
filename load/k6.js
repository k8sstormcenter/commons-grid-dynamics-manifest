import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE_URL || 'https://commons-grid.local';
const DURATION = __ENV.DURATION || '60s';

// to get a token we reach the IdP service directly and send the Host header it expects
const ZITADEL_URL = __ENV.ZITADEL_URL || 'http://zitadel.zitadel.svc:8080';
const ZITADEL_HOST = __ENV.ZITADEL_HOST || 'localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || '';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || '';

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: { adr_driver: { executor: 'constant-vus', vus: 2, duration: DURATION } },
};

export function setup() {
  if (!CLIENT_ID || !CLIENT_SECRET) return { token: '' };
  const r = http.post(ZITADEL_URL + '/oauth/v2/token',
    { grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET, scope: 'openid' },
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Host': ZITADEL_HOST } });
  let token = '';
  try { token = JSON.parse(r.body).access_token || ''; } catch (e) { token = ''; }
  return { token };
}

function hdr(data, useCase, json) {
  const h = { 'User-Agent': 'adr-driver/k6', 'X-Test-Case': useCase };
  if (json) h['Content-Type'] = 'application/json';
  if (data.token) h['Authorization'] = 'Bearer ' + data.token;
  return { headers: h };
}

function get(data, useCase, path) {
  const r = http.get(BASE + path, hdr(data, useCase, false));
  check(r, { [useCase + ' ok']: x => x.status === 200 });
  return r;
}
function post(data, useCase, path, body) {
  const r = http.post(BASE + path, JSON.stringify(body), hdr(data, useCase, true));
  check(r, { [useCase + ' ok']: x => x.status === 200 });
  return r;
}

export default function (data) {
  get(data, 'open-shell', '/');
  get(data, 'constants', '/api/constants');
  get(data, 'presets', '/api/presets');
  get(data, 'abuses', '/api/abuses');
  get(data, 'packages', '/api/packages');
  post(data, 'simulate', '/api/simulate', { P: {} });

  const ens = post(data, 'ensemble', '/api/ensemble', { P: {}, seeds: [1, 2, 3] });
  let runs = [];
  try { runs = JSON.parse(ens.body); if (!Array.isArray(runs)) runs = []; } catch (e) { runs = []; }
  post(data, 'summarise', '/api/summarise', { runs: runs.slice(0, 3) });
  post(data, 'sweep2D', '/api/sweep2D', { base: {}, xKey: 'audit', yKey: 'fine', nx: 3, ny: 3, seeds: [1, 2] });
  post(data, 'sweepRun', '/api/sweepRun', { P: { audit: 0.5, fine: 1000 }, seeds: [1, 2] });

  sleep(1);
}
