import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE_URL || 'http://commons-grid-dynamics.commons-grid.svc';
const DURATION = __ENV.DURATION || '60s';

export const options = {
  scenarios: {
    adr_driver: { executor: 'constant-vus', vus: 2, duration: DURATION },
  },
};

function hdr(useCase, json) {
  const h = { 'User-Agent': 'adr-driver/k6', 'X-Test-Case': useCase };
  if (json) h['Content-Type'] = 'application/json';
  return { headers: h };
}

function get(useCase, path) {
  const r = http.get(BASE + path, hdr(useCase, false));
  check(r, { [useCase + ' 200']: x => x.status === 200 });
  return r;
}

function post(useCase, path, body) {
  const r = http.post(BASE + path, JSON.stringify(body), hdr(useCase, true));
  check(r, { [useCase + ' 200']: x => x.status === 200 });
  return r;
}

export default function () {
  // use case: open the simulator shell
  get('open-shell', '/');

  // use case: load constants and reference data
  const c = get('constants', '/api/constants');
  get('presets', '/api/presets');
  get('abuses', '/api/abuses');
  get('packages', '/api/packages');

  // use case: run a single simulation with default parameters
  post('simulate', '/api/simulate', { P: {} });

  // use case: run an ensemble over several seeds
  const seeds = [1, 2, 3];
  const ens = post('ensemble', '/api/ensemble', { P: {}, seeds });
  let runs = [];
  try { runs = JSON.parse(ens.body); } catch (e) { runs = []; }

  // use case: summarise an ensemble
  if (runs.length) post('summarise', '/api/summarise', { runs });

  // use case: sweep two levers across a grid
  const sw = post('sweep2D', '/api/sweep2D', { base: {}, xKey: 'audit', yKey: 'fine', nx: 3, ny: 3, seeds: [1, 2] });
  let tasks = [];
  try { tasks = (JSON.parse(sw.body).tasks) || []; } catch (e) { tasks = []; }

  // use case: run one cell of a sweep
  if (tasks.length) post('sweepRun', '/api/sweepRun', { P: tasks[0].P, seeds: [1, 2] });

  sleep(1);
}
