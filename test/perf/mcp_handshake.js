// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// k6 scenario: the gateway-LOCAL /mcp handshake (initialize + tools/list).
//
// This measures ONLY the gateway's own answered path. initialize and tools/list
// are answered gateway-local and NEVER forwarded (internal/ingress/handler.go
// steps 3b): the daemon boots with NO -control-url, so tools/call would fail
// closed and is deliberately not on the measured path. The regression signal is
// the latency of the authenticated, locally-answered handshake pipeline - the
// hot path every MCP client hits before it can call a tool.
//
// The measured path is the REAL authenticated pipeline, proven by setup():
//   - GET /healthz must be 200 (the daemon is up and ready).
//   - POST initialize with a VALID minted bearer (and NO MCP-Protocol-Version
//     header - initialize is spec-exempt from the version pin) must be 200.
//   - POST initialize with a WRONG bearer must be 401.
// The 401 leg is the soundness guard: if auth were bypassed, or the scenario were
// aimed at an unauthenticated surface (/health), the wrong bearer would NOT 401
// and setup() aborts the whole run as an ERROR. So a green run PROVES the numbers
// come from the authenticated handshake, not an open endpoint.
//
// The per-iteration request is tools/list (WITH the version header, which
// tools/list requires) so each measured op exercises the auth + version-pin +
// embedded-tools-list answer. The regression threshold lives entirely in
// scripts/perf_compare.py; this scenario carries NO absolute-latency threshold -
// only a functional-correctness floor (requests must not fail, checks must pass),
// so a slow-but-correct machine does not red the run; a broken pipeline does.

import http from 'k6/http';
import { check, fail } from 'k6';

const BASE_URL = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const BEARER = __ENV.GATEWAY_BEARER || '';
const SUMMARY_PATH = __ENV.SUMMARY_PATH || 'summary.json';

// The MCP revision the gateway pins (internal/ingress/handler.go
// pinnedProtocolVersion). tools/list requires this header; initialize is exempt.
const PROTOCOL_VERSION = '2025-06-18';

const INITIALIZE_BODY = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: 'k6-perf', version: '0' },
  },
});

const TOOLS_LIST_BODY = JSON.stringify({
  jsonrpc: '2.0',
  id: 2,
  method: 'tools/list',
  params: {},
});

export const options = {
  scenarios: {
    handshake: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: '60s',
      // A 10s warmup precedes the measured window: startTime shifts the scenario
      // start so the process is JIT-warm and the arrival rate is steady before
      // the first measured iteration. The comparer's min-of-rounds also guards
      // against a cold tail; the warmup keeps the measured window itself clean.
      startTime: '10s',
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  thresholds: {
    // Functional-correctness floor ONLY - regression lives in perf_compare.py.
    // A failed request or a failed check aborts the run (abortOnFail) so a broken
    // measured pipeline never produces a green summary the comparer would trust.
    http_req_failed: [{ threshold: 'rate<0.01', abortOnFail: true }],
    checks: ['rate>0.99'],
  },
};

// setup runs ONCE before the measured window. It proves the measured path is the
// authenticated handshake pipeline; any failed assertion here fails the whole run
// as an ERROR (not a latency red), so the numbers are never taken from a
// mis-aimed or auth-bypassed scenario.
export function setup() {
  if (!BEARER) {
    fail('GATEWAY_BEARER is required (a valid minted sk-ocu- bearer)');
  }

  // The setup assertions POST a DELIBERATE 401 (the wrong-bearer guard). Each
  // setup request declares its own expected status via responseCallback so k6's
  // http_req_failed metric does not count the intentional 401 (or the 200s) as a
  // transport failure - otherwise the abortOnFail threshold would trip on our own
  // soundness probe before the measured window even starts. The explicit
  // status-equality checks below are what enforce the guard; the callback only
  // keeps the metric honest about which statuses were EXPECTED here.

  // (1) readiness: the daemon is up and the boot-set loaded.
  const health = http.get(`${BASE_URL}/healthz`, {
    responseCallback: http.expectedStatuses(200),
  });
  if (health.status !== 200) {
    fail(`setup: GET /healthz expected 200, got ${health.status} - daemon not ready`);
  }

  // (2) a VALID bearer on initialize (version-header EXEMPT) must be 200.
  const ok = http.post(`${BASE_URL}/`, INITIALIZE_BODY, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${BEARER}` },
    responseCallback: http.expectedStatuses(200),
  });
  if (ok.status !== 200) {
    fail(`setup: initialize with a valid bearer expected 200, got ${ok.status} - handshake broken`);
  }

  // (3) a WRONG bearer must be 401. This is the soundness guard: it proves the
  // measured surface is the AUTHENTICATED pipeline, not an open endpoint. If this
  // does not 401, auth is bypassed or the scenario is aimed at the wrong path, and
  // any latency number would be measuring the wrong thing - so we ABORT. 401 is
  // the EXPECTED status here, so it is not counted as an http_req_failed.
  const wrong = http.post(`${BASE_URL}/`, INITIALIZE_BODY, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer sk-ocu-wrong-bearer-not-in-boot-set',
    },
    responseCallback: http.expectedStatuses(401),
  });
  if (wrong.status !== 401) {
    fail(`setup: wrong bearer expected 401, got ${wrong.status} - measured path is NOT the authenticated pipeline`);
  }

  return { bearer: BEARER };
}

// Each measured iteration POSTs tools/list with the valid bearer AND the version
// header (tools/list requires the pin). It checks 200 and that the body carries
// "tools" (the embedded tool-list answer), so the measured op is the real
// gateway-local answer, not an error frame that happens to be fast.
export default function (data) {
  const res = http.post(`${BASE_URL}/`, TOOLS_LIST_BODY, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${data.bearer}`,
      'MCP-Protocol-Version': PROTOCOL_VERSION,
    },
  });
  check(res, {
    'tools/list is 200': (r) => r.status === 200,
    'body contains tools': (r) => typeof r.body === 'string' && r.body.indexOf('tools') !== -1,
  });
}

// handleSummary writes the k6 summary JSON to SUMMARY_PATH in the SAME FLAT shape
// --summary-export produces (metrics.<name>["p(95)"], the percentile keys hoisted
// out of the per-metric `values` object handleSummary nests them under). Emitting
// the export shape here means perf_compare.py reads ONE format regardless of how
// the run was invoked - the comparer never has to know it came from handleSummary
// rather than the --summary-export flag.
export function handleSummary(data) {
  const flat = { metrics: {} };
  for (const name in data.metrics) {
    const m = data.metrics[name];
    // Hoist the metric's `values` (avg/min/max/med/p(90)/p(95)/...) to the metric
    // object itself, exactly as --summary-export flattens it.
    flat.metrics[name] = Object.assign({}, m.values || {});
  }
  return {
    [SUMMARY_PATH]: JSON.stringify(flat),
  };
}
