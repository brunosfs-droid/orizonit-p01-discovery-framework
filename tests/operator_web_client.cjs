// Event-level client checks with a text-only DOM; this is not a browser renderer.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor() { this.children = []; this.handlers = {}; this.value = ''; this.hidden = false; this.disabled = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(x => x.textContent).join(''); }
  set innerHTML(_) { throw new Error('HTML injection sink used'); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this._text = ''; this.children = nodes; }
  addEventListener(type, handler) { this.handlers[type] = handler; }
  focus() { this.focused = true; }
  fire(type, extra = {}) { return this.handlers[type]?.({preventDefault() {}, ...extra}); }
}
const source = fs.readFileSync(path.join(__dirname, '../server/web/operator.js'), 'utf8');
function client() {
  const elements = new Map(), calls = [], timers = new Map(), events = {}, replies = [];
  let next = 1;
  const element = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const context = {
    document: {getElementById: element, createElement: () => new Element()},
    window: {addEventListener: (name, handler) => { events[name] = handler; }},
    URLSearchParams, AbortController,
    setTimeout: (handler, delay) => { const id = next++; timers.set(id, {handler, delay}); return id; },
    clearTimeout: id => timers.delete(id),
    fetch: async (url, options) => {
      calls.push({url, options});
      if (!replies.length) throw new Error('unexpected request');
      const reply = replies.shift(); return typeof reply === 'function' ? reply() : reply;
    }
  };
  vm.runInNewContext(source, context, {filename: 'operator.js'});
  element('page-size').value = '1';
  return {element, calls, timers, events, replies};
}
const response = (status, body) => ({ok: status >= 200 && status < 300, status, json: async () => body});
const session = {access_token: 't'.repeat(43), token_type: 'Bearer', operator_id: 'OP-01', expires_in: 900};
const malicious = '<img src=x onerror=alert(1)>';
function report(overrides = {}) {
  return {status:'found', assessment_id:'LAB-001', source_bytes_revalidated:false, lifecycle:{state:'completed',revision:4},
    identity:{central_asset_count:1}, recorded_finding_occurrences:2, snapshot_at_utc:'2026-10-03T03:00:00Z', report_scope_sha256:'a'.repeat(64),
    coverage:{evaluation_count:4, import_count:2, analyzed_import_count:2, credentialed_sources_evaluated:2, credentialed_sources_indexed:2,
      projection_status:'all_imports_analyzed', outcomes:{finding:2, no_finding:2, insufficient_evidence:0, not_applicable:0, not_supported:0}},
    evaluations:[{analysis_id:'ana-'+'1'.repeat(32), ordinal:0, rule_id:'WIN-AD-001', result:'finding', asset_id:'asset-01',
      source_path:malicious, source_sha256:'b'.repeat(64), bundle_id:'bundle-01', link_state:'linked', asset_decision:'linked', asset_reason_code:'exact',
      observation_ordinal:0, evidence_refs:[malicious], finding_id:'finding-01', finding_status:'Open', evidence:{text:malicious},
      rule:{title:malicious, recommendation:malicious}}],
    has_more:true, next_cursor:{after_analysis_id:'ana-'+'1'.repeat(32), after_ordinal:0}, ...overrides};
}
const tick = () => new Promise(resolve => setImmediate(resolve));
async function login(c) {
  c.element('username').value = 'reader'; c.element('password').value = 'Synthetic LAB passphrase 01!';
  c.replies.push(response(201, session)); await c.element('login-form').fire('submit');
  assert.equal(c.element('password').value, ''); assert.equal(c.element('username').value, '');
  assert.equal(c.element('login-panel').hidden, true);
}
async function read(c, doc = report()) {
  c.element('assessment').value = 'LAB-001'; c.replies.push(response(200, doc)); c.element('report-form').fire('submit'); await tick();
}
(async () => {
  // Login failure clears the password; no bearer sent to the login endpoint.
  let c = client(); c.element('username').value = 'reader'; c.element('password').value = 'PRIVATE';
  c.replies.push(response(401, {error_code:'invalid_credentials'})); await c.element('login-form').fire('submit');
  assert.equal(c.element('password').value, ''); assert.match(c.element('message').textContent, /inválidos/);
  assert.equal(c.calls[0].options.headers.Authorization, undefined);
  assert.equal(c.calls[0].options.credentials, 'omit'); assert.equal(c.calls[0].options.cache, 'no-store');
  assert.equal(c.calls[0].options.redirect, 'error');
  // Untrusted report strings remain text, and historical lifecycle/counts survive.
  c = client(); await login(c); await read(c);
  assert.equal(c.element('finding-count').textContent, '2'); assert.match(c.element('lifecycle').textContent, /completed/);
  assert.equal(c.element('evaluations').children.length, 1); assert.ok(c.element('evaluations').textContent.includes(malicious));
  assert.equal(c.calls[1].options.headers.Authorization, 'Bearer '+session.access_token);
  // Continue using the original selection, cursor and fence even if the input changed.
  c.element('assessment').value = 'LAB-OTHER'; c.element('page-size').value = '100';
  c.replies.push(response(200, report({has_more:false}))); c.element('next-button').fire('click'); await tick();
  const url = new URL(c.calls[2].url, 'http://localhost');
  assert.equal(url.pathname, '/api/v1/assessments/LAB-001/report'); assert.equal(url.searchParams.get('limit'), '1');
  assert.equal(url.searchParams.get('expected_scope_sha256'), 'a'.repeat(64)); assert.equal(url.searchParams.get('after_ordinal'), '0');
  assert.equal(c.element('next-button').disabled, true); assert.match(c.element('page-label').textContent, /Página 2/);
  // An HTTP conflict or malformed changed fence clears stale results.
  c.replies.push(response(409, {error_code:'report_scope_conflict'})); c.element('restart-button').fire('click'); await tick();
  assert.equal(c.element('report-panel').hidden, true); assert.equal(c.element('evaluations').children.length, 0);
  assert.equal(c.element('next-button').disabled, true); assert.match(c.element('message').textContent, /escopo mudou/);
  await read(c); c.replies.push(response(200, report({report_scope_sha256:'b'.repeat(64)}))); c.element('next-button').fire('click'); await tick();
  assert.equal(c.element('report-panel').hidden, true);
  // Logout clears data immediately, revokes the captured token, and ignores late data.
  c = client(); await login(c); await read(c);
  let release; c.replies.push(() => new Promise(resolve => { release = resolve; })); c.element('next-button').fire('click'); await tick();
  c.replies.push(response(200, {status:'logged_out'})); await c.element('logout-button').fire('click');
  assert.equal(c.element('workspace').hidden, true); assert.equal(c.element('operator-name').textContent, '');
  assert.equal(c.calls.at(-1).options.method, 'DELETE'); assert.equal(c.calls.at(-1).options.headers.Authorization, 'Bearer '+session.access_token);
  release(response(200, report())); await tick(); assert.equal(c.element('report-panel').hidden, true);
  // A 401, expiry timer and browser history restoration all clear client state.
  c = client(); await login(c); c.element('assessment').value='LAB-001'; c.replies.push(response(401, {})); c.element('report-form').fire('submit'); await tick();
  assert.equal(c.element('workspace').hidden, true);
  await login(c); const timer = [...c.timers.values()].find(x => x.delay === 900000); assert.ok(timer); timer.handler();
  assert.equal(c.element('workspace').hidden, true); assert.equal(c.element('assessment').value, '');
  await login(c); c.events.pageshow({persisted:true}); assert.equal(c.element('workspace').hidden, true);
  console.log('OPERATOR WEB CLIENT PASS — 6 behavioral groups');
})().catch(error => { console.error(error); process.exitCode = 1; });
