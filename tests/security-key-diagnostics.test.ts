import '@angular/compiler';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SecurityKeyDiagnosticsService } from '../src/app/services/security-key-diagnostics.service';

function installEnvironment() {
  let time = 100;
  const activation = { isActive: false, hasBeenActive: true };
  const surface: Record<string, unknown> = {
    isSecureContext: true,
    location: { origin: 'https://password.example/private-path?secret=query#fragment' },
  };
  surface['self'] = surface;
  surface['top'] = surface;
  Object.defineProperties(globalThis, {
    window: { value: surface, configurable: true },
    document: { value: { visibilityState: 'visible' }, configurable: true },
    navigator: { value: {
      userAgent: 'TestBrowser/1.0', userActivation: activation,
      credentials: { create() {}, get() {} },
    }, configurable: true },
    PublicKeyCredential: { value: class {}, configurable: true },
    performance: { value: { now: () => time }, configurable: true },
  });
  return { activation, advance: (milliseconds: number) => { time += milliseconds; } };
}

test('diagnostics are opt-in, have no disabled report, and disabling clears pending data', () => {
  installEnvironment();
  const service = new SecurityKeyDiagnosticsService();
  assert.equal(service.enabled(), false);
  const ignored = service.begin('registration', 'create');
  assert.equal(ignored, 0);
  service.event(ignored, 'prf-result', { enabled: true, resultPresent: true, resultLength: 32 });
  service.fail(ignored, new DOMException('must not log', 'NotAllowedError'));
  service.success(ignored, 'credential-registered');
  assert.deepEqual(service.entries(), []);
  assert.equal(service.exportReport(), '');

  service.setEnabled(true);
  const active = service.begin('registration', 'create');
  assert.equal(service.entries().length, 1);
  service.setEnabled(false);
  assert.deepEqual(service.entries(), []);
  assert.equal(service.exportReport(), '');
  service.setEnabled(true);
  service.success(active, 'credential-registered');
  assert.deepEqual(service.entries(), [], 'late results from a disabled session must be ignored');
});

test('diagnostics whitelist fields and values instead of serializing caller objects', () => {
  const { activation, advance } = installEnvironment();
  const service = new SecurityKeyDiagnosticsService();
  service.setEnabled(true);
  const secret = 'NEVER_INCLUDE_master_PIN_label_credential_ciphertext_PRF_salts';
  const id = service.begin('setup', 'get');
  activation.isActive = true;
  advance(10);
  const sensitiveExtras = {
    masterSecret: secret, pin: secret, name: secret, credentialId: secret,
    ciphertext: secret, prfSalt: secret, hkdfSalt: secret,
    nested: { rawPrf: secret }, toJSON() { throw new Error('Caller serialization is forbidden'); },
  };
  service.event(id, 'request-options', {
    residentKey: 'required', userVerification: 'required', authenticatorAttachment: 'cross-platform',
    extensions: ['prf', secret], algorithmIds: [-7, -257, 12345, secret], ...sensitiveExtras,
  });
  service.event(id, 'credential-response', { attachment: 'cross-platform', ...sensitiveExtras });
  service.event(id, 'prf-result', { enabled: true, resultPresent: true, resultLength: 32, ...sensitiveExtras });
  service.event(id, 'verification', { userVerified: true, ...sensitiveExtras });
  service.event(id, 'encryption-verified', { verified: true, ...sensitiveExtras });
  service.event(id, secret as any, sensitiveExtras);
  service.event(id, 'verification', { userVerified: secret });
  service.success(id, secret as any);

  const text = service.exportReport();
  assert.equal(text.includes(secret), false);
  assert.equal(text.includes('private-path'), false);
  assert.equal(text.includes('secret=query'), false);
  const report = JSON.parse(text);
  const entry = report.entries[0];
  assert.equal(report.format, 'password-mgr-security-key-diagnostics');
  assert.equal(typeof report.buildId, 'string');
  assert.equal(entry.environment.origin, 'https://password.example');
  assert.equal(entry.environment.browserUA, 'TestBrowser/1.0');
  assert.equal(entry.environment.userActivation.isActive, false);
  assert.equal(entry.events[0].environment.userActivation.isActive, true,
    'request options must capture a fresh activation snapshot');
  assert.deepEqual(entry.events[0].details, {
    residentKey: 'required', userVerification: 'required', authenticatorAttachment: 'cross-platform',
    extensions: ['prf'], algorithmIds: [-7, -257], algorithmCount: 2,
  });
  assert.deepEqual(entry.events[2].details, { enabled: true, resultPresent: true, resultLength: 32 });
  assert.equal('summary' in entry, false);
});

test('diagnostics record only bounded error names, legacy codes, and abort state', () => {
  installEnvironment();
  const service = new SecurityKeyDiagnosticsService();
  service.setEnabled(true);
  const secret = 'secret-browser-message-stack-abort-reason';
  const id = service.begin('setup', 'get');
  const controller = new AbortController();
  controller.abort(secret);
  service.fail(id, new DOMException(secret, 'NotAllowedError'), controller.signal);
  const unknown = service.begin('unlock', 'get');
  const error = new Error(secret);
  error.name = secret;
  Object.assign(error, { code: 9999, stack: secret });
  service.fail(unknown, error);
  const plain = service.begin('registration', 'create');
  service.fail(plain, { name: secret, code: 12, message: secret, stack: secret });

  const text = service.exportReport();
  assert.equal(text.includes(secret), false);
  const rows = JSON.parse(text).entries;
  assert.deepEqual(rows[0].error, { name: 'NotAllowedError', code: 0, aborted: true });
  assert.deepEqual(rows[1].error, { name: 'Other', aborted: false });
  assert.deepEqual(rows[2].error, { name: 'Other', aborted: false });
  for (const row of rows) {
    assert.equal('message' in row.error, false);
    assert.equal('stack' in row.error, false);
  }
});

test('diagnostics cap requests and events and measure rounded bounded durations', () => {
  const { advance } = installEnvironment();
  const service = new SecurityKeyDiagnosticsService();
  service.setEnabled(true);
  for (let i = 0; i < 60; i++) {
    const id = service.begin('unlock', 'get');
    advance(1.6);
    for (let j = 0; j < 30; j++) service.event(id, 'prf-result', { resultLength: j === 0 ? 99999 : 32 });
    advance(3.6);
    service.success(id, 'master-unlocked');
    service.fail(id, new Error('late error'));
  }
  const entries = service.entries();
  assert.equal(entries.length, 50);
  assert.equal(entries[0].id, 11);
  assert.equal(entries.at(-1)!.id, 60);
  assert.equal(entries[0].events.length, 16);
  assert.equal(entries[0].events[0].details['resultLength'], 'over-64');
  assert.equal(entries[0].events[0].elapsedMs, 2);
  assert.equal(entries[0].elapsedMs, 5);
  assert.equal(entries[0].status, 'succeeded');
  assert.equal(entries[0].summary, 'master-unlocked');
  assert.equal(entries[0].error, undefined);
  const backwards = service.begin('unlock', 'get');
  advance(-1_000_000);
  service.success(backwards);
  assert.equal(service.entries().at(-1)!.elapsedMs, 0);
  const enormous = service.begin('unlock', 'get');
  advance(1_000_000_000);
  service.success(enormous);
  assert.equal(service.entries().at(-1)!.elapsedMs, 86_400_000);
});

test('report export rebuilds its schema and clear prevents late completion from restoring data', () => {
  installEnvironment();
  const service = new SecurityKeyDiagnosticsService();
  service.setEnabled(true);
  const id = service.begin('registration', 'create');
  service.event(id, 'prf-result', { enabled: true });
  const secret = 'extra-properties-must-never-be-exported';
  Object.assign(service.entries()[0], { masterSecret: secret, toJSON() { throw new Error(secret); } });
  Object.assign(service.entries()[0].events[0].details, { rawPrf: secret });
  Object.assign(service.entries()[0].events[0], { pin: secret });
  assert.equal(service.exportReport().includes(secret), false);
  service.clear();
  service.fail(id, new DOMException(secret, 'NotAllowedError'));
  assert.equal(service.enabled(), true);
  assert.deepEqual(service.entries(), []);
  const next = service.begin('registration', 'create');
  assert.ok(next > id, 'clear must not reuse IDs while previous operations can finish');
});
