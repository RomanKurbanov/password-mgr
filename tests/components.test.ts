import '@angular/compiler';
import assert from 'node:assert/strict';
import { test, TestContext } from 'node:test';
import { Injector, runInInjectionContext, SimpleChange } from '@angular/core';
import { AppComponent } from '../src/app/app.component';
import { SecurityKeysComponent } from '../src/app/security-keys.component';
import { CryptoService } from '../src/app/services/crypto.service';
import { SecurityKeyService } from '../src/app/services/security-key.service';
import { SecurityKeyDiagnosticsService } from '../src/app/services/security-key-diagnostics.service';
import { StorageService } from '../src/app/services/storage.service';
import { createBackup } from '../src/app/services/backup';
import { PendingSecurityKeyEnrollment } from '../src/app/models/security-key.model';
import { passwordParams, securityKeyRecord } from './fixtures';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

function pendingEnrollment(overrides: Partial<PendingSecurityKeyEnrollment> = {}): PendingSecurityKeyEnrollment {
  const { ciphertext, ...pending } = securityKeyRecord(overrides);
  return pending;
}

function environment() {
  const events = new EventTarget();
  Object.defineProperties(globalThis, {
    CSS: { value: { supports: () => false }, configurable: true },
    window: { value: Object.assign(events, { location: new URL('https://password.example') }), configurable: true },
    navigator: { value: { clipboard: { writeText: async () => {} } }, configurable: true },
  });
  return events;
}

function promisedClipboard(t: TestContext, write: (items: ClipboardItem[]) => Promise<void>): void {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'ClipboardItem');
  class FakeClipboardItem {
    constructor(private readonly data: Record<string, Promise<Blob>>) {}
    getType(type: string): Promise<Blob> { return this.data[type]; }
  }
  Object.defineProperty(globalThis, 'ClipboardItem', { value: FakeClipboardItem, configurable: true });
  Object.assign(navigator.clipboard, { write });
  t.after(() => {
    if (original) Object.defineProperty(globalThis, 'ClipboardItem', original);
    else Reflect.deleteProperty(globalThis, 'ClipboardItem');
  });
}

function app(generator: Pick<CryptoService, 'generatePassword'>) {
  const events = environment();
  const injector = Injector.create({ providers: [
    { provide: CryptoService, useValue: generator },
    { provide: StorageService, useValue: { load: () => [], remove: () => [] } },
  ] });
  const component = runInInjectionContext(injector, () => new AppComponent());
  component.editParams.set(passwordParams());
  component.masterSecret.set('original master');
  return { component, events, generate: () => (component as any).doGenerate() as Promise<void> };
}

function controls(keyOverrides: Record<string, unknown> = {}, storageOverrides: Record<string, unknown> = {}) {
  environment();
  const writes: unknown[] = [];
  const keyService = {
    diagnostics: new SecurityKeyDiagnosticsService(),
    isSupported: () => true,
    load: () => [securityKeyRecord()],
    save: (keys: unknown) => { writes.push(keys); },
    beginEnrollment: async () => pendingEnrollment(),
    finishEnrollment: async () => securityKeyRecord(),
    ...keyOverrides,
  };
  const storage = { load: () => [], save: () => {}, ...storageOverrides };
  const injector = Injector.create({ providers: [
    { provide: SecurityKeyService, useValue: keyService },
    { provide: StorageService, useValue: storage },
  ] });
  const component = runInInjectionContext(injector, () => new SecurityKeysComponent());
  component.ngOnInit();
  return { component, writes, diagnostics: keyService.diagnostics };
}

test('manual generation and key unlock pass the identical secret and settings to the generator', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const calls: unknown[] = [];
  const { component, generate } = app({ generatePassword: async (secret, params) => {
    calls.push([secret, params]);
    return 'unchanged-password';
  } });
  await generate();
  assert.equal(component.keyUnlocked(), false);
  component.clearMasterSecret();
  component.onSecurityKeyUnlocked('original master');
  await generate();
  assert.deepEqual(calls[0], calls[1]);
  assert.equal(component.generatedPassword(), 'unchanged-password');
  assert.equal(component.keyUnlocked(), true);
  component.ngOnDestroy();
});

test('clearing the secret discards an in-flight generation result', async () => {
  const pending = deferred<string>();
  const { component, generate } = app({ generatePassword: () => pending.promise });
  const run = generate();
  assert.equal(component.generating(), true);
  component.clearMasterSecret();
  pending.resolve('must not reappear');
  await run;
  assert.equal(component.masterSecret(), '');
  assert.equal(component.generatedPassword(), '');
  assert.equal(component.generating(), false);
});

test('newer site edits win over a slower earlier password calculation', async () => {
  const older = deferred<string>();
  const newer = deferred<string>();
  let calls = 0;
  const { component, generate } = app({ generatePassword: () => ++calls === 1 ? older.promise : newer.promise });
  const first = generate();
  component.editParams.set(passwordParams({ domain: 'other.example' }));
  component.triggerRegenerate();
  const second = generate();
  newer.resolve('new result');
  await second;
  older.resolve('old result');
  await first;
  assert.equal(component.generatedPassword(), 'new result');
});

test('new entry and deletion invalidate pending password calculations', async () => {
  for (const action of ['newParam', 'deleteParam'] as const) {
    const pending = deferred<string>();
    const { component, generate } = app({ generatePassword: () => pending.promise });
    const run = generate();
    component[action]();
    pending.resolve('stale');
    await run;
    assert.equal(component.generatedPassword(), '');
  }
});

test('copy clears both secrets and reveal states after a successful write', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => '' });
  component.onSecurityKeyUnlocked('original master');
  component.generatedPassword.set('password to copy');
  component.showPassword.set(true);
  component.showMasterSecret.set(true);
  await component.copyPassword();
  assert.equal(component.masterSecret(), '');
  assert.equal(component.keyUnlocked(), false);
  assert.equal(component.generatedPassword(), '');
  assert.equal(component.showPassword(), false);
  assert.equal(component.showMasterSecret(), false);
  assert.equal(component.copySuccess(), true);
  component.ngOnDestroy();
});

test('a late clipboard success does not clear a newly entered secret', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => '' });
  const pending = deferred<void>();
  navigator.clipboard.writeText = () => pending.promise;
  component.generatedPassword.set('old password');
  const copy = component.copyPassword();
  component.masterSecret.set('new master');
  component.onMasterSecretChange();
  pending.resolve();
  await copy;
  assert.equal(component.masterSecret(), 'new master');
  component.ngOnDestroy();
});

test('copy still clears the same unlocked secret when site settings change during clipboard access', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => '' });
  const pending = deferred<void>();
  navigator.clipboard.writeText = () => pending.promise;
  component.onSecurityKeyUnlocked('original master');
  component.generatedPassword.set('old password');
  const copy = component.copyPassword();
  component.triggerRegenerate();
  pending.resolve();
  await copy;
  assert.equal(component.masterSecret(), '');
  assert.equal(component.keyUnlocked(), false);
  component.ngOnDestroy();
});

test('key and manual secrets expire after two minutes', t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => '' });
  component.onSecurityKeyUnlocked('original master');
  t.mock.timers.tick(2 * 60_000 - 1);
  assert.equal(component.masterSecret(), 'original master');
  t.mock.timers.tick(1);
  assert.equal(component.masterSecret(), '');
  component.onSecurityKeyUnlocked('original master');
  component.masterSecret.set('manual value');
  component.onMasterSecretChange();
  t.mock.timers.tick(2 * 60_000);
  assert.equal(component.masterSecret(), '');
  assert.equal(component.keyUnlocked(), false);
  component.ngOnDestroy();
});

test('leaving the page locks both manual and key sessions', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const { component, events } = app({ generatePassword: async () => '' });
  component.ngOnInit();
  events.dispatchEvent(new Event('pagehide'));
  assert.equal(component.masterSecret(), '');
  component.onSecurityKeyUnlocked('unlocked value');
  events.dispatchEvent(new Event('pagehide'));
  assert.equal(component.masterSecret(), '');
  component.ngOnDestroy();
});

test('cancelled unlock cannot emit a late decrypted secret', async () => {
  const pending = deferred<string>();
  let signal: AbortSignal | undefined;
  const { component } = controls({ unlock: (_key: unknown, received: AbortSignal) => {
    signal = received;
    return pending.promise;
  } });
  const emitted: string[] = [];
  component.unlocked.subscribe(value => emitted.push(value));
  const run = component.unlock();
  component.cancelOperation();
  pending.resolve('must be discarded');
  await run;
  assert.equal(signal!.aborted, true);
  assert.deepEqual(emitted, []);
  assert.equal(component.busy(), null);
});

test('editing or clearing the master cancels pending enrollment without saving', async () => {
  const pending = deferred<PendingSecurityKeyEnrollment>();
  const { component, writes } = controls({ beginEnrollment: () => pending.promise });
  component.masterSecret = 'master';
  component.keyName = 'Spare';
  const run = component.enroll();
  component.ngOnChanges({ resetVersion: new SimpleChange(0, 1, false) });
  pending.resolve(pendingEnrollment());
  await run;
  assert.deepEqual(writes, []);
});

test('destroyed controls discard late unlock results', async () => {
  const pending = deferred<string>();
  const { component } = controls({ unlock: () => pending.promise });
  let emitted = false;
  component.unlocked.subscribe(() => { emitted = true; });
  const run = component.unlock();
  component.ngOnDestroy();
  pending.resolve('late secret');
  await run;
  assert.equal(emitted, false);
});

test('failed enrollment persistence leaves the previous key list intact', async () => {
  const original = securityKeyRecord();
  const { component } = controls({
    finishEnrollment: async () => securityKeyRecord({ name: 'Spare', credentialId: 'Ag' }),
    save: () => { throw new Error('storage is full'); },
  });
  component.masterSecret = 'master';
  component.keyName = 'Spare';
  await component.enroll();
  await component.finishEnrollment();
  assert.deepEqual(component.keys(), [original]);
  assert.match(component.error(), /storage is full/);
});

test('invalid backup changes neither key storage nor site settings', async () => {
  let siteWrites = 0;
  const { component, writes } = controls({}, { save: () => { siteWrites++; } });
  const input = { files: [{ size: 3, text: async () => 'bad' }], value: 'backup.json' };
  await component.importBackup(input as unknown as HTMLInputElement);
  assert.deepEqual(writes, []);
  assert.equal(siteWrites, 0);
  assert.match(component.error(), /JSON/);
});

test('site-storage failure rolls back imported key records and publishes no changes', async () => {
  const { component, writes } = controls({}, { save: () => { throw new Error('quota'); } });
  const backup = createBackup([passwordParams()], [securityKeyRecord({ credentialId: 'Ag' })]);
  let emitted = false;
  component.paramsImported.subscribe(() => { emitted = true; });
  const input = { files: [{ size: backup.length, text: async () => backup }], value: 'backup.json' };
  await component.importBackup(input as unknown as HTMLInputElement);
  assert.equal(writes.length, 2);
  assert.deepEqual(writes[1], [securityKeyRecord()]);
  assert.deepEqual(component.keys(), [securityKeyRecord()]);
  assert.equal(emitted, false);
});

test('successful import keeps existing site settings and key records', async () => {
  let saved: unknown;
  const { component, writes } = controls({}, {
    load: () => [passwordParams()], save: (params: unknown) => { saved = params; },
  });
  const backup = createBackup([
    passwordParams({ domain: 'must-not-replace.example' }), passwordParams({ id: 'new-site' }),
  ], [securityKeyRecord({ name: 'must-not-replace' })]);
  const input = { files: [{ size: backup.length, text: async () => backup }], value: 'backup.json' };
  await component.importBackup(input as unknown as HTMLInputElement);
  assert.deepEqual(saved, [passwordParams(), passwordParams({ id: 'new-site' })]);
  assert.deepEqual(writes[0], [securityKeyRecord()]);
  assert.match(component.message(), /Imported 1 site settings and 0 keys/);
});

test('enrollment preserves keys saved by another tab while the browser prompt was open', async () => {
  const primary = securityKeyRecord();
  const otherTab = securityKeyRecord({ credentialId: 'Ag', name: 'Other tab key' });
  const added = securityKeyRecord({ credentialId: 'Aw', name: 'New key' });
  const pending = deferred<ReturnType<typeof securityKeyRecord>>();
  let stored = [primary];
  const { component } = controls({
    load: () => stored,
    save: (keys: typeof stored) => { stored = keys; },
    beginEnrollment: async () => pendingEnrollment({ credentialId: added.credentialId }),
    finishEnrollment: () => pending.promise,
  });
  component.masterSecret = 'master';
  component.keyName = 'New key';
  await component.enroll();
  const run = component.finishEnrollment();
  stored = [primary, otherTab];
  pending.resolve(added);
  await run;
  assert.deepEqual(stored, [primary, otherTab, added]);
  assert.deepEqual(component.keys(), stored);
});

test('registration waits for a separate Finish setup action before encryption or persistence', async () => {
  let registrationCalls = 0;
  let finishCalls = 0;
  const added = securityKeyRecord({ credentialId: 'Ag', name: 'Spare' });
  const { component, writes } = controls({
    beginEnrollment: async () => {
      registrationCalls++;
      return pendingEnrollment({ credentialId: added.credentialId });
    },
    finishEnrollment: async () => { finishCalls++; return added; },
  });
  component.masterSecret = 'original master';
  component.keyName = 'Spare';
  await component.enroll();
  assert.equal(registrationCalls, 1);
  assert.equal(finishCalls, 0);
  assert.deepEqual(writes, []);
  assert.ok(component.pendingEnrollment());
  assert.equal(component.busy(), null);
  await component.finishEnrollment();
  assert.equal(finishCalls, 1);
  assert.equal(writes.length, 1);
  assert.equal(component.pendingEnrollment(), null);
});

test('failed Finish setup can retry without registering another credential', async () => {
  let registrationCalls = 0;
  let finishCalls = 0;
  const added = securityKeyRecord({ credentialId: 'Ag' });
  const { component, writes } = controls({
    beginEnrollment: async () => {
      registrationCalls++;
      return pendingEnrollment({ credentialId: added.credentialId });
    },
    finishEnrollment: async () => {
      if (++finishCalls === 1) throw new Error('Encryption setup: NotAllowedError');
      return added;
    },
  });
  component.masterSecret = 'original master';
  component.keyName = 'Spare';
  await component.enroll();
  const pending = component.pendingEnrollment();
  await component.finishEnrollment();
  assert.match(component.error(), /Encryption setup/);
  assert.equal(component.pendingEnrollment(), pending);
  assert.deepEqual(writes, []);
  await component.finishEnrollment();
  assert.equal(registrationCalls, 1);
  assert.equal(finishCalls, 2);
  assert.equal(writes.length, 1);
  assert.equal(component.error(), '');
});

test('master-secret reset discards a registered pending credential and prevents finishing', async () => {
  let finishCalls = 0;
  const { component, writes } = controls({ finishEnrollment: async () => {
    finishCalls++;
    return securityKeyRecord();
  } });
  component.masterSecret = 'master';
  component.keyName = 'Spare';
  await component.enroll();
  assert.ok(component.pendingEnrollment());
  component.ngOnChanges({ resetVersion: new SimpleChange(0, 1, false) });
  await component.finishEnrollment();
  assert.equal(component.pendingEnrollment(), null);
  assert.equal(finishCalls, 0);
  assert.deepEqual(writes, []);
});

test('cancelling a pending finish discards late encryption and clears stale error messages', async () => {
  const pending = deferred<ReturnType<typeof securityKeyRecord>>();
  const { component, writes } = controls({ finishEnrollment: () => pending.promise });
  component.masterSecret = 'master';
  component.keyName = 'Spare';
  await component.enroll();
  const run = component.finishEnrollment();
  component.error.set('Retry Finish setup');
  component.cancelOperation();
  pending.resolve(securityKeyRecord({ credentialId: 'Ag' }));
  await run;
  assert.equal(component.pendingEnrollment(), null);
  assert.equal(component.error(), '');
  assert.deepEqual(writes, []);
});

test('removing a key preserves records added by another tab', () => {
  const primary = securityKeyRecord();
  const otherTab = securityKeyRecord({ credentialId: 'Ag', name: 'Other tab key' });
  let stored = [primary];
  const { component } = controls({
    load: () => stored,
    save: (keys: typeof stored) => { stored = keys; },
  });
  stored = [primary, otherTab];
  component.removeKey(primary);
  assert.deepEqual(stored, [otherTab]);
});

test('import merges the latest persisted settings instead of a stale tab snapshot', async () => {
  const primary = securityKeyRecord();
  const otherTabKey = securityKeyRecord({ credentialId: 'Ag' });
  let storedKeys = [primary];
  let storedParams = [passwordParams()];
  const { component } = controls({
    load: () => storedKeys,
    save: (keys: typeof storedKeys) => { storedKeys = keys; },
  }, {
    load: () => storedParams,
    save: (params: typeof storedParams) => { storedParams = params; },
  });
  storedKeys = [primary, otherTabKey];
  storedParams = [passwordParams(), passwordParams({ id: 'other-tab-site' })];
  const backup = createBackup([passwordParams({ id: 'imported-site' })], []);
  const input = { files: [{ size: backup.length, text: async () => backup }], value: 'backup.json' };
  await component.importBackup(input as unknown as HTMLInputElement);
  assert.deepEqual(storedKeys, [primary, otherTabKey]);
  assert.deepEqual(storedParams.map(item => item.id), ['site-1', 'other-tab-site', 'imported-site']);
});

test('diagnostic controls enable the shared recorder and disabling clears the report', () => {
  const { component, writes, diagnostics } = controls();
  assert.equal(diagnostics.enabled(), false);
  component.toggleDiagnostics(true);
  assert.equal(diagnostics.enabled(), true);
  const operation = diagnostics.begin('unlock', 'get');
  diagnostics.fail(operation, new DOMException('private browser error text', 'NotAllowedError'));
  assert.equal(diagnostics.entries().length, 1);
  assert.match(diagnostics.exportReport(), /NotAllowedError/);
  component.diagnosticCopyMessage.set('old copy status');
  component.toggleDiagnostics(false);
  assert.equal(diagnostics.enabled(), false);
  assert.deepEqual(diagnostics.entries(), []);
  assert.equal(diagnostics.exportReport(), '');
  assert.equal(component.diagnosticCopyMessage(), '');
  assert.deepEqual(writes, []);
});

test('copying diagnostics writes only the sanitized report to the clipboard', async () => {
  const { component, writes, diagnostics } = controls();
  component.masterSecret = 'private-master-for-copy-test';
  component.keyName = 'private-key-label-for-copy-test';
  component.toggleDiagnostics(true);
  const operation = diagnostics.begin('setup', 'get');
  diagnostics.fail(operation, new DOMException(component.masterSecret + component.keyName, 'NotAllowedError'));
  const report = diagnostics.exportReport();
  const clipboard: string[] = [];
  navigator.clipboard.writeText = async text => { clipboard.push(text); };
  await component.copyDiagnostics();
  assert.deepEqual(clipboard, [report]);
  assert.equal(report.includes(component.masterSecret), false);
  assert.equal(report.includes(component.keyName), false);
  assert.match(component.diagnosticCopyMessage(), /copied/i);
  assert.deepEqual(writes, []);
});

test('diagnostic clipboard failure gives an actionable message without writing keys or secrets', async () => {
  const { component, writes, diagnostics } = controls();
  component.masterSecret = 'private-master-never-to-persist';
  component.toggleDiagnostics(true);
  const operation = diagnostics.begin('unlock', 'get');
  diagnostics.fail(operation, new DOMException('private exception contents', 'NotAllowedError'));
  navigator.clipboard.writeText = async () => { throw new Error(component.masterSecret); };
  await component.copyDiagnostics();
  assert.ok(component.diagnosticCopyMessage().length > 0);
  assert.equal(component.diagnosticCopyMessage().includes(component.masterSecret), false);
  assert.equal(diagnostics.exportReport().includes(component.masterSecret), false);
  assert.equal(diagnostics.entries().length, 1, 'the report remains available for manual copying');
  assert.deepEqual(writes, []);
});


test('failed copying retains the password and never clears the clipboard later', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => '' });
  const written: string[] = [];
  navigator.clipboard.writeText = async text => { written.push(text); throw new Error('denied'); };
  component.generatedPassword.set('retry-me');
  t.mock.method(component as any, 'delay', async () => {});
  await component.copyPassword();
  assert.equal(component.copyError(), true);
  assert.equal(component.generatedPassword(), 'retry-me');
  assert.equal(component.masterSecret(), 'original master');
  navigator.clipboard.writeText = async text => { written.push(text); };
  await component.copyPassword();
  written.push('unrelated clipboard content');
  t.mock.timers.tick(30_000);
  assert.equal(written.at(-1), 'unrelated clipboard content');
  assert.equal(written.includes(''), false);
  component.ngOnDestroy();
});

test('locking during clipboard retries prevents further writes or stale feedback', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => '' });
  let writes = 0;
  navigator.clipboard.writeText = async () => { writes++; throw new Error('denied'); };
  component.generatedPassword.set('password');
  const copy = component.copyPassword();
  await Promise.resolve();
  component.clearMasterSecret();
  t.mock.timers.tick(150);
  await copy;
  assert.equal(writes, 1);
  assert.equal(component.copyError(), false);
  assert.equal(component.copySuccess(), false);
  component.ngOnDestroy();
});

test('unrelated activity does not extend manual or key secret deadlines', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'] });
  const { component, events } = app({ generatePassword: async () => '' });
  component.ngOnInit();
  component.onMasterSecretChange();
  t.mock.timers.tick(60_000);
  events.dispatchEvent(new Event('keydown'));
  events.dispatchEvent(new Event('pointerdown'));
  t.mock.timers.tick(59_999);
  assert.equal(component.masterSecret(), 'original master');
  t.mock.timers.tick(1);
  assert.equal(component.masterSecret(), '');
  component.onSecurityKeyUnlocked('key secret');
  t.mock.timers.tick(60_000);
  events.dispatchEvent(new Event('pointerdown'));
  t.mock.timers.tick(59_999);
  assert.equal(component.masterSecret(), 'key secret');
  t.mock.timers.tick(1);
  assert.equal(component.masterSecret(), '');
  component.ngOnDestroy();
});

test('editing the master password restarts its two-minute deadline', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { component } = app({ generatePassword: async () => '' });
  component.onMasterSecretChange();
  t.mock.timers.tick(90_000);
  component.masterSecret.set('edited master');
  component.onMasterSecretChange();
  t.mock.timers.tick(119_999);
  assert.equal(component.masterSecret(), 'edited master');
  t.mock.timers.tick(1);
  assert.equal(component.masterSecret(), '');
  component.ngOnDestroy();
});

test('emptying the master password cancels its clearing timer', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { component } = app({ generatePassword: async () => '' });
  component.onMasterSecretChange();
  t.mock.timers.tick(60_000);
  component.masterSecret.set('');
  component.onMasterSecretChange();
  const clear = t.mock.method(component, 'clearMasterSecret');
  t.mock.timers.tick(2 * 60_000);
  assert.equal(component.masterSecret(), '');
  assert.equal(clear.mock.calls.length, 0);
  component.ngOnDestroy();
});

test('resuming after a suspended deadline locks before activity can extend it', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'] });
  const { component, events } = app({ generatePassword: async () => '' });
  component.ngOnInit();
  component.onMasterSecretChange();
  t.mock.timers.setTime(Date.now() + 2 * 60_000);
  events.dispatchEvent(new Event('focus'));
  events.dispatchEvent(new Event('keydown'));
  assert.equal(component.masterSecret(), '');
  assert.equal(component.generatedPassword(), '');
  component.ngOnDestroy();
});

test('pagehide prevents pending generation from restoring a manual password', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const pending = deferred<string>();
  const { component, events, generate } = app({ generatePassword: () => pending.promise });
  component.ngOnInit();
  const run = generate();
  events.dispatchEvent(new Event('pagehide'));
  pending.resolve('stale-password');
  await run;
  assert.equal(component.masterSecret(), '');
  assert.equal(component.generatedPassword(), '');
  component.ngOnDestroy();
});

test('failed storage writes leave saved list, selection and editing timestamp unchanged', () => {
  environment();
  const original = passwordParams();
  const injector = Injector.create({ providers: [
    { provide: CryptoService, useValue: {} },
    { provide: StorageService, useValue: {
      load: () => [original],
      save: () => { throw new Error('Storage full'); },
      remove: () => { throw new Error('Storage denied'); },
    } },
  ] });
  const component = runInInjectionContext(injector, () => new AppComponent());
  component.savedParams.set([original]);
  component.editParams.set({ ...original, name: 'unsaved' });
  component.saveParam();
  assert.deepEqual(component.savedParams(), [original]);
  assert.equal(component.selectedId(), null);
  assert.equal(component.editParams()?.updatedAt, original.updatedAt);
  assert.match(component.storageError(), /Storage full/);
  component.deleteParam();
  assert.equal(component.editParams()?.name, 'unsaved');
  assert.deepEqual(component.savedParams(), [original]);
  assert.match(component.storageError(), /Storage denied/);
  component.ngOnDestroy();
});

test('corrupted site settings block imports before any key write', async () => {
  const { component, writes } = controls({}, {
    load: () => { throw new Error('Saved site settings are damaged'); },
  });
  const backup = createBackup([passwordParams()], []);
  const input = { files: [{ size: backup.length, text: async () => backup }], value: 'backup.json' };
  await component.importBackup(input as unknown as HTMLInputElement);
  assert.deepEqual(writes, []);
  assert.match(component.error(), /damaged/);
});

test('retrieval searches account fields and cancel restores saved settings', () => {
  const { component } = app({ generatePassword: async () => 'password' });
  const saved = passwordParams({ name: 'Railway', domain: 'rail.example', username: 'traveller' });
  component.savedParams.set([saved]);
  component.searchQuery.set('TRAVELLER');
  assert.equal(component.filteredParams().length, 1);
  component.searchQuery.set('missing');
  assert.equal(component.filteredParams().length, 0);
  component.selectParam(saved.id);
  assert.equal(component.editing(), false);
  component.editing.set(true);
  component.editParams.set({ ...saved, length: 32 });
  component.cancelEdit();
  assert.deepEqual(component.editParams(), saved);
  assert.equal(component.editing(), false);
});

test('copy intent generates, copies, and locks without revealing the password', async () => {
  const { component } = app({ generatePassword: async () => 'generated result' });
  const copied: string[] = [];
  navigator.clipboard.writeText = async text => { copied.push(text); };
  await component.generateAndCopy();
  assert.deepEqual(copied, ['generated result']);
  assert.equal(component.masterSecret(), '');
  assert.equal(component.showPassword(), false);
  assert.equal(component.copySuccess(), true);
});

test('changing accounts during unlock-and-copy never copies another account', async () => {
  const pending = deferred<string>();
  const { component } = app({ generatePassword: () => pending.promise });
  const copied: string[] = [];
  navigator.clipboard.writeText = async text => { copied.push(text); };
  const run = component.generateAndCopy();
  component.newParam();
  pending.resolve('old account');
  await run;
  assert.deepEqual(copied, []);
});

test('a key unlock waits for a fresh copy click, and a denied copy retains the key session for retry', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component, generate } = app({ generatePassword: async () => 'key password' });
  let attempts = 0;
  navigator.clipboard.writeText = async () => { attempts++; throw new DOMException('denied', 'NotAllowedError'); };
  component.onKeyUnlocked('unlocked master');
  await generate();
  assert.equal(attempts, 0, 'unlocking must not write after the WebAuthn prompt');
  await component.generateAndCopy();
  assert.equal(attempts, 1, 'permission failures need another click, not timed retries');
  assert.equal(component.copyError(), true);
  assert.match(component.copyErrorMessage(), /Click Copy password again/);
  assert.equal(component.masterSecret(), 'unlocked master');
  assert.equal(component.generatedPassword(), 'key password');
  assert.equal(component.keyUnlocked(), true);
  navigator.clipboard.writeText = async text => { assert.equal(text, 'key password'); attempts++; };
  await component.generateAndCopy();
  assert.equal(attempts, 2);
  assert.equal(component.masterSecret(), '');
  assert.equal(component.generatedPassword(), '');
  assert.equal(component.keyUnlocked(), false);
  assert.equal(component.copySuccess(), true);
  component.ngOnDestroy();
});

test('promised clipboard writing starts before asynchronous password generation completes', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const pending = deferred<string>();
  const { component } = app({ generatePassword: () => pending.promise });
  const copied: string[] = [];
  let started = false;
  promisedClipboard(t, async items => {
    started = true;
    copied.push(await (await items[0].getType('text/plain')).text());
  });
  const run = component.generateAndCopy();
  assert.equal(started, true, 'the native write must start within the original click');
  assert.deepEqual(copied, []);
  assert.equal(component.masterSecret(), 'original master');
  pending.resolve('generated asynchronously');
  await run;
  assert.deepEqual(copied, ['generated asynchronously']);
  assert.equal(component.copySuccess(), true);
  assert.equal(component.masterSecret(), '');
  assert.equal(component.generatedPassword(), '');
  component.ngOnDestroy();
});

test('a rejected promised clipboard write preserves the generated password for a fresh click', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => 'keep for retry' });
  let attempts = 0;
  promisedClipboard(t, async () => { attempts++; throw new DOMException('blocked', 'NotAllowedError'); });
  await component.generateAndCopy();
  assert.equal(attempts, 1);
  assert.equal(component.generatedPassword(), 'keep for retry');
  assert.equal(component.masterSecret(), 'original master');
  assert.equal(component.copyError(), true);
  let copied = '';
  navigator.clipboard.writeText = async text => { copied = text; };
  await component.generateAndCopy();
  assert.equal(copied, 'keep for retry');
  assert.equal(component.masterSecret(), '');
  component.ngOnDestroy();
});

test('locking during promised clipboard generation prevents the secret from reaching the clipboard', async t => {
  const pending = deferred<string>();
  const { component } = app({ generatePassword: () => pending.promise });
  const copied: string[] = [];
  promisedClipboard(t, async items => { copied.push(await (await items[0].getType('text/plain')).text()); });
  const run = component.generateAndCopy();
  component.clearMasterSecret();
  pending.resolve('must not copy');
  await run;
  assert.deepEqual(copied, []);
  assert.equal(component.masterSecret(), '');
  assert.equal(component.generatedPassword(), '');
  assert.equal(component.copyError(), false);
});

test('switching accounts during promised clipboard generation rejects the old account password', async t => {
  const pending = deferred<string>();
  const { component } = app({ generatePassword: () => pending.promise });
  const copied: string[] = [];
  promisedClipboard(t, async items => { copied.push(await (await items[0].getType('text/plain')).text()); });
  const run = component.generateAndCopy();
  component.newParam();
  pending.resolve('old account password');
  await run;
  assert.deepEqual(copied, []);
});
