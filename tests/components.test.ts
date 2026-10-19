import '@angular/compiler';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Injector, runInInjectionContext, SimpleChange } from '@angular/core';
import { AppComponent } from '../src/app/app.component';
import { SecurityKeysComponent } from '../src/app/security-keys.component';
import { CryptoService } from '../src/app/services/crypto.service';
import { SecurityKeyService } from '../src/app/services/security-key.service';
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
  return { component, writes };
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

test('copy keeps the generated password and clears the master as before', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => '' });
  component.onSecurityKeyUnlocked('original master');
  component.generatedPassword.set('password to copy');
  await component.copyPassword();
  assert.equal(component.masterSecret(), '');
  assert.equal(component.keyUnlocked(), false);
  assert.equal(component.generatedPassword(), 'password to copy');
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

test('key sessions expire in five minutes without timing out manual entry', t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { component } = app({ generatePassword: async () => '' });
  component.onSecurityKeyUnlocked('original master');
  t.mock.timers.tick(5 * 60_000 - 1);
  assert.equal(component.masterSecret(), 'original master');
  t.mock.timers.tick(1);
  assert.equal(component.masterSecret(), '');
  component.onSecurityKeyUnlocked('original master');
  component.masterSecret.set('manual value');
  component.onMasterSecretChange();
  t.mock.timers.tick(5 * 60_000);
  assert.equal(component.masterSecret(), 'manual value');
  assert.equal(component.keyUnlocked(), false);
  component.ngOnDestroy();
});

test('leaving the page locks a key session but preserves the manual-entry behavior', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const { component, events } = app({ generatePassword: async () => '' });
  component.ngOnInit();
  events.dispatchEvent(new Event('pagehide'));
  assert.equal(component.masterSecret(), 'original master');
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
