import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createBackup, parseBackup, mergeBackup } from '../src/app/services/backup';
import { MemoryStorage, passwordParams, securityKeyRecord } from './fixtures';

test('backup round-trips exact generation settings and encrypted key records', () => {
  const params = [passwordParams({
    name: ' \tMy site ', domain: ' EXAMPLE.com ', username: '用户\n', symbols: '!!@#@',
  })];
  const securityKeys = [securityKeyRecord()];
  const text = createBackup(params, securityKeys);
  assert.deepEqual(parseBackup(text), { params, securityKeys });
  assert.equal(JSON.parse(text).version, 1);
  assert.equal(JSON.parse(text).format, 'password-mgr-backup');
});

test('backup exports only persisted fields, excluding accidental plaintext master data', () => {
  const masterSecret = 'Unmistakable plaintext master 🔑';
  const params = [Object.assign(passwordParams(), { masterSecret })];
  const keys = [Object.assign(securityKeyRecord(), { masterSecret, unlockedSecret: masterSecret })];
  const text = createBackup(params, keys);
  assert.equal(text.includes(masterSecret), false);
  assert.deepEqual(parseBackup(text), {
    params: [passwordParams()], securityKeys: [securityKeyRecord()],
  });
});

test('invalid backup rejects the entire package without changing local storage', () => {
  const storage = new MemoryStorage();
  storage.setItem('password-mgr:params', 'existing settings');
  storage.setItem('password-mgr:security-keys:v1', 'existing keys');
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true });
  const writesBefore = storage.writes;
  const good = JSON.parse(createBackup([passwordParams()], [securityKeyRecord()]));
  const invalid = [
    '{broken',
    JSON.stringify({ ...good, version: 2 }),
    JSON.stringify({ ...good, format: 'some-other-app' }),
    JSON.stringify({ ...good, params: [passwordParams(), passwordParams({ length: 7 })] }),
    JSON.stringify({ ...good, params: [passwordParams({ counter: 1.5 })] }),
    JSON.stringify({ ...good, params: [{ ...passwordParams(), username: null }] }),
    JSON.stringify({ ...good, params: [passwordParams(), passwordParams()] }),
    JSON.stringify({ ...good, securityKeys: [securityKeyRecord({ ciphertext: 'bad' })] }),
    JSON.stringify({ ...good, securityKeys: [securityKeyRecord(), securityKeyRecord()] }),
    ' '.repeat(1_048_577),
  ];
  for (const text of invalid) assert.throws(() => parseBackup(text));
  assert.equal(storage.writes, writesBefore);
  assert.equal(storage.getItem('password-mgr:params'), 'existing settings');
  assert.equal(storage.getItem('password-mgr:security-keys:v1'), 'existing keys');
});

test('backup size limits count UTF-8 bytes rather than JavaScript characters', () => {
  const text = JSON.stringify({
    ...JSON.parse(createBackup([], [])),
    padding: '🔑'.repeat(280_000),
  });
  assert.ok(text.length < 1_048_576);
  assert.ok(Buffer.byteLength(text, 'utf8') > 1_048_576);
  assert.throws(() => parseBackup(text), /limit/i);
});

test('backup merge preserves existing entries and appends only new identities', () => {
  const existingParam = passwordParams({ name: 'Local edit' });
  const existingKey = securityKeyRecord({ name: 'Local key name' });
  const newParam = passwordParams({ id: 'site-2', domain: 'second.example' });
  const newKey = securityKeyRecord({ credentialId: Buffer.alloc(16, 9).toString('base64url') });
  const incoming = {
    params: [passwordParams({ name: 'Old backup name' }), newParam],
    securityKeys: [securityKeyRecord({ name: 'Old key name' }), newKey],
  };
  const result = mergeBackup([existingParam], [existingKey], incoming);
  assert.deepEqual(result, {
    params: [existingParam, newParam], securityKeys: [existingKey, newKey],
    addedParams: 1, addedKeys: 1,
  });
  assert.equal(existingParam.name, 'Local edit');
  assert.equal(existingKey.name, 'Local key name');
  const repeated = mergeBackup(result.params, result.securityKeys, incoming);
  assert.equal(repeated.addedParams, 0);
  assert.equal(repeated.addedKeys, 0);
});
