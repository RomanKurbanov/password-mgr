import '@angular/compiler';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { SecurityKeyService } from '../src/app/services/security-key.service';
import { CryptoService } from '../src/app/services/crypto.service';
import { MemoryStorage, passwordParams, securityKeyRecord } from './fixtures';

const storageKey = 'password-mgr:security-keys:v1';

async function enroll(service: SecurityKeyService, master: string, name: string, signal?: AbortSignal) {
  const pending = await service.beginEnrollment(name, signal);
  return service.finishEnrollment(pending, master, signal);
}

class FakeAuthenticator {
  readonly storage = new MemoryStorage();
  readonly location = new URL('https://password.example');
  readonly creates: CredentialCreationOptions[] = [];
  readonly gets: CredentialRequestOptions[] = [];
  readonly prfOutputs: Uint8Array[] = [];
  prfAvailable = true;
  getPrfAvailable = true;
  wrongPrf = false;
  wrongCredential = false;
  flags = 0x05;
  attachment = 'cross-platform';
  createError: Error | undefined;
  getError: Error | undefined;
  onGet: (() => void) | undefined;

  install(): SecurityKeyService {
    Object.defineProperties(globalThis, {
      window: { value: { isSecureContext: true, location: this.location }, configurable: true },
      PublicKeyCredential: { value: class {}, configurable: true },
      localStorage: { value: this.storage, configurable: true },
      navigator: {
        configurable: true,
        value: {
          credentials: {
            create: async (options: CredentialCreationOptions) => {
              this.creates.push(options);
              if (this.createError) throw this.createError;
              return this.credential(new Uint8Array(16).fill(this.creates.length), true);
            },
            get: async (options: CredentialRequestOptions) => {
              this.gets.push(options);
              if (this.getError) throw this.getError;
              this.onGet?.();
              const descriptor = options.publicKey!.allowCredentials![0];
              const requestedId = new Uint8Array(descriptor.id as ArrayBuffer);
              const rawId = this.wrongCredential ? new Uint8Array(16).fill(255) : requestedId;
              const salt = (options.publicKey!.extensions as any).prf.eval.first;
              const output = createHash('sha256')
                .update(requestedId).update(new Uint8Array(salt))
                .update(this.wrongPrf ? 'wrong-device-secret' : 'device-secret').digest();
              this.prfOutputs.push(new Uint8Array(output));
              return this.credential(rawId, false, new Uint8Array(output));
            },
          },
        },
      },
    });
    return new SecurityKeyService();
  }

  private credential(id: Uint8Array, enrollment: boolean, output?: Uint8Array): unknown {
    const authenticatorData = new Uint8Array(37);
    authenticatorData[32] = this.flags;
    return {
      type: 'public-key',
      id: Buffer.from(id).toString('base64url'),
      rawId: id.slice().buffer,
      authenticatorAttachment: this.attachment,
      response: enrollment
        ? { getAuthenticatorData: () => authenticatorData.slice().buffer }
        : { authenticatorData: authenticatorData.slice().buffer },
      getClientExtensionResults: () => enrollment
        ? { prf: { enabled: this.prfAvailable } }
        : this.getPrfAvailable ? { prf: { results: { first: output!.slice().buffer } } } : {},
    };
  }
}

test('registration and encryption are separate ceremonies with no automatic second prompt', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const pending = await service.beginEnrollment(' My key ');

  assert.equal(pending.name, 'My key');
  assert.equal(pending.rpId, 'password.example');
  assert.equal('ciphertext' in pending, false);
  assert.equal(authenticator.creates.length, 1);
  assert.equal(authenticator.gets.length, 0, 'registration must wait for a separate encryption action');
  assert.equal(authenticator.storage.writes, 0);

  const record = await service.finishEnrollment(pending, 'master remains in memory');
  assert.equal(authenticator.creates.length, 1, 'encryption must use the registered credential');
  assert.equal(authenticator.gets.length, 1);
  assert.equal(authenticator.storage.writes, 0);
  const { ciphertext, iv, ...metadata } = record;
  const { iv: pendingIv, ...pendingMetadata } = pending;
  assert.ok(ciphertext.length > 0);
  assert.notEqual(iv, pendingIv, 'finishing must use a fresh encryption nonce');
  assert.deepEqual(metadata, pendingMetadata);
  assert.equal(await service.unlock(record), 'master remains in memory');
});

test('failed encryption can retry the pending credential without another registration', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const existing = await enroll(service, 'existing master', 'Primary');
  service.save([existing]);
  const savedBefore = authenticator.storage.getItem(storageKey);
  const writesBefore = authenticator.storage.writes;
  const pending = await service.beginEnrollment('Spare');
  const createCount = authenticator.creates.length;
  const getCount = authenticator.gets.length;
  authenticator.getError = new DOMException('Fresh user activation required', 'NotAllowedError');

  await assert.rejects(service.finishEnrollment(pending, 'existing master'), /encryption setup.*NotAllowedError/i);
  assert.equal(authenticator.creates.length, createCount);
  assert.equal(authenticator.gets.length, getCount + 1);
  assert.equal(authenticator.storage.getItem(storageKey), savedBefore);
  assert.equal(authenticator.storage.writes, writesBefore);
  assert.equal('ciphertext' in pending, false);

  authenticator.getError = undefined;
  const spare = await service.finishEnrollment(pending, 'existing master');
  assert.equal(authenticator.creates.length, createCount);
  assert.equal(authenticator.gets.length, getCount + 2);
  assert.equal(spare.credentialId, pending.credentialId);
  assert.equal(authenticator.storage.getItem(storageKey), savedBefore);
  assert.equal(authenticator.storage.writes, writesBefore);
  assert.equal(await service.unlock(spare), 'existing master');
});

test('reusing pending registration encrypts different secrets with independent nonces', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const pending = await service.beginEnrollment('Key');
  const snapshot = { ...pending };
  const first = await service.finishEnrollment(pending, 'first master');
  const second = await service.finishEnrollment(pending, 'second master');
  assert.equal(authenticator.creates.length, 1);
  assert.equal(authenticator.gets.length, 2);
  assert.equal(first.credentialId, second.credentialId);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.ciphertext, second.ciphertext);
  assert.deepEqual(pending, snapshot);
  assert.equal(await service.unlock(first), 'first master');
  assert.equal(await service.unlock(second), 'second master');
});

test('NotAllowed errors identify registration, encryption setup, and unlock separately', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  authenticator.createError = new DOMException('Browser rejected create', 'NotAllowedError');
  await assert.rejects(service.beginEnrollment('Key'), /key registration.*NotAllowedError.*Register key/i);
  assert.equal(authenticator.gets.length, 0);
  authenticator.createError = undefined;
  const pending = await service.beginEnrollment('Key');
  authenticator.getError = new DOMException('Browser rejected get', 'NotAllowedError');
  await assert.rejects(service.finishEnrollment(pending, 'master'), /encryption setup.*NotAllowedError.*Finish setup.*do not need to register/i);
  authenticator.getError = undefined;
  const record = await service.finishEnrollment(pending, 'master');
  authenticator.getError = new DOMException('Browser rejected unlock', 'NotAllowedError');
  await assert.rejects(service.unlock(record), /key unlock.*NotAllowedError.*Unlock with key/i);
  assert.equal(authenticator.storage.writes, 0);
});

test('enrollment and unlock preserve exact master and existing generated password', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const master = '\uFEFF \tpässw🔑rd\n秘密 ';
  const record = await enroll(service, master, ' My physical key ');
  assert.equal(record.name, 'My physical key');
  assert.equal(record.rpId, 'password.example');
  assert.equal(JSON.stringify(record).includes(master), false);
  assert.equal(Buffer.from(record.ciphertext, 'base64url').includes(Buffer.from(master)), false);
  assert.equal(authenticator.storage.writes, 0, 'enrollment must not save before the caller accepts it');
  service.save([record]);
  assert.deepEqual(service.load(), [record]);
  assert.equal(authenticator.storage.getItem(storageKey)!.includes(master), false);

  const recovered = await service.unlock(record);
  assert.equal(recovered, master);
  const generator = new CryptoService();
  assert.equal(
    await generator.generatePassword(recovered, passwordParams()),
    await generator.generatePassword(master, passwordParams()),
  );

  const creation = authenticator.creates[0].publicKey!;
  assert.equal(creation.authenticatorSelection!.authenticatorAttachment, 'cross-platform');
  assert.equal(creation.authenticatorSelection!.residentKey, 'required');
  assert.equal(creation.authenticatorSelection!.userVerification, 'required');
  for (const request of authenticator.gets) {
    assert.equal(request.publicKey!.userVerification, 'required');
    assert.equal(request.publicKey!.rpId, record.rpId);
    assert.equal(request.publicKey!.allowCredentials!.length, 1);
    assert.deepEqual(
      Buffer.from(request.publicKey!.allowCredentials![0].id as ArrayBuffer),
      Buffer.from(record.credentialId, 'base64url'),
    );
  }
});

test('spare keys have independent encrypted records for the same master secret', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const master = 'same master on both physical keys';
  const primary = await enroll(service, master, 'Primary');
  const spare = await enroll(service, master, 'Spare');
  assert.notEqual(primary.credentialId, spare.credentialId);
  assert.notEqual(primary.ciphertext, spare.ciphertext);
  assert.notEqual(primary.prfSalt, spare.prfSalt);
  assert.notEqual(primary.hkdfSalt, spare.hkdfSalt);
  assert.notEqual(primary.iv, spare.iv);
  service.save([primary, spare]);
  assert.equal(await service.unlock(primary), master);
  assert.equal(await service.unlock(spare), master);
});

test('unsupported PRF enrollment fails without changing existing local data', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const existing = await enroll(service, 'existing master', 'Existing');
  service.save([existing]);
  const storedBefore = authenticator.storage.getItem(storageKey);
  const writesBefore = authenticator.storage.writes;
  authenticator.prfAvailable = false;
  await assert.rejects(enroll(service, 'new master', 'Unsupported'), /PRF/);
  assert.equal(authenticator.storage.getItem(storageKey), storedBefore);
  assert.equal(authenticator.storage.writes, writesBefore);
  authenticator.prfAvailable = true;
  authenticator.getPrfAvailable = false;
  await assert.rejects(enroll(service, 'new master', 'Missing PRF output'), /PRF/);
  assert.equal(authenticator.storage.writes, writesBefore);
});

test('wrong PRF output, ciphertext tampering, and authenticated metadata tampering fail closed', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const record = await enroll(service, 'sensitive master', 'Key');
  authenticator.wrongPrf = true;
  await assert.rejects(service.unlock(record), /could not be opened/i);
  authenticator.wrongPrf = false;
  for (const field of ['ciphertext', 'iv', 'hkdfSalt', 'prfSalt'] as const) {
    const bytes = Buffer.from(record[field], 'base64url');
    bytes[0] ^= 0x80;
    await assert.rejects(service.unlock({ ...record, [field]: bytes.toString('base64url') }), /could not be opened/i);
  }
  assert.equal(authenticator.storage.writes, 0);
});

test('unlock rejects a different credential and missing user verification', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const record = await enroll(service, 'master', 'Key');
  authenticator.wrongCredential = true;
  await assert.rejects(service.unlock(record), /different.*credential/i);
  authenticator.wrongCredential = false;
  authenticator.flags = 0x01;
  await assert.rejects(service.unlock(record), /user verification/i);
  await assert.rejects(enroll(service, 'master', 'Unverified'), /user verification/i);
  authenticator.flags = 0x05;
  authenticator.attachment = 'platform';
  await assert.rejects(service.unlock(record), /external physical/i);
});

test('cancellation before and during ceremonies does not save an enrollment', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const before = new AbortController();
  before.abort();
  await assert.rejects(enroll(service, 'master', 'Key', before.signal), /cancelled/i);
  assert.equal(authenticator.creates.length, 0);
  const during = new AbortController();
  authenticator.onGet = () => during.abort();
  await assert.rejects(enroll(service, 'master', 'Key', during.signal), /cancelled/i);
  assert.equal(authenticator.storage.writes, 0);
  authenticator.onGet = undefined;
  authenticator.getError = new DOMException('User dismissed prompt', 'NotAllowedError');
  await assert.rejects(enroll(service, 'master', 'Key'), /encryption setup.*NotAllowedError/i);
  assert.equal(authenticator.storage.writes, 0);
});

test('a backup enrolled for another hostname is rejected before a key prompt', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const record = await enroll(service, 'master', 'Key');
  const getCount = authenticator.gets.length;
  authenticator.location.hostname = 'different.example';
  await assert.rejects(service.unlock(record), /enrolled for password\.example/i);
  assert.equal(authenticator.gets.length, getCount);
});

test('malformed saved records are reported and cannot be overwritten', () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const badValues = ['{broken', '{}', '[{"version":999}]'];
  for (const bad of badValues) {
    authenticator.storage.setItem(storageKey, bad);
    const writesBefore = authenticator.storage.writes;
    assert.throws(() => service.load(), /invalid.*unchanged/i);
    assert.throws(() => service.save([]), /invalid.*unchanged/i);
    assert.equal(authenticator.storage.getItem(storageKey), bad);
    assert.equal(authenticator.storage.writes, writesBefore);
  }
});

test('browser capability detection keeps unsupported contexts out of key ceremonies', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  assert.equal(service.isSupported(), true);
  (globalThis as any).window.isSecureContext = false;
  assert.equal(service.isSupported(), false);
  await assert.rejects(enroll(service, 'master', 'Key'), /HTTPS or localhost/i);
  assert.equal(authenticator.creates.length, 0);
});

test('enrollment refuses an encrypted record if the verification decrypt does not match', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const existing = await enroll(service, 'existing master', 'Primary');
  service.save([existing]);
  const before = authenticator.storage.getItem(storageKey);
  const writesBefore = authenticator.storage.writes;
  const descriptor = Object.getOwnPropertyDescriptor(crypto.subtle, 'decrypt');
  Object.defineProperty(crypto.subtle, 'decrypt', {
    configurable: true,
    value: async () => new TextEncoder().encode('corrupt verification result').buffer,
  });
  try {
    await assert.rejects(enroll(service, 'existing master', 'Spare'), /encryption check failed/i);
  } finally {
    if (descriptor) Object.defineProperty(crypto.subtle, 'decrypt', descriptor);
    else delete (crypto.subtle as any).decrypt;
  }
  assert.equal(authenticator.storage.getItem(storageKey), before);
  assert.equal(authenticator.storage.writes, writesBefore);
  assert.equal(await service.unlock(existing), 'existing master');
});

test('key storage rejects duplicate identities and oversized collections without replacing data', () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const existing = securityKeyRecord();
  service.save([existing]);
  const before = authenticator.storage.getItem(storageKey);
  const writesBefore = authenticator.storage.writes;
  assert.throws(() => service.save([existing, { ...existing, name: 'Same key renamed' }]), /duplicate/i);
  assert.throws(() => service.save(Array.from({ length: 33 }, () => existing)), /at most 32/i);
  assert.equal(authenticator.storage.getItem(storageKey), before);
  assert.equal(authenticator.storage.writes, writesBefore);
});

test('security-key operations do not collect diagnostics until explicitly enabled', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  assert.equal(service.diagnostics.enabled(), false);
  const record = await enroll(service, 'private master', 'Private key label');
  assert.equal(await service.unlock(record), 'private master');
  authenticator.getError = new DOMException('private exception details', 'NotAllowedError');
  await assert.rejects(service.unlock(record), /NotAllowedError/);
  assert.deepEqual(service.diagnostics.entries(), []);
  assert.equal(service.diagnostics.exportReport(), '');
  assert.equal(authenticator.storage.writes, 0);
});

test('opt-in diagnostics capture failed ceremony phases and durations while excluding all secret material', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const master = 'NEVER-EXPORT-this-master-🔑';
  const keyLabel = 'NEVER-EXPORT-this-key-label';
  const rawMessage = `NEVER-EXPORT-raw-browser-exception ${master} ${keyLabel}`;
  service.diagnostics.setEnabled(true);

  authenticator.createError = new DOMException(rawMessage, 'NotAllowedError');
  await assert.rejects(service.beginEnrollment(keyLabel), /NotAllowedError/);
  authenticator.createError = undefined;
  const pending = await service.beginEnrollment(keyLabel);
  authenticator.getError = new DOMException(rawMessage, 'NotAllowedError');
  await assert.rejects(service.finishEnrollment(pending, master), /NotAllowedError/);
  authenticator.getError = undefined;
  const record = await service.finishEnrollment(pending, master);
  authenticator.getError = new DOMException(rawMessage, 'NotAllowedError');
  await assert.rejects(service.unlock(record), /NotAllowedError/);
  authenticator.getError = undefined;
  assert.equal(await service.unlock(record), master);

  const exported = service.diagnostics.exportReport();
  const report = JSON.parse(exported);
  assert.equal(report.format, 'password-mgr-security-key-diagnostics');
  assert.equal(report.version, 1);
  assert.equal(report.entries.length, 6);
  const failures = report.entries.filter((entry: any) => entry.status === 'failed');
  assert.deepEqual(failures.map((entry: any) => [entry.phase, entry.requestKind, entry.error.name]), [
    ['registration', 'create', 'NotAllowedError'],
    ['setup', 'get', 'NotAllowedError'],
    ['unlock', 'get', 'NotAllowedError'],
  ]);
  for (const entry of failures) {
    assert.equal(entry.error.code, 0);
    assert.equal(entry.error.aborted, false);
  }
  assert.deepEqual(report.entries.filter((entry: any) => entry.status === 'succeeded')
    .map((entry: any) => entry.summary), [
    'credential-registered', 'encryption-verified', 'master-unlocked',
  ]);
  for (const entry of report.entries) {
    assert.ok(Number.isFinite(entry.elapsedMs) && entry.elapsedMs >= 0);
    assert.notEqual(entry.status, 'pending');
    assert.ok(entry.events.some((event: any) => event.name === 'request-options'));
    for (const event of entry.events) {
      assert.ok(Number.isFinite(event.elapsedMs) && event.elapsedMs >= 0);
    }
  }

  const forbidden = [
    master, keyLabel, rawMessage,
    record.credentialId, record.prfSalt, record.hkdfSalt, record.iv, record.ciphertext,
    pending.iv,
    ...authenticator.prfOutputs.flatMap(bytes => [
      Buffer.from(bytes).toString('base64url'),
      Buffer.from(bytes).toString('base64'),
      Buffer.from(bytes).toString('hex'),
      JSON.stringify([...bytes]),
    ]),
  ];
  for (const secret of forbidden) {
    assert.equal(exported.includes(secret), false, 'diagnostics must omit private values');
  }
  assert.equal(authenticator.storage.writes, 0, 'diagnostics must remain in memory');
  service.diagnostics.setEnabled(false);
  assert.deepEqual(service.diagnostics.entries(), []);
  assert.equal(service.diagnostics.exportReport(), '');
});

test('diagnostics identify a missing PRF result after the browser returned a credential', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  service.diagnostics.setEnabled(true);
  const pending = await service.beginEnrollment('Key');
  authenticator.getPrfAvailable = false;
  await assert.rejects(service.finishEnrollment(pending, 'master'), /PRF/);
  const report = JSON.parse(service.diagnostics.exportReport());
  const failed = report.entries.at(-1);
  assert.equal(failed.phase, 'setup');
  assert.equal(failed.status, 'failed');
  assert.equal(failed.error.name, 'Error');
  assert.ok(failed.events.some((event: any) => event.name === 'credential-response'));
  const prf = failed.events.find((event: any) => event.name === 'prf-result');
  assert.deepEqual(prf.details, { resultPresent: false, resultLength: 0 });
  assert.equal(authenticator.storage.writes, 0);
});
