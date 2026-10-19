import '@angular/compiler';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { SecurityKeyService } from '../src/app/services/security-key.service';
import { CryptoService } from '../src/app/services/crypto.service';
import { MemoryStorage, passwordParams, securityKeyRecord } from './fixtures';

const storageKey = 'password-mgr:security-keys:v1';

class FakeAuthenticator {
  readonly storage = new MemoryStorage();
  readonly location = new URL('https://password.example');
  readonly creates: CredentialCreationOptions[] = [];
  readonly gets: CredentialRequestOptions[] = [];
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

test('enrollment and unlock preserve exact master and existing generated password', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const master = '\uFEFF \tpässw🔑rd\n秘密 ';
  const record = await service.enroll(master, ' My physical key ');
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
  const primary = await service.enroll(master, 'Primary');
  const spare = await service.enroll(master, 'Spare');
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
  const existing = await service.enroll('existing master', 'Existing');
  service.save([existing]);
  const storedBefore = authenticator.storage.getItem(storageKey);
  const writesBefore = authenticator.storage.writes;
  authenticator.prfAvailable = false;
  await assert.rejects(service.enroll('new master', 'Unsupported'), /PRF/);
  assert.equal(authenticator.storage.getItem(storageKey), storedBefore);
  assert.equal(authenticator.storage.writes, writesBefore);
  authenticator.prfAvailable = true;
  authenticator.getPrfAvailable = false;
  await assert.rejects(service.enroll('new master', 'Missing PRF output'), /PRF/);
  assert.equal(authenticator.storage.writes, writesBefore);
});

test('wrong PRF output, ciphertext tampering, and authenticated metadata tampering fail closed', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const record = await service.enroll('sensitive master', 'Key');
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
  const record = await service.enroll('master', 'Key');
  authenticator.wrongCredential = true;
  await assert.rejects(service.unlock(record), /different.*credential/i);
  authenticator.wrongCredential = false;
  authenticator.flags = 0x01;
  await assert.rejects(service.unlock(record), /user verification/i);
  await assert.rejects(service.enroll('master', 'Unverified'), /user verification/i);
  authenticator.flags = 0x05;
  authenticator.attachment = 'platform';
  await assert.rejects(service.unlock(record), /external physical/i);
});

test('cancellation before and during ceremonies does not save an enrollment', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const before = new AbortController();
  before.abort();
  await assert.rejects(service.enroll('master', 'Key', before.signal), /cancelled/i);
  assert.equal(authenticator.creates.length, 0);
  const during = new AbortController();
  authenticator.onGet = () => during.abort();
  await assert.rejects(service.enroll('master', 'Key', during.signal), /cancelled/i);
  assert.equal(authenticator.storage.writes, 0);
  authenticator.onGet = undefined;
  authenticator.getError = new DOMException('User dismissed prompt', 'NotAllowedError');
  await assert.rejects(service.enroll('master', 'Key'), /cancelled.*timed out/i);
  assert.equal(authenticator.storage.writes, 0);
});

test('a backup enrolled for another hostname is rejected before a key prompt', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const record = await service.enroll('master', 'Key');
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
  await assert.rejects(service.enroll('master', 'Key'), /HTTPS or localhost/i);
  assert.equal(authenticator.creates.length, 0);
});

test('enrollment refuses an encrypted record if the verification decrypt does not match', async () => {
  const authenticator = new FakeAuthenticator();
  const service = authenticator.install();
  const existing = await service.enroll('existing master', 'Primary');
  service.save([existing]);
  const before = authenticator.storage.getItem(storageKey);
  const writesBefore = authenticator.storage.writes;
  const descriptor = Object.getOwnPropertyDescriptor(crypto.subtle, 'decrypt');
  Object.defineProperty(crypto.subtle, 'decrypt', {
    configurable: true,
    value: async () => new TextEncoder().encode('corrupt verification result').buffer,
  });
  try {
    await assert.rejects(service.enroll('existing master', 'Spare'), /encryption check failed/i);
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
