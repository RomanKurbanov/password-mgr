import { Injectable } from '@angular/core';
import {
  MAX_MASTER_SECRET_BYTES,
  MAX_SECURITY_KEY_RECORDS,
  PendingSecurityKeyEnrollment,
  SecurityKeyRecord,
  parsePendingSecurityKeyEnrollment,
  parseSecurityKeyRecord,
} from '../models/security-key.model';
import { SecurityKeyDiagnosticsService } from './security-key-diagnostics.service';

const STORAGE_KEY = 'password-mgr:security-keys:v1';
const MAX_STORED_CHARACTERS = 1_000_000;
const KEY_CONTEXT = 'password-mgr:security-key:v1:master-secret';
const PRF_UNAVAILABLE = 'This key and browser did not provide WebAuthn PRF. Use a PRF-capable FIDO2 security key and a compatible browser. You can still type your master secret.';

function encodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBytes(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

function checkCancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Security-key operation cancelled.', 'AbortError');
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

function authenticatedData(record: Pick<SecurityKeyRecord, 'version' | 'rpId' | 'credentialId' | 'prfSalt' | 'hkdfSalt'>): Uint8Array<ArrayBuffer> {
  // Labels may change; the credential, scheme and both derivation inputs may not.
  return new TextEncoder().encode(JSON.stringify({
    context: KEY_CONTEXT,
    version: record.version,
    rpId: record.rpId,
    credentialId: record.credentialId,
    prfSalt: record.prfSalt,
    hkdfSalt: record.hkdfSalt,
  }));
}

function publicKeyCredential(value: Credential | null): PublicKeyCredential {
  if (!value || value.type !== 'public-key' || !('rawId' in value) ||
      !(value.rawId instanceof ArrayBuffer) || !('getClientExtensionResults' in value) ||
      typeof value.getClientExtensionResults !== 'function') {
    throw new Error('The browser did not return a usable security-key credential. Please try again.');
  }
  const credential = value as PublicKeyCredential;
  if (credential.authenticatorAttachment && credential.authenticatorAttachment !== 'cross-platform') {
    throw new Error('Select an external physical security key for this operation.');
  }
  return credential;
}

function requireVerification(authenticatorData: ArrayBuffer): void {
  const bytes = new Uint8Array(authenticatorData);
  if (bytes.length < 37 || (bytes[32] & 0x05) !== 0x05) {
    throw new Error('The security key did not confirm user verification. Set up its PIN or biometric verification and try again.');
  }
}

type OperationPhase = 'registration' | 'setup' | 'unlock';

function operationError(error: unknown, phase: OperationPhase, signal?: AbortSignal): Error {
  const step = phase === 'registration' ? 'Key registration' : phase === 'setup' ? 'Encryption setup' : 'Key unlock';
  if (signal?.aborted || (error instanceof DOMException && error.name === 'AbortError')) {
    return new Error(`${step} cancelled. You can try again or type your master secret.`);
  }
  if (error instanceof DOMException) {
    if (error.name === 'NotAllowedError') {
      const compatibility = ' Browser or key compatibility can also cause this error.';
      if (phase === 'registration') {
        return new Error('The browser did not complete key registration (NotAllowedError). Retry Register key, choose your external security key, and complete its PIN and touch prompts.' + compatibility);
      }
      if (phase === 'setup') {
        return new Error('The browser did not complete encryption setup (NotAllowedError). Retry Finish setup with the same key; you do not need to register it again.' + compatibility);
      }
      return new Error('The browser did not complete key unlock (NotAllowedError). Retry Unlock with key and complete its PIN and touch prompts.' + compatibility);
    }
    if (error.name === 'NotSupportedError') return new Error(`${step} failed: ${PRF_UNAVAILABLE}`);
    if (error.name === 'SecurityError') {
      return new Error(`${step} was blocked for this site. Use HTTPS or localhost and the same hostname where the key was enrolled.`);
    }
    if (error.name === 'InvalidStateError') {
      if (phase === 'registration') {
        return new Error('Key registration failed: the security key could not create this credential. Try a different key or check its available credential storage.');
      }
      const retry = phase === 'setup' ? 'Finish setup' : 'Unlock with key';
      return new Error(`${step} failed. Retry ${retry} with the same enrolled security key.`);
    }
    // Do not surface browser-provided exception messages or other opaque details.
    return new Error(`${step} failed in the browser. Retry this step with a compatible browser and security key, or type your master secret.`);
  }
  if (error instanceof TypeError || error instanceof RangeError) {
    return new Error(`${step} could not be completed. Retry this step with a compatible browser and security key, or type your master secret.`);
  }
  return error instanceof Error ? new Error(`${step} failed: ${error.message}`) : new Error(`${step} failed. Please try again.`);
}

@Injectable({ providedIn: 'root' })
export class SecurityKeyService {
  constructor(readonly diagnostics: SecurityKeyDiagnosticsService = new SecurityKeyDiagnosticsService()) {}

  isSupported(): boolean {
    return typeof window !== 'undefined' && window.isSecureContext &&
      typeof PublicKeyCredential !== 'undefined' && typeof navigator !== 'undefined' &&
      typeof navigator.credentials?.create === 'function' &&
      typeof navigator.credentials?.get === 'function' &&
      typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
  }

  load(): SecurityKeyRecord[] {
    let raw: string | null;
    try {
      raw = localStorage.getItem(STORAGE_KEY);
    } catch {
      throw new Error('Browser storage is unavailable. Allow local storage to save or use security-key records.');
    }
    if (raw === null) return [];
    try {
      if (raw.length > MAX_STORED_CHARACTERS) throw new Error('Storage is too large');
      return this.validateRecords(JSON.parse(raw));
    } catch {
      throw new Error('Saved security-key data is invalid and has been left unchanged. Restore a valid backup in another browser profile, or repair this profile\'s key storage before managing keys.');
    }
  }

  save(records: SecurityKeyRecord[]): void {
    const validated = this.validateRecords(records);
    // Never overwrite malformed existing data, including when deleting the last key.
    this.load();
    const serialized = JSON.stringify(validated);
    if (serialized.length > MAX_STORED_CHARACTERS) {
      throw new Error('The security-key records exceed the browser-storage limit.');
    }
    try {
      localStorage.setItem(STORAGE_KEY, serialized);
    } catch {
      throw new Error('Security-key records could not be saved. Browser storage may be full or disabled.');
    }
  }

  async beginEnrollment(name: string, signal?: AbortSignal): Promise<PendingSecurityKeyEnrollment> {
    const diagnostic = this.diagnostics.begin('registration', 'create');
    try {
      this.requireSupport();
      checkCancelled(signal);
      const label = name.trim();
      if (!label || label.length > 80 || /[\u0000-\u001f\u007f]/.test(label)) {
        throw new Error('Give the security key a name of 1 to 80 characters.');
      }
      const rpId = window.location.hostname;
      this.diagnostics.event(diagnostic, 'request-options', {
        residentKey: 'required', userVerification: 'required',
        authenticatorAttachment: 'cross-platform', extensions: ['prf'], algorithmIds: [-7, -257],
      });
      const created = publicKeyCredential(await navigator.credentials.create({
        publicKey: {
          challenge: randomBytes(32),
          rp: { id: rpId, name: 'Password Manager' },
          user: { id: randomBytes(32), name: label, displayName: label },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: {
            authenticatorAttachment: 'cross-platform',
            residentKey: 'required',
            requireResidentKey: true,
            userVerification: 'required',
          },
          attestation: 'none',
          timeout: 120_000,
          extensions: { prf: {} },
        },
        signal,
      }));
      this.diagnostics.event(diagnostic, 'credential-response', { attachment: created.authenticatorAttachment ?? null });
      checkCancelled(signal);
      const attestation = created.response as AuthenticatorAttestationResponse;
      if (typeof attestation.getAuthenticatorData !== 'function') {
        throw new Error('This browser cannot inspect security-key verification. Update it or use a compatible browser.');
      }
      const authData = attestation.getAuthenticatorData();
      this.diagnostics.event(diagnostic, 'verification', {
        userVerified: new Uint8Array(authData).length >= 37 && (new Uint8Array(authData)[32] & 0x04) !== 0,
      });
      requireVerification(authData);
      const prfEnabled = created.getClientExtensionResults().prf?.enabled === true;
      this.diagnostics.event(diagnostic, 'prf-result', { enabled: prfEnabled });
      if (!prfEnabled) {
        throw new Error(PRF_UNAVAILABLE);
      }
      const credentialId = new Uint8Array(created.rawId);
      if (credentialId.length === 0 || credentialId.length > 1024) {
        throw new Error('The security key returned an invalid credential ID.');
      }
      const pending = parsePendingSecurityKeyEnrollment({
        version: 1 as const,
        credentialId: encodeBytes(credentialId),
        name: label,
        rpId,
        prfSalt: encodeBytes(randomBytes(32)),
        hkdfSalt: encodeBytes(randomBytes(32)),
        iv: encodeBytes(randomBytes(12)),
        createdAt: new Date().toISOString(),
      });
      this.diagnostics.success(diagnostic, 'credential-registered');
      return pending;
    } catch (error) {
      this.diagnostics.fail(diagnostic, error, signal);
      throw operationError(error, 'registration', signal);
    }
  }

  async finishEnrollment(value: PendingSecurityKeyEnrollment, masterSecret: string, signal?: AbortSignal): Promise<SecurityKeyRecord> {
    const diagnostic = this.diagnostics.begin('setup', 'get');
    let plaintext: Uint8Array<ArrayBuffer> | undefined;
    let prfOutput: Uint8Array<ArrayBuffer> | undefined;
    let roundtrip: Uint8Array<ArrayBuffer> | undefined;
    try {
      this.requireSupport();
      checkCancelled(signal);
      const pending = parsePendingSecurityKeyEnrollment(value);
      if (pending.rpId !== window.location.hostname) {
        throw new Error(`This setup started for ${pending.rpId}. Open that hostname to finish it, or start a new registration here.`);
      }
      plaintext = new TextEncoder().encode(masterSecret);
      if (plaintext.length === 0 || plaintext.length > MAX_MASTER_SECRET_BYTES) {
        throw new Error('Enter a master secret of up to 16 KiB before finishing security-key setup.');
      }
      // Every attempt gets a fresh nonce, including retries after an encryption or
      // save failure. Reusing public pending metadata must never reuse a GCM nonce.
      const iv = randomBytes(12);
      const metadata = { ...pending, iv: encodeBytes(iv) };
      // No asynchronous work precedes this request: the caller's fresh button
      // gesture starts exactly one WebAuthn ceremony, independent of registration.
      prfOutput = await this.evaluatePrf(decodeBytes(pending.credentialId), pending.rpId, decodeBytes(pending.prfSalt), signal, diagnostic);
      const key = await this.deriveWrappingKey(prfOutput, decodeBytes(pending.hkdfSalt));
      checkCancelled(signal);
      const algorithm: AesGcmParams = { name: 'AES-GCM', iv, additionalData: authenticatedData(metadata), tagLength: 128 };
      const ciphertext = await crypto.subtle.encrypt(algorithm, key, plaintext);
      checkCancelled(signal);
      roundtrip = new Uint8Array(await crypto.subtle.decrypt(algorithm, key, ciphertext));
      checkCancelled(signal);
      if (!equalBytes(plaintext, roundtrip)) {
        throw new Error('The security-key encryption check failed. No key record was saved.');
      }
      const record = parseSecurityKeyRecord({ ...metadata, ciphertext: encodeBytes(new Uint8Array(ciphertext)) });
      this.diagnostics.event(diagnostic, 'encryption-verified', { verified: true });
      this.diagnostics.success(diagnostic, 'encryption-verified');
      return record;
    } catch (error) {
      this.diagnostics.fail(diagnostic, error, signal);
      throw operationError(error, 'setup', signal);
    } finally {
      plaintext?.fill(0);
      prfOutput?.fill(0);
      roundtrip?.fill(0);
    }
  }

  async unlock(value: SecurityKeyRecord, signal?: AbortSignal): Promise<string> {
    const diagnostic = this.diagnostics.begin('unlock', 'get');
    let prfOutput: Uint8Array<ArrayBuffer> | undefined;
    let plaintext: Uint8Array<ArrayBuffer> | undefined;
    try {
      this.requireSupport();
      checkCancelled(signal);
      const record = parseSecurityKeyRecord(value);
      if (record.rpId !== window.location.hostname) {
        throw new Error(`This key was enrolled for ${record.rpId}. Open that hostname to unlock it, or type your master secret here.`);
      }
      prfOutput = await this.evaluatePrf(decodeBytes(record.credentialId), record.rpId, decodeBytes(record.prfSalt), signal, diagnostic);
      const key = await this.deriveWrappingKey(prfOutput, decodeBytes(record.hkdfSalt));
      checkCancelled(signal);
      try {
        plaintext = new Uint8Array(await crypto.subtle.decrypt({
          name: 'AES-GCM',
          iv: decodeBytes(record.iv),
          additionalData: authenticatedData(record),
          tagLength: 128,
        }, key, decodeBytes(record.ciphertext)));
      } catch {
        checkCancelled(signal);
        throw new Error('The encrypted master secret could not be opened. The key or backup may not match, or the backup was changed. Restore a valid backup or type your master secret.');
      }
      checkCancelled(signal);
      // Preserve an initial U+FEFF, which the default UTF-8 decoder would strip.
      const secret = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
      this.diagnostics.success(diagnostic, 'master-unlocked');
      return secret;
    } catch (error) {
      this.diagnostics.fail(diagnostic, error, signal);
      throw operationError(error, 'unlock', signal);
    } finally {
      prfOutput?.fill(0);
      plaintext?.fill(0);
    }
  }

  private requireSupport(): void {
    if (!this.isSupported()) {
      throw new Error('Security-key unlock requires HTTPS or localhost and a browser with WebAuthn and Web Crypto. You can still type your master secret.');
    }
  }

  private validateRecords(value: unknown): SecurityKeyRecord[] {
    if (!Array.isArray(value) || value.length > MAX_SECURITY_KEY_RECORDS) {
      throw new Error(`Security-key data must contain at most ${MAX_SECURITY_KEY_RECORDS} records.`);
    }
    const records = value.map(parseSecurityKeyRecord);
    if (new Set(records.map(record => `${record.rpId}\0${record.credentialId}`)).size !== records.length) {
      throw new Error('Security-key data contains duplicate credentials.');
    }
    return records;
  }

  private async evaluatePrf(credentialId: Uint8Array<ArrayBuffer>, rpId: string, salt: Uint8Array<ArrayBuffer>, signal?: AbortSignal, diagnostic = 0): Promise<Uint8Array<ArrayBuffer>> {
    checkCancelled(signal);
    this.diagnostics.event(diagnostic, 'request-options', { userVerification: 'required', extensions: ['prf'] });
    const credential = publicKeyCredential(await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        rpId,
        allowCredentials: [{ type: 'public-key', id: credentialId }],
        userVerification: 'required',
        timeout: 120_000,
        extensions: { prf: { eval: { first: salt } } },
      },
      signal,
    }));
    this.diagnostics.event(diagnostic, 'credential-response', { attachment: credential.authenticatorAttachment ?? null });
    // This assertion transports a local PRF output. AES-GCM verifies the encrypted
    // master secret; there is no server authentication or assertion-signature check.
    const result = credential.getClientExtensionResults().prf?.results?.first;
    let bytes: Uint8Array | undefined;
    if (result instanceof ArrayBuffer) bytes = new Uint8Array(result);
    else if (ArrayBuffer.isView(result)) bytes = new Uint8Array(result.buffer, result.byteOffset, result.byteLength);
    try {
      this.diagnostics.event(diagnostic, 'prf-result', { resultPresent: !!bytes, resultLength: bytes?.length ?? 0 });
      checkCancelled(signal);
      if (!equalBytes(new Uint8Array(credential.rawId), credentialId)) {
        throw new Error('The browser returned a different security-key credential. Select the enrolled physical key and try again.');
      }
      const authData = (credential.response as AuthenticatorAssertionResponse).authenticatorData;
      this.diagnostics.event(diagnostic, 'verification', {
        userVerified: new Uint8Array(authData).length >= 37 && (new Uint8Array(authData)[32] & 0x04) !== 0,
      });
      requireVerification(authData);
      if (!bytes || bytes.length !== 32) throw new Error(PRF_UNAVAILABLE);
      return bytes.slice();
    } finally {
      bytes?.fill(0);
    }
  }

  private async deriveWrappingKey(prfOutput: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
    const material = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode(KEY_CONTEXT),
    }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
}
