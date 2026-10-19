import type { PasswordParams } from '../src/app/models/password-params.model';
import type { SecurityKeyRecord } from '../src/app/models/security-key.model';

export function passwordParams(overrides: Partial<PasswordParams> = {}): PasswordParams {
  return {
    id: 'site-1',
    name: 'Example',
    domain: 'Example.COM',
    username: 'Alice@Example.COM',
    counter: 1,
    length: 20,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    symbols: '!@#$%^&*()_+-=',
    createdAt: '2026-10-19T00:00:00.000Z',
    updatedAt: '2026-10-19T00:00:00.000Z',
    ...overrides,
  };
}

export class MemoryStorage implements Storage {
  private readonly items = new Map<string, string>();
  writes = 0;

  get length(): number { return this.items.size; }
  clear(): void { this.items.clear(); }
  getItem(key: string): string | null { return this.items.get(key) ?? null; }
  key(index: number): string | null { return [...this.items.keys()][index] ?? null; }
  removeItem(key: string): void { this.items.delete(key); }
  setItem(key: string, value: string): void {
    this.writes++;
    this.items.set(key, String(value));
  }
}

export function securityKeyRecord(overrides: Partial<SecurityKeyRecord> = {}): SecurityKeyRecord {
  const encoded = (length: number, byte: number): string =>
    Buffer.alloc(length, byte).toString('base64url');
  return {
    version: 1,
    credentialId: encoded(16, 1),
    name: 'Primary key',
    rpId: 'password.example',
    prfSalt: encoded(32, 2),
    hkdfSalt: encoded(32, 3),
    iv: encoded(12, 4),
    ciphertext: encoded(48, 5),
    createdAt: '2026-10-19T00:00:00.000Z',
    ...overrides,
  };
}
