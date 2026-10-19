export interface SecurityKeyRecord {
  version: 1;
  credentialId: string;
  name: string;
  rpId: string;
  prfSalt: string;
  hkdfSalt: string;
  iv: string;
  ciphertext: string;
  createdAt: string;
}

export const MAX_SECURITY_KEY_RECORDS = 32;
export const MAX_MASTER_SECRET_BYTES = 16_384;

function invalid(field: string): never {
  throw new Error(`Invalid security-key backup: ${field}.`);
}

function readString(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    return invalid(field);
  }
  return value;
}

function readBytes(value: unknown, field: string, minBytes: number, maxBytes: number): string {
  const encoded = readString(value, field, Math.ceil(maxBytes * 4 / 3));
  if (!/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.length % 4 === 1) {
    return invalid(field);
  }

  let decoded: string;
  try {
    decoded = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return invalid(field);
  }
  if (decoded.length < minBytes || decoded.length > maxBytes ||
      btoa(decoded).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== encoded) {
    return invalid(field);
  }
  return encoded;
}

/** Validate and copy untrusted storage/import data without changing any cryptographic bytes. */
export function parseSecurityKeyRecord(value: unknown): SecurityKeyRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return invalid('record');
  }
  const input = value as Record<string, unknown>;
  if (input['version'] !== 1) return invalid('unsupported version');

  const name = readString(input['name'], 'name', 80);
  if (!name.trim() || /[\u0000-\u001f\u007f]/.test(name)) return invalid('name');

  const rpId = readString(input['rpId'], 'site hostname', 253);
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(rpId) ||
      rpId.split('.').some(label => label.length === 0 || label.length > 63 ||
        label.startsWith('-') || label.endsWith('-'))) {
    return invalid('site hostname');
  }

  const createdAt = readString(input['createdAt'], 'creation date', 24);
  const date = new Date(createdAt);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== createdAt) {
    return invalid('creation date');
  }

  return {
    version: 1,
    credentialId: readBytes(input['credentialId'], 'credential ID', 1, 1024),
    name,
    rpId,
    prfSalt: readBytes(input['prfSalt'], 'PRF salt', 32, 32),
    hkdfSalt: readBytes(input['hkdfSalt'], 'HKDF salt', 32, 32),
    iv: readBytes(input['iv'], 'encryption nonce', 12, 12),
    ciphertext: readBytes(input['ciphertext'], 'encrypted master secret', 17, MAX_MASTER_SECRET_BYTES + 16),
    createdAt,
  };
}
