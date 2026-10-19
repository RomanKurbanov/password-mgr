import { PasswordParams } from '../models/password-params.model';
import {
  MAX_SECURITY_KEY_RECORDS,
  parseSecurityKeyRecord,
  SecurityKeyRecord,
} from '../models/security-key.model';

const BACKUP_FORMAT = 'password-mgr-backup';
const MAX_BACKUP_BYTES = 1_048_576;
const MAX_PARAMS = 10_000;

export interface BackupData {
  params: PasswordParams[];
  securityKeys: SecurityKeyRecord[];
}

export interface BackupMergeResult extends BackupData {
  addedParams: number;
  addedKeys: number;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseParams(value: unknown): PasswordParams {
  if (!isObject(value)) throw new Error('Backup contains invalid site settings.');
  const strings = ['id', 'name', 'domain', 'username', 'symbols', 'createdAt', 'updatedAt'];
  const booleans = ['includeUppercase', 'includeLowercase', 'includeNumbers'];
  if (
    !strings.every(field => typeof value[field] === 'string') ||
    !booleans.every(field => typeof value[field] === 'boolean') ||
    typeof value['counter'] !== 'number' ||
    !Number.isFinite(value['counter']) ||
    !Number.isInteger(value['counter']) ||
    value['counter'] < 1 ||
    typeof value['length'] !== 'number' ||
    !Number.isFinite(value['length']) ||
    !Number.isInteger(value['length']) ||
    value['length'] < 8 ||
    value['length'] > 64
  ) {
    throw new Error('Backup contains invalid site settings.');
  }

  // Copy only the persisted schema; never trim or normalize generation inputs.
  return {
    id: value['id'] as string,
    name: value['name'] as string,
    domain: value['domain'] as string,
    username: value['username'] as string,
    counter: value['counter'],
    length: value['length'],
    includeUppercase: value['includeUppercase'] as boolean,
    includeLowercase: value['includeLowercase'] as boolean,
    includeNumbers: value['includeNumbers'] as boolean,
    symbols: value['symbols'] as string,
    createdAt: value['createdAt'] as string,
    updatedAt: value['updatedAt'] as string,
  };
}

function parseKey(value: unknown): SecurityKeyRecord {
  const key = parseSecurityKeyRecord(value);
  // Explicitly exclude transient fields even if a caller provides extra data.
  return {
    version: key.version,
    credentialId: key.credentialId,
    name: key.name,
    rpId: key.rpId,
    prfSalt: key.prfSalt,
    hkdfSalt: key.hkdfSalt,
    iv: key.iv,
    ciphertext: key.ciphertext,
    createdAt: key.createdAt,
  };
}

function keyIdentity(key: SecurityKeyRecord): string {
  return JSON.stringify([key.rpId, key.credentialId]);
}

function readData(value: Record<string, unknown>): BackupData {
  if (!Array.isArray(value['params']) || value['params'].length > MAX_PARAMS) {
    throw new Error('Backup must contain at most 10,000 site settings.');
  }
  if (!Array.isArray(value['securityKeys']) || value['securityKeys'].length > MAX_SECURITY_KEY_RECORDS) {
    throw new Error(`Backup must contain at most ${MAX_SECURITY_KEY_RECORDS} security keys.`);
  }
  const params = value['params'].map(parseParams);
  const securityKeys = value['securityKeys'].map(parseKey);
  if (new Set(params.map(param => param.id)).size !== params.length) {
    throw new Error('Backup contains duplicate site-setting IDs.');
  }
  if (new Set(securityKeys.map(keyIdentity)).size !== securityKeys.length) {
    throw new Error('Backup contains duplicate security keys.');
  }
  return { params, securityKeys };
}

export function createBackup(params: PasswordParams[], keys: SecurityKeyRecord[]): string {
  const data = readData({ params, securityKeys: keys });
  const text = JSON.stringify({
    format: BACKUP_FORMAT,
    version: 1,
    createdAt: new Date().toISOString(),
    params: data.params,
    securityKeys: data.securityKeys,
  }, null, 2);
  if (new TextEncoder().encode(text).byteLength > MAX_BACKUP_BYTES) {
    throw new Error('Backup exceeds the 1 MiB file limit.');
  }
  return text;
}

export function parseBackup(text: string): BackupData {
  if (text.length > MAX_BACKUP_BYTES || new TextEncoder().encode(text).byteLength > MAX_BACKUP_BYTES) {
    throw new Error('Backup exceeds the 1 MiB file limit.');
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('Backup is not valid JSON.');
  }
  if (
    !isObject(value) ||
    value['format'] !== BACKUP_FORMAT ||
    value['version'] !== 1 ||
    typeof value['createdAt'] !== 'string'
  ) {
    throw new Error('Unsupported backup format or version.');
  }
  return readData(value);
}

export function mergeBackup(
  existingParams: PasswordParams[],
  existingKeys: SecurityKeyRecord[],
  incoming: BackupData,
): BackupMergeResult {
  const params = [...existingParams];
  const securityKeys = [...existingKeys];
  const paramIds = new Set(params.map(param => param.id));
  const keyIds = new Set(securityKeys.map(keyIdentity));
  let addedParams = 0;
  let addedKeys = 0;

  for (const param of incoming.params) {
    if (paramIds.has(param.id)) continue;
    params.push(param);
    paramIds.add(param.id);
    addedParams += 1;
  }
  for (const key of incoming.securityKeys) {
    const id = keyIdentity(key);
    if (keyIds.has(id)) continue;
    securityKeys.push(key);
    keyIds.add(id);
    addedKeys += 1;
  }
  return { params, securityKeys, addedParams, addedKeys };
}
