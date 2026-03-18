import { Injectable } from '@angular/core';
import { PasswordParams } from '../models/password-params.model';

const STORAGE_KEY = 'password-mgr:params';

function isValidParam(p: unknown): p is PasswordParams {
  if (typeof p !== 'object' || p === null) return false;
  const obj = p as Record<string, unknown>;
  return (
    typeof obj['id'] === 'string' &&
    typeof obj['domain'] === 'string' &&
    typeof obj['length'] === 'number' &&
    obj['length'] >= 8 &&
    obj['length'] <= 64 &&
    typeof obj['counter'] === 'number' &&
    obj['counter'] >= 1 &&
    typeof obj['includeUppercase'] === 'boolean' &&
    typeof obj['includeLowercase'] === 'boolean' &&
    typeof obj['includeNumbers'] === 'boolean'
  );
}

@Injectable({ providedIn: 'root' })
export class StorageService {
  load(): PasswordParams[] {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed.filter(isValidParam);
    } catch {
      return [];
    }
  }

  save(params: PasswordParams[]): void {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(params));
  }

  upsert(params: PasswordParams[]): void {
    this.save(params);
  }

  remove(id: string): PasswordParams[] {
    const current = this.load().filter(p => p.id !== id);
    this.save(current);
    return current;
  }
}
