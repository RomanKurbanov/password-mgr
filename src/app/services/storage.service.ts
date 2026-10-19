import { Injectable } from '@angular/core';
import { PasswordParams } from '../models/password-params.model';
import { parseParams } from './backup';

const STORAGE_KEY = 'password-mgr:params';

@Injectable({ providedIn: 'root' })
export class StorageService {
  load(): PasswordParams[] {
    let raw: string | null;
    try {
      raw = this.readRaw();
    } catch {
      throw new Error('Cannot read saved site settings. Check browser storage permissions and reload.');
    }
    if (raw === null) return [];
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!Array.isArray(parsed)) throw new Error();
      const params = parsed.map(parseParams);
      if (new Set(params.map(p => p.id)).size !== params.length) throw new Error();
      return params;
    } catch {
      throw new Error('Saved site settings are damaged. Download the original data for recovery; saving, deleting, and importing are blocked to preserve it.');
    }
  }

  readRaw(): string | null {
    return localStorage.getItem(STORAGE_KEY);
  }

  save(params: PasswordParams[]): void {
    // Recheck storage before every write, including imports and changes in other tabs.
    this.load();
    const validated = params.map(parseParams);
    if (new Set(validated.map(p => p.id)).size !== validated.length) {
      throw new Error('Site settings contain duplicate IDs.');
    }
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(validated));
    } catch {
      throw new Error('Could not save site settings. Check browser storage permissions or available space and retry.');
    }
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
