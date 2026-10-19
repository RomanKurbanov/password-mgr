import { CommonModule } from '@angular/common';
import { Component, EventEmitter, Input, OnChanges, OnDestroy, OnInit, Output, SimpleChanges, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { PasswordParams } from './models/password-params.model';
import { SecurityKeyRecord } from './models/security-key.model';
import { createBackup, mergeBackup, parseBackup } from './services/backup';
import { SecurityKeyService } from './services/security-key.service';
import { StorageService } from './services/storage.service';

@Component({
  selector: 'app-security-keys',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './security-keys.component.html',
  styleUrl: './security-keys.component.scss',
})
export class SecurityKeysComponent implements OnInit, OnChanges, OnDestroy {
  private readonly keyService = inject(SecurityKeyService);
  private readonly storage = inject(StorageService);

  @Input() masterSecret = '';
  @Input() resetVersion = 0;
  @Output() readonly unlocked = new EventEmitter<string>();
  @Output() readonly paramsImported = new EventEmitter<PasswordParams[]>();
  @Output() readonly lockRequested = new EventEmitter<void>();

  readonly supported = this.keyService.isSupported();
  readonly hostname = window.location.hostname;
  readonly keys = signal<SecurityKeyRecord[]>([]);
  readonly selectedKeyId = signal('');
  readonly busy = signal<'enroll' | 'unlock' | 'import' | null>(null);
  readonly error = signal('');
  readonly message = signal('');
  readonly storageError = signal('');
  readonly pendingRemoval = signal<SecurityKeyRecord | null>(null);
  keyName = '';

  private operation = 0;
  private controller: AbortController | null = null;

  ngOnInit(): void {
    try {
      this.setKeys(this.keyService.load());
    } catch (error) {
      this.storageError.set(this.errorMessage(error));
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['resetVersion']) this.cancelOperation();
  }

  ngOnDestroy(): void {
    this.cancelOperation();
  }

  keyId(key: SecurityKeyRecord): string {
    return `${key.rpId}:${key.credentialId}`;
  }

  selectedKey(): SecurityKeyRecord | undefined {
    return this.keys().find(key => this.keyId(key) === this.selectedKeyId());
  }

  cancelOperation(): void {
    this.operation++;
    this.controller?.abort();
    this.controller = null;
    this.busy.set(null);
  }

  async enroll(): Promise<void> {
    if (this.busy() || this.storageError() || !this.masterSecret || !this.supported) return;
    const operation = this.beginOperation('enroll');
    try {
      const key = await this.keyService.enroll(this.masterSecret, this.keyName, this.controller!.signal);
      if (operation !== this.operation) return;
      const keys = [...this.keyService.load(), key];
      this.keyService.save(keys);
      this.setKeys(keys);
      this.selectedKeyId.set(this.keyId(key));
      this.keyName = '';
      this.message.set('Key registered and encryption verified. Export a backup before relying on key unlock.');
    } catch (error) {
      if (operation === this.operation) this.error.set(this.errorMessage(error));
    } finally {
      this.finishOperation(operation);
    }
  }

  async unlock(): Promise<void> {
    const key = this.selectedKey();
    if (!key || this.busy() || !this.supported || key.rpId !== this.hostname) return;
    const operation = this.beginOperation('unlock');
    try {
      const secret = await this.keyService.unlock(key, this.controller!.signal);
      if (operation !== this.operation) return;
      this.unlocked.emit(secret);
      this.message.set('Unlocked. The secret clears after copying, locking, leaving this page, or five minutes.');
    } catch (error) {
      if (operation === this.operation) this.error.set(this.errorMessage(error));
    } finally {
      this.finishOperation(operation);
    }
  }

  removeKey(key: SecurityKeyRecord): void {
    if (this.busy() || this.storageError()) return;
    try {
      const keys = this.keyService.load().filter(item => this.keyId(item) !== this.keyId(key));
      this.keyService.save(keys);
      this.setKeys(keys);
      this.pendingRemoval.set(null);
      this.lockRequested.emit();
      this.error.set('');
      this.message.set('Saved unlock removed from this browser. The credential on your physical key and exported backups are unchanged.');
    } catch (error) {
      this.error.set(this.errorMessage(error));
    }
  }

  exportBackup(): void {
    if (this.busy() || this.storageError()) return;
    try {
      const data = createBackup(this.storage.load(), this.keyService.load());
      const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `password-mgr-backup-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      this.error.set('');
      this.message.set('Backup exported. It contains site settings and encrypted secrets; keep it together with access to your registered key.');
    } catch (error) {
      this.error.set(this.errorMessage(error));
    }
  }

  async importBackup(input: HTMLInputElement): Promise<void> {
    const file = input.files?.[0];
    if (!file || this.busy() || this.storageError()) return;
    const operation = this.beginOperation('import');
    try {
      if (file.size > 1_048_576) throw new Error('Backup is too large (maximum 1 MB).');
      const incoming = parseBackup(await file.text());
      if (operation !== this.operation) return;
      const previousKeys = this.keyService.load();
      const merged = mergeBackup(this.storage.load(), previousKeys, incoming);
      // Ensure the merged result can itself be backed up before changing storage.
      createBackup(merged.params, merged.securityKeys);
      // Restore the previous key records if saving the site settings fails.
      this.keyService.save(merged.securityKeys);
      try {
        this.storage.save(merged.params);
      } catch (error) {
        this.keyService.save(previousKeys);
        throw error;
      }
      this.setKeys(merged.securityKeys);
      this.paramsImported.emit(merged.params);
      this.message.set(`Imported ${merged.addedParams} site settings and ${merged.addedKeys} keys. Existing entries were kept. Keys unlock only on the domain where they were registered.`);
    } catch (error) {
      if (operation === this.operation) this.error.set(this.errorMessage(error));
    } finally {
      input.value = '';
      this.finishOperation(operation);
    }
  }

  private beginOperation(kind: 'enroll' | 'unlock' | 'import'): number {
    this.cancelOperation();
    this.controller = new AbortController();
    this.busy.set(kind);
    this.error.set('');
    this.message.set('');
    return this.operation;
  }

  private finishOperation(operation: number): void {
    if (operation !== this.operation) return;
    this.controller = null;
    this.busy.set(null);
  }

  private setKeys(keys: SecurityKeyRecord[]): void {
    this.keys.set(keys);
    if (!this.selectedKey()) {
      const first = keys.find(key => key.rpId === this.hostname) ?? keys[0];
      this.selectedKeyId.set(first ? this.keyId(first) : '');
    }
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : 'The operation failed. You can still enter your master secret manually.';
  }
}
