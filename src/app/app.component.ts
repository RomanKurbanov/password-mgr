import {
  Component,
  OnInit,
  OnDestroy,
  ViewChild,
  signal,
  computed,
  inject,
  ChangeDetectionStrategy,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Subject, Subscription } from 'rxjs';
import { debounceTime } from 'rxjs/operators';

import { PasswordParams, createDefaultParams } from './models/password-params.model';
import { CryptoService } from './services/crypto.service';
import { StorageService } from './services/storage.service';
import { SecurityKeysComponent } from './security-keys.component';

@Component({
  selector: 'app-root',
  imports: [FormsModule, SecurityKeysComponent],
  templateUrl: './app.component.html',
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './app.component.scss',
})
export class AppComponent implements OnInit, OnDestroy {
  private crypto = inject(CryptoService);
  private storage = inject(StorageService);
  private readonly clipboardRetryAttempts = 5;
  private readonly clipboardRetryDelayMs = 150;
  @ViewChild(SecurityKeysComponent) private keyControls?: SecurityKeysComponent;

  readonly supportsTextSecurity = CSS.supports('-webkit-text-security', 'disc');
  readonly lengthPresets = [12, 16, 20, 24, 32];

  // State signals
  sidebarOpen = signal(false);
  editing = signal(false);
  settingsOpen = signal(false);
  searchQuery = signal('');
  usernameCopyMessage = signal('');
  masterSecret = signal('');
  showMasterSecret = signal(false);
  savedParams = signal<PasswordParams[]>([]);
  selectedId = signal<string | null>(null);
  generating = signal(false);
  generatedPassword = signal('');
  showPassword = signal(false);
  error = signal('');
  copySuccess = signal(false);
  copyError = signal(false);
  copying = signal(false);
  storageError = signal('');
  keyUnlocked = signal(false);
  securityKeyResetVersion = signal(0);

  // Current editing params (null = nothing selected)
  editParams = signal<PasswordParams | null>(null);

  // Derived
  selectedParams = computed(() =>
    this.savedParams().find(p => p.id === this.selectedId()) ?? null
  );

  sortedParams = computed(() =>
    [...this.savedParams()].sort((a, b) =>
      new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
    )
  );

  filteredParams = computed(() => {
    const query = this.searchQuery().trim().toLowerCase();
    return this.sortedParams().filter(p => [p.name, p.domain, p.username].some(value => value.toLowerCase().includes(query)));
  });

  cancelEdit(): void {
    const saved = this.selectedParams();
    this.editParams.set(saved ? { ...saved } : null);
    this.editing.set(false);
    this.triggerRegenerate();
  }

  async copyUsername(): Promise<void> {
    const username = this.editParams()?.username;
    if (!username) return;
    try {
      await navigator.clipboard.writeText(username);
      this.usernameCopyMessage.set('Username copied.');
    } catch {
      this.usernameCopyMessage.set('Could not copy username. Please try again.');
    }
  }

  async generateAndCopy(): Promise<void> {
    if (this.copyIntent || this.copying() || !this.masterSecret() || this.editing()) return;
    this.copyIntent = true;
    const params = this.editParams();
    const secretVersion = this.secretVersion;
    try {
      if (!this.generatedPassword()) await this.doGenerate();
      if (params === this.editParams() && secretVersion === this.secretVersion && !this.editing()) {
        await this.copyPassword();
      }
    } finally {
      this.copyIntent = false;
    }
  }

  secretWeak = computed(() => {
    const s = this.masterSecret();
    return s.length > 0 && s.length < 12;
  });

  // Debounce subject
  private regenerate$ = new Subject<void>();
  private sub = new Subscription();
  private generationVersion = 0;
  private copyIntent = false;
  private secretVersion = 0;
  private readonly lockAfterMs = 5 * 60_000;
  private lockTimer: ReturnType<typeof setTimeout> | undefined;
  private idleDeadline = 0;
  private keyDeadline = 0;
  private readonly onPageHide = (): void => this.clearMasterSecret();
  private readonly onResume = (): void => { this.checkSession(); };
  private readonly onActivity = (): void => {
    if (!this.checkSession() || !this.masterSecret()) return;
    this.idleDeadline = Date.now() + this.lockAfterMs;
    this.scheduleLock();
  };

  private checkSession(): boolean {
    const now = Date.now();
    if ((this.idleDeadline && now >= this.idleDeadline) ||
        (this.keyDeadline && now >= this.keyDeadline)) {
      this.clearMasterSecret();
      return false;
    }
    return true;
  }

  private scheduleLock(): void {
    clearTimeout(this.lockTimer);
    const deadline = this.keyDeadline ? Math.min(this.idleDeadline, this.keyDeadline) : this.idleDeadline;
    this.lockTimer = setTimeout(() => this.clearMasterSecret(), Math.max(0, deadline - Date.now()));
  }

  ngOnInit(): void {
    try {
      this.savedParams.set(this.storage.load());
    } catch (error) {
      this.reportStorageError(error);
    }
    window.addEventListener('pagehide', this.onPageHide);
    window.addEventListener('pageshow', this.onResume);
    window.addEventListener('focus', this.onResume);
    window.addEventListener('visibilitychange', this.onResume);
    window.addEventListener('pointerdown', this.onActivity);
    window.addEventListener('keydown', this.onActivity);

    this.sub.add(
      this.regenerate$.pipe(debounceTime(500)).subscribe(() => {
        if (!this.copyIntent) void this.doGenerate();
      })
    );
  }

  ngOnDestroy(): void {
    this.sub.unsubscribe();
    window.removeEventListener('pagehide', this.onPageHide);
    window.removeEventListener('pageshow', this.onResume);
    window.removeEventListener('focus', this.onResume);
    window.removeEventListener('visibilitychange', this.onResume);
    window.removeEventListener('pointerdown', this.onActivity);
    window.removeEventListener('keydown', this.onActivity);
    this.clearMasterSecret();
  }

  // Called whenever any relevant input changes
  triggerRegenerate(): void {
    this.generationVersion++;
    this.generating.set(false);
    this.generatedPassword.set('');
    this.error.set('');
    this.regenerate$.next();
  }

  private async doGenerate(): Promise<void> {
    if (!this.checkSession()) return;
    const version = ++this.generationVersion;
    const secret = this.masterSecret();
    const current = this.editParams();
    const params = current ? { ...current } : null;
    if (!secret || !params || !params.domain) {
      this.generatedPassword.set('');
      this.generating.set(false);
      return;
    }

    this.generating.set(true);
    this.error.set('');
    try {
      const pwd = await this.crypto.generatePassword(secret, params);
      if (this.checkSession() && version === this.generationVersion) this.generatedPassword.set(pwd);
    } catch (e) {
      if (version === this.generationVersion) {
        this.error.set(e instanceof Error ? e.message : 'Generation failed');
        this.generatedPassword.set('');
      }
    } finally {
      if (version === this.generationVersion) this.generating.set(false);
    }
  }

  selectParam(id: string): void {
    this.editing.set(false);
    this.settingsOpen.set(false);
    this.copySuccess.set(false);
    this.usernameCopyMessage.set('');
    this.selectedId.set(id);
    this.sidebarOpen.set(false);
    const found = this.savedParams().find(p => p.id === id);
    if (found) {
      this.editParams.set({ ...found });
      this.showPassword.set(false);
      this.generatedPassword.set('');
      this.triggerRegenerate();
    }
  }

  newParam(): void {
    this.editing.set(true);
    this.settingsOpen.set(false);
    this.generationVersion++;
    this.generating.set(false);
    const p = createDefaultParams();
    this.editParams.set(p);
    this.selectedId.set(null);
    this.sidebarOpen.set(false);
    this.generatedPassword.set('');
    this.showPassword.set(false);
    this.error.set('');
  }

  saveParam(): void {
    const current = this.editParams();
    if (!current) return;
    const p = { ...current, updatedAt: new Date().toISOString() };
    try {
      const list = this.storage.load();
      const updated = list.some(x => x.id === p.id)
        ? list.map(x => x.id === p.id ? p : x) : [...list, p];
      this.storage.save(updated);
      this.savedParams.set(updated);
      this.editParams.set(p);
      this.selectedId.set(p.id);
      this.editing.set(false);
      this.storageError.set('');
    } catch (error) {
      this.reportStorageError(error);
    }
  }

  deleteParam(): void {
    const p = this.editParams();
    if (!p) return;
    try {
      const updated = this.storage.remove(p.id);
      this.savedParams.set(updated);
      this.editParams.set(null);
      this.selectedId.set(null);
      this.triggerRegenerate();
      this.storageError.set('');
    } catch (error) {
      this.reportStorageError(error);
    }
  }

  downloadStoredSettings(): void {
    try {
      const raw = this.storage.readRaw();
      if (raw === null) throw new Error('No stored site settings are available to download.');
      const url = URL.createObjectURL(new Blob([raw], { type: 'text/plain' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'password-mgr-settings-recovery.txt';
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {
      this.storageError.set('Cannot download stored settings. Check browser storage permissions and retry.');
    }
  }

  private reportStorageError(error: unknown): void {
    this.storageError.set(error instanceof Error ? error.message : 'Could not access saved site settings.');
  }

  async copyPassword(): Promise<void> {
    if (!this.checkSession() || this.copying()) return;
    const pwd = this.generatedPassword();
    if (!pwd) return;
    const version = this.secretVersion;
    this.copying.set(true);
    this.copyError.set(false);
    this.copySuccess.set(false);
    try {
      const copied = await this.writeClipboardWithRetry(pwd, version);
      if (version !== this.secretVersion || !this.checkSession()) return;
      if (copied) {
        this.clearMasterSecret();
        this.copySuccess.set(true);
        setTimeout(() => this.copySuccess.set(false), 2000);
      } else {
        this.copyError.set(true);
        setTimeout(() => this.copyError.set(false), 3000);
      }
    } finally {
      this.copying.set(false);
    }
  }

  setLength(n: number): void {
    const p = this.editParams();
    if (!p) return;
    const clamped = Math.min(64, Math.max(8, Number.isFinite(n) ? Math.round(n) : p.length));
    if (clamped === p.length) return;
    this.editParams.set({ ...p, length: clamped });
    this.triggerRegenerate();
  }

  incrementCounter(): void {
    const p = this.editParams();
    if (!p) return;
    this.editParams.set({ ...p, counter: p.counter + 1 });
    this.triggerRegenerate();
  }

  decrementCounter(): void {
    const p = this.editParams();
    if (!p || p.counter <= 1) return;
    this.editParams.set({ ...p, counter: p.counter - 1 });
    this.triggerRegenerate();
  }

  clearMasterSecret(): void {
    this.secretVersion++;
    this.generationVersion++;
    this.generating.set(false);
    this.cancelSecurityKeyOperation();
    this.endKeySession();
    this.masterSecret.set('');
    this.showMasterSecret.set(false);
    this.generatedPassword.set('');
    this.showPassword.set(false);
    this.copySuccess.set(false);
    this.copyError.set(false);
  }

  onSecurityKeyUnlocked(secret: string): void {
    this.secretVersion++;
    this.endKeySession();
    this.masterSecret.set(secret);
    this.showMasterSecret.set(false);
    this.keyUnlocked.set(true);
    this.keyDeadline = this.idleDeadline = Date.now() + this.lockAfterMs;
    this.scheduleLock();
    this.triggerRegenerate();
  }

  async onKeyCopyUnlocked(secret: string): Promise<void> {
    this.onSecurityKeyUnlocked(secret);
    if (this.editParams() && !this.editing() && !this.settingsOpen()) await this.generateAndCopy();
  }

  onParamsImported(params: PasswordParams[]): void {
    this.savedParams.set(params);
    this.storageError.set('');
  }

  private endKeySession(): void {
    clearTimeout(this.lockTimer);
    this.lockTimer = undefined;
    this.idleDeadline = this.keyDeadline = 0;
    this.keyUnlocked.set(false);
  }

  private cancelSecurityKeyOperation(): void {
    this.keyControls?.cancelOperation();
    this.securityKeyResetVersion.update(version => version + 1);
  }

  private async writeClipboardWithRetry(text: string, version: number): Promise<boolean> {
    for (let attempt = 1; attempt <= this.clipboardRetryAttempts; attempt += 1) {
      if (!this.checkSession() || version !== this.secretVersion) return false;
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        if (attempt === this.clipboardRetryAttempts) {
          return false;
        }

        await this.delay(this.clipboardRetryDelayMs);
      }
    }

    return false;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  onParamChange(): void {
    this.triggerRegenerate();
  }

  onMasterSecretChange(): void {
    this.secretVersion++;
    this.endKeySession();
    this.cancelSecurityKeyOperation();
    if (this.masterSecret()) {
      this.idleDeadline = Date.now() + this.lockAfterMs;
      this.scheduleLock();
    }
    this.copySuccess.set(false);
    this.copyError.set(false);
    this.triggerRegenerate();
  }

  formatUpdatedAt(iso: string): string {
    const date = new Date(iso);
    const now = new Date();
    const sameDay = date.toDateString() === now.toDateString();
    if (sameDay) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    const diffDays = Math.floor((now.getTime() - date.getTime()) / 86_400_000);
    if (diffDays < 7) {
      return date.toLocaleDateString([], { weekday: 'short' });
    }
    if (date.getFullYear() === now.getFullYear()) {
      return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }
    return date.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  }
}
