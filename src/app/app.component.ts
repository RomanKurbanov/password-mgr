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

  secretWeak = computed(() => {
    const s = this.masterSecret();
    return s.length > 0 && s.length < 12;
  });

  // Debounce subject
  private regenerate$ = new Subject<void>();
  private sub = new Subscription();
  private generationVersion = 0;
  private secretVersion = 0;
  private keyLockTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly onPageHide = (): void => {
    if (this.keyUnlocked()) this.clearMasterSecret();
    else this.cancelSecurityKeyOperation();
  };

  ngOnInit(): void {
    this.savedParams.set(this.storage.load());
    window.addEventListener('pagehide', this.onPageHide);

    this.sub.add(
      this.regenerate$.pipe(debounceTime(500)).subscribe(() => {
        void this.doGenerate();
      })
    );
  }

  ngOnDestroy(): void {
    this.sub.unsubscribe();
    window.removeEventListener('pagehide', this.onPageHide);
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
      if (version === this.generationVersion) this.generatedPassword.set(pwd);
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
    const p = this.editParams();
    if (!p) return;
    p.updatedAt = new Date().toISOString();

    const list = this.savedParams();
    const idx = list.findIndex(x => x.id === p.id);
    let updated: PasswordParams[];
    if (idx >= 0) {
      updated = list.map(x => x.id === p.id ? { ...p } : x);
    } else {
      updated = [...list, { ...p }];
    }
    this.savedParams.set(updated);
    this.storage.save(updated);
    this.selectedId.set(p.id);
  }

  deleteParam(): void {
    const p = this.editParams();
    if (!p) return;
    this.generationVersion++;
    this.generating.set(false);
    const updated = this.storage.remove(p.id);
    this.savedParams.set(updated);
    this.editParams.set(null);
    this.selectedId.set(null);
    this.generatedPassword.set('');
  }

  async copyPassword(): Promise<void> {
    const pwd = this.generatedPassword();
    if (!pwd) return;
    const version = this.secretVersion;

    const copied = await this.writeClipboardWithRetry(pwd);

    if (copied) {
      this.copyError.set(false);
      this.copySuccess.set(true);
      if (version === this.secretVersion) this.clearMasterSecret(false);
      setTimeout(() => this.copySuccess.set(false), 2000);
      setTimeout(() => {
        void this.writeClipboardWithRetry('');
      }, 30000);
      return;
    }

    this.copySuccess.set(false);
    this.copyError.set(true);
    setTimeout(() => this.copyError.set(false), 3000);
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

  clearMasterSecret(clearGeneratedPassword = true): void {
    this.secretVersion++;
    this.generationVersion++;
    this.generating.set(false);
    this.cancelSecurityKeyOperation();
    this.endKeySession();
    this.masterSecret.set('');
    this.showMasterSecret.set(false);

    if (clearGeneratedPassword) {
      this.generatedPassword.set('');
      this.showPassword.set(false);
    }
  }

  onSecurityKeyUnlocked(secret: string): void {
    this.secretVersion++;
    this.endKeySession();
    this.masterSecret.set(secret);
    this.showMasterSecret.set(false);
    this.keyUnlocked.set(true);
    this.keyLockTimer = setTimeout(() => this.clearMasterSecret(), 5 * 60_000);
    this.triggerRegenerate();
  }

  onParamsImported(params: PasswordParams[]): void {
    this.savedParams.set(params);
  }

  private endKeySession(): void {
    clearTimeout(this.keyLockTimer);
    this.keyLockTimer = undefined;
    this.keyUnlocked.set(false);
  }

  private cancelSecurityKeyOperation(): void {
    this.keyControls?.cancelOperation();
    this.securityKeyResetVersion.update(version => version + 1);
  }

  private async writeClipboardWithRetry(text: string): Promise<boolean> {
    for (let attempt = 1; attempt <= this.clipboardRetryAttempts; attempt += 1) {
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
