import {
  Component,
  OnInit,
  OnDestroy,
  signal,
  computed,
  inject,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Subject, Subscription } from 'rxjs';
import { debounceTime } from 'rxjs/operators';

import { PasswordParams, createDefaultParams } from './models/password-params.model';
import { CryptoService } from './services/crypto.service';
import { StorageService } from './services/storage.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent implements OnInit, OnDestroy {
  private crypto = inject(CryptoService);
  private storage = inject(StorageService);

  readonly supportsTextSecurity = CSS.supports('-webkit-text-security', 'disc');

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

  ngOnInit(): void {
    this.savedParams.set(this.storage.load());

    this.sub.add(
      this.regenerate$.pipe(debounceTime(500)).subscribe(() => {
        void this.doGenerate();
      })
    );
  }

  ngOnDestroy(): void {
    this.sub.unsubscribe();
  }

  // Called whenever any relevant input changes
  triggerRegenerate(): void {
    this.generatedPassword.set('');
    this.error.set('');
    this.regenerate$.next();
  }

  private async doGenerate(): Promise<void> {
    const secret = this.masterSecret();
    const params = this.editParams();
    if (!secret || !params || !params.domain) {
      this.generatedPassword.set('');
      return;
    }

    this.generating.set(true);
    this.error.set('');
    try {
      const pwd = await this.crypto.generatePassword(secret, params);
      this.generatedPassword.set(pwd);
    } catch (e) {
      this.error.set(e instanceof Error ? e.message : 'Generation failed');
      this.generatedPassword.set('');
    } finally {
      this.generating.set(false);
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
    const updated = this.storage.remove(p.id);
    this.savedParams.set(updated);
    this.editParams.set(null);
    this.selectedId.set(null);
    this.generatedPassword.set('');
  }

  async copyPassword(): Promise<void> {
    const pwd = this.generatedPassword();
    if (!pwd) return;
    try {
      await navigator.clipboard.writeText(pwd);
      this.copySuccess.set(true);
      setTimeout(() => this.copySuccess.set(false), 2000);
      setTimeout(() => navigator.clipboard.writeText(''), 30000);
    } catch {
      this.copyError.set(true);
      setTimeout(() => this.copyError.set(false), 3000);
    }
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
    this.masterSecret.set('');
    this.generatedPassword.set('');
    this.showMasterSecret.set(false);
  }

  onParamChange(): void {
    this.triggerRegenerate();
  }

  onMasterSecretChange(): void {
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
