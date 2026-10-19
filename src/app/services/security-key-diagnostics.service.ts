import { Injectable, signal } from '@angular/core';
import { APP_BUILD_ID } from '../build-info';

export type DiagnosticPhase = 'registration' | 'setup' | 'unlock';
export type DiagnosticEventName = 'request-options' | 'credential-response' | 'prf-result' | 'verification' | 'encryption-verified';
export type DiagnosticSummary = 'credential-registered' | 'encryption-verified' | 'master-unlocked';

export interface DiagnosticEnvironment {
  origin: string | null;
  secureContext: boolean;
  browserUA: string;
  visibility: 'visible' | 'hidden' | 'unknown';
  topLevel: boolean | null;
  userActivation: { isActive: boolean | null; hasBeenActive: boolean | null };
  apis: { publicKeyCredential: boolean; credentialCreate: boolean; credentialGet: boolean; webCrypto: boolean };
}

export interface DiagnosticEvent {
  name: DiagnosticEventName;
  elapsedMs: number;
  details: Record<string, string | number | boolean | null | string[] | number[]>;
  environment?: DiagnosticEnvironment;
}

export interface DiagnosticEntry {
  id: number;
  phase: DiagnosticPhase;
  requestKind: 'create' | 'get';
  startedAt: string;
  elapsedMs: number;
  status: 'pending' | 'succeeded' | 'failed';
  environment: DiagnosticEnvironment;
  events: DiagnosticEvent[];
  error?: { name: string; code?: number; aborted: boolean };
  summary?: DiagnosticSummary;
}

const PHASES = ['registration', 'setup', 'unlock'] as const;
const EVENT_NAMES = ['request-options', 'credential-response', 'prf-result', 'verification', 'encryption-verified'] as const;
const SUMMARIES = ['credential-registered', 'encryption-verified', 'master-unlocked'] as const;
const ERROR_NAMES = ['AbortError', 'NotAllowedError', 'NotSupportedError', 'SecurityError', 'InvalidStateError',
  'ConstraintError', 'DataError', 'EncodingError', 'OperationError', 'NotFoundError', 'UnknownError',
  'TimeoutError', 'TypeError', 'RangeError', 'Error', 'Other'] as const;
const MAX_ENTRIES = 50;
const MAX_EVENTS = 16;
const MAX_ELAPSED_MS = 86_400_000;

function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

function member<T extends string>(value: unknown, values: readonly T[]): value is T {
  return typeof value === 'string' && (values as readonly string[]).includes(value);
}

function booleanOrNull(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function origin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : null;
  } catch {
    return null;
  }
}

function environment(value: unknown): DiagnosticEnvironment {
  const input = record(value);
  const activation = record(input['userActivation']);
  const apis = record(input['apis']);
  return {
    origin: origin(input['origin']),
    secureContext: input['secureContext'] === true,
    browserUA: typeof input['browserUA'] === 'string'
      ? input['browserUA'].replace(/[^\x20-\x7e]/g, '').slice(0, 512) : 'unknown',
    visibility: member(input['visibility'], ['visible', 'hidden'] as const) ? input['visibility'] : 'unknown',
    topLevel: booleanOrNull(input['topLevel']),
    userActivation: {
      isActive: booleanOrNull(activation['isActive']),
      hasBeenActive: booleanOrNull(activation['hasBeenActive']),
    },
    apis: {
      publicKeyCredential: apis['publicKeyCredential'] === true,
      credentialCreate: apis['credentialCreate'] === true,
      credentialGet: apis['credentialGet'] === true,
      webCrypto: apis['webCrypto'] === true,
    },
  };
}

function captureEnvironment(): DiagnosticEnvironment {
  let topLevel: boolean | null = null;
  try {
    if (typeof window !== 'undefined') topLevel = window.self === window.top;
  } catch { /* A restricted frame does not reveal additional information. */ }
  return environment({
    origin: typeof window === 'undefined' ? null : window.location.origin,
    secureContext: typeof window !== 'undefined' && window.isSecureContext,
    browserUA: typeof navigator === 'undefined' ? undefined : navigator.userAgent,
    visibility: typeof document === 'undefined' ? undefined : document.visibilityState,
    topLevel,
    userActivation: typeof navigator === 'undefined' ? undefined : {
      isActive: navigator.userActivation?.isActive,
      hasBeenActive: navigator.userActivation?.hasBeenActive,
    },
    apis: {
      publicKeyCredential: typeof PublicKeyCredential !== 'undefined',
      credentialCreate: typeof navigator !== 'undefined' && typeof navigator.credentials?.create === 'function',
      credentialGet: typeof navigator !== 'undefined' && typeof navigator.credentials?.get === 'function',
      webCrypto: typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined',
    },
  });
}

function now(): number {
  const value = typeof performance === 'undefined' ? NaN : performance.now();
  return Number.isFinite(value) ? value : Date.now();
}

function milliseconds(value: number): number {
  return Number.isFinite(value) ? Math.min(MAX_ELAPSED_MS, Math.max(0, Math.round(value))) : 0;
}

/** Select only fields whose value types and possible strings are explicitly allowed. */
function details(name: DiagnosticEventName, value: unknown): DiagnosticEvent['details'] {
  const input = record(value);
  const output: DiagnosticEvent['details'] = {};
  if (name === 'request-options') {
    for (const key of ['residentKey', 'userVerification']) {
      if (member(input[key], ['required', 'preferred', 'discouraged'] as const)) output[key] = input[key];
    }
    if (member(input['authenticatorAttachment'], ['cross-platform', 'platform'] as const)) {
      output['authenticatorAttachment'] = input['authenticatorAttachment'];
    }
    if (Array.isArray(input['extensions']) && input['extensions'].includes('prf')) output['extensions'] = ['prf'];
    const algorithmIds = input['algorithmIds'];
    if (Array.isArray(algorithmIds)) {
      const algorithms = [-7, -257, -8].filter(algorithm => algorithmIds.includes(algorithm));
      output['algorithmIds'] = algorithms;
      output['algorithmCount'] = algorithms.length;
    }
  } else if (name === 'credential-response') {
    if (input['attachment'] === null || member(input['attachment'], ['cross-platform', 'platform'] as const)) {
      output['attachment'] = input['attachment'];
    }
  } else if (name === 'prf-result') {
    if (typeof input['enabled'] === 'boolean') output['enabled'] = input['enabled'];
    if (typeof input['resultPresent'] === 'boolean') output['resultPresent'] = input['resultPresent'];
    const length = input['resultLength'];
    if (typeof length === 'number' && Number.isSafeInteger(length) && length >= 0) {
      output['resultLength'] = length <= 64 ? length : 'over-64';
    } else if (length === 'over-64') output['resultLength'] = 'over-64';
  } else if (name === 'verification' && typeof input['userVerified'] === 'boolean') {
    output['userVerified'] = input['userVerified'];
  } else if (name === 'encryption-verified' && typeof input['verified'] === 'boolean') {
    output['verified'] = input['verified'];
  }
  return output;
}

function safeError(error: unknown, signal?: AbortSignal): NonNullable<DiagnosticEntry['error']> {
  const isDomException = typeof DOMException !== 'undefined' && error instanceof DOMException;
  const name = error instanceof Error || isDomException ? error.name : undefined;
  const output: NonNullable<DiagnosticEntry['error']> = {
    name: member(name, ERROR_NAMES) ? name : 'Other',
    aborted: signal?.aborted === true || name === 'AbortError',
  };
  if (isDomException && Number.isInteger(error.code) && error.code >= 0 && error.code <= 25) output.code = error.code;
  return output;
}

/** Rebuild report rows too, so even extra properties added to a signal value never get exported. */
function reportEntry(value: unknown): DiagnosticEntry | null {
  const input = record(value);
  if (!Number.isSafeInteger(input['id']) || (input['id'] as number) <= 0 ||
      !member(input['phase'], PHASES) || !member(input['requestKind'], ['create', 'get'] as const) ||
      !member(input['status'], ['pending', 'succeeded', 'failed'] as const) ||
      typeof input['startedAt'] !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(input['startedAt'])) return null;
  const output: DiagnosticEntry = {
    id: input['id'] as number,
    phase: input['phase'],
    requestKind: input['requestKind'],
    startedAt: input['startedAt'],
    elapsedMs: milliseconds(typeof input['elapsedMs'] === 'number' ? input['elapsedMs'] : 0),
    status: input['status'],
    environment: environment(input['environment']),
    events: [],
  };
  if (Array.isArray(input['events'])) {
    for (const event of input['events'].slice(0, MAX_EVENTS)) {
      const item = record(event);
      if (!member(item['name'], EVENT_NAMES)) continue;
      const selected: DiagnosticEvent = {
        name: item['name'],
        elapsedMs: milliseconds(typeof item['elapsedMs'] === 'number' ? item['elapsedMs'] : 0),
        details: details(item['name'], item['details']),
      };
      if (selected.name === 'request-options') selected.environment = environment(item['environment']);
      output.events.push(selected);
    }
  }
  if (input['error']) {
    const error = record(input['error']);
    output.error = { name: member(error['name'], ERROR_NAMES) ? error['name'] : 'Other', aborted: error['aborted'] === true };
    const code = error['code'];
    if (typeof code === 'number' && Number.isInteger(code) && code >= 0 && code <= 25) output.error.code = code;
  }
  if (member(input['summary'], SUMMARIES)) output.summary = input['summary'];
  return output;
}

@Injectable({ providedIn: 'root' })
export class SecurityKeyDiagnosticsService {
  private readonly enabledState = signal(false);
  private readonly entriesState = signal<DiagnosticEntry[]>([]);
  readonly enabled = this.enabledState.asReadonly();
  readonly entries = this.entriesState.asReadonly();
  private nextId = 0;
  private readonly active = new Map<number, number>();

  setEnabled(enabled: boolean): void {
    const active = enabled === true;
    this.enabledState.set(active);
    if (!active) this.clear();
  }

  clear(): void {
    this.entriesState.set([]);
    this.active.clear();
  }

  begin(phase: DiagnosticPhase, requestKind: 'create' | 'get'): number {
    if (!this.enabled() || !member(phase, PHASES) || !member(requestKind, ['create', 'get'] as const)) return 0;
    const id = ++this.nextId;
    this.active.set(id, now());
    const entry: DiagnosticEntry = { id, phase, requestKind, startedAt: new Date().toISOString(),
      elapsedMs: 0, status: 'pending', environment: captureEnvironment(), events: [] };
    const entries = [...this.entries(), entry].slice(-MAX_ENTRIES);
    const retained = new Set(entries.map(item => item.id));
    for (const activeId of this.active.keys()) if (!retained.has(activeId)) this.active.delete(activeId);
    this.entriesState.set(entries);
    return id;
  }

  event(id: number, name: DiagnosticEventName, value?: unknown): void {
    if (!this.enabled() || !this.active.has(id) || !member(name, EVENT_NAMES)) return;
    const entry = this.entries().find(item => item.id === id);
    if (!entry || entry.events.length >= MAX_EVENTS) return;
    const event: DiagnosticEvent = { name, elapsedMs: this.elapsed(id), details: details(name, value) };
    if (name === 'request-options') event.environment = captureEnvironment();
    this.entriesState.update(entries => entries.map(item => item.id === id ? { ...item, events: [...item.events, event] } : item));
  }

  fail(id: number, error: unknown, signal?: AbortSignal): void {
    if (!this.enabled() || !this.active.has(id)) return;
    const selected = safeError(error, signal);
    this.entriesState.update(entries => entries.map(item => item.id === id
      ? { ...item, elapsedMs: this.elapsed(id), status: 'failed', error: selected } : item));
    this.active.delete(id);
  }

  success(id: number, summary?: DiagnosticSummary): void {
    if (!this.enabled() || !this.active.has(id)) return;
    this.entriesState.update(entries => entries.map(item => item.id === id
      ? { ...item, elapsedMs: this.elapsed(id), status: 'succeeded', ...(member(summary, SUMMARIES) ? { summary } : {}) } : item));
    this.active.delete(id);
  }

  exportReport(): string {
    if (!this.enabled()) return '';
    return JSON.stringify({
      format: 'password-mgr-security-key-diagnostics',
      version: 1,
      buildId: /^[A-Za-z0-9._+-]{1,120}$/.test(APP_BUILD_ID) ? APP_BUILD_ID : 'unknown',
      entries: this.entries().slice(-MAX_ENTRIES).map(reportEntry).filter(entry => entry !== null),
    }, null, 2);
  }

  private elapsed(id: number): number {
    return milliseconds(now() - (this.active.get(id) ?? now()));
  }
}
