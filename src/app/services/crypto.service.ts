import { Injectable } from '@angular/core';
import { PasswordParams } from '../models/password-params.model';

const PBKDF2_ITERATIONS = 600_000;

@Injectable({ providedIn: 'root' })
export class CryptoService {
  async generatePassword(masterSecret: string, params: PasswordParams): Promise<string> {
    const { domain, username, counter, length, includeUppercase, includeLowercase, includeNumbers, symbols } = params;

    // Build charset
    const charset = this.buildCharset(includeUppercase, includeLowercase, includeNumbers, symbols);
    if (charset.length === 0) {
      throw new Error('At least one character set must be selected');
    }

    // Build deterministic salt encoding all parameters
    const sortedSymbols = symbols.split('').sort().join('');
    const charsetFlags = `${includeUppercase ? '1' : '0'}${includeLowercase ? '1' : '0'}${includeNumbers ? '1' : '0'}`;
    const saltStr = [domain.toLowerCase(), username.toLowerCase(), String(counter), String(length), sortedSymbols, charsetFlags].join('\0');
    const saltBytes = new TextEncoder().encode(saltStr);

    // Import master secret as PBKDF2 key material
    const secretBytes = new TextEncoder().encode(masterSecret);
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      secretBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    // Derive 64-byte master key
    const masterKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-512',
      },
      keyMaterial,
      512
    );
    const masterKey = new Uint8Array(masterKeyBits);

    // Expand bytes via SHA-512(masterKey || i)
    const expandedBytes = await this.expandBytes(masterKey, length * 4);

    // Map to charset using rejection sampling
    return this.mapToCharset(expandedBytes, charset, length);
  }

  private buildCharset(upper: boolean, lower: boolean, numbers: boolean, symbols: string): string {
    let charset = '';
    if (upper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (lower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (numbers) charset += '0123456789';
    if (symbols) charset += [...new Set(symbols.split(''))].join('');
    return charset;
  }

  private async expandBytes(masterKey: Uint8Array, minBytes: number): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    let i = 0;

    while (totalBytes < minBytes) {
      const input = new Uint8Array(masterKey.length + 1);
      input.set(masterKey);
      input[masterKey.length] = i;

      const hashBuf = await crypto.subtle.digest('SHA-512', input);
      const chunk = new Uint8Array(hashBuf);
      chunks.push(chunk);
      totalBytes += chunk.length;
      i++;
    }

    const result = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  private mapToCharset(bytes: Uint8Array, charset: string, length: number): string {
    const charsetLen = charset.length;
    const limit = Math.floor(65536 / charsetLen) * charsetLen;
    let result = '';
    let byteIndex = 0;

    while (result.length < length) {
      if (byteIndex + 1 >= bytes.length) {
        throw new Error('Not enough expanded bytes for rejection sampling');
      }
      const value = (bytes[byteIndex] << 8) | bytes[byteIndex + 1];
      byteIndex += 2;

      if (value < limit) {
        result += charset[value % charsetLen];
      }
      // else: reject and try next uint16
    }

    return result;
  }
}
