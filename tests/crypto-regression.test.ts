import '@angular/compiler';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CryptoService } from '../src/app/services/crypto.service';
import { passwordParams } from './fixtures';

// Fixed vectors independently calculated with Node's PBKDF2-SHA512 and SHA512
// primitives from the original generator before adding security-key unlock.
const vectors = [
  {
    secret: 'correct horse battery staple',
    params: passwordParams(),
    expected: 'mtavKwNloUEm7#_G(hrV',
  },
  {
    secret: ' \tpässw🔑rd\n秘密 ',
    params: passwordParams({
      domain: 'EXAMPLE.org', username: 'UsÉr', counter: 7, length: 32,
      symbols: '!!@#@',
    }),
    expected: 'WgM00!EGWgZstRoDcYNRKkXcF@DqI6@K',
  },
  {
    secret: 'numbers only',
    params: passwordParams({
      domain: 'bank.example', username: '123', counter: 25, length: 64,
      includeUppercase: false, includeLowercase: false, symbols: '',
    }),
    expected: '3681375850074984400402506569460079464747216848765798415892512262',
  },
  {
    secret: 'symbols',
    params: passwordParams({
      domain: 'service.example', username: '', counter: 2, length: 8,
      includeUppercase: false, includeLowercase: false,
      includeNumbers: false, symbols: '!%=',
    }),
    expected: '!%!!%%!!',
  },
];

for (const [index, vector] of vectors.entries()) {
  test(`existing password vector ${index + 1} is unchanged`, async () => {
    assert.equal(await new CryptoService().generatePassword(vector.secret, vector.params), vector.expected);
  });
}

test('generation remains deterministic and preserves case-insensitive site identity', async () => {
  const service = new CryptoService();
  const vector = vectors[0];
  assert.equal(await service.generatePassword(vector.secret, passwordParams({
    domain: 'example.com', username: 'alice@example.com',
  })), vector.expected);
  assert.equal(await service.generatePassword(vector.secret, vector.params), vector.expected);
});

test('generation still rejects an empty character set', async () => {
  await assert.rejects(new CryptoService().generatePassword('secret', passwordParams({
    includeUppercase: false, includeLowercase: false,
    includeNumbers: false, symbols: '',
  })), /character set/i);
});
