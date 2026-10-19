import '@angular/compiler';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { StorageService } from '../src/app/services/storage.service';
import { MemoryStorage, passwordParams } from './fixtures';

function setup(raw?: string) {
  const memory = new MemoryStorage();
  if (raw !== undefined) memory.setItem('password-mgr:params', raw);
  Object.defineProperty(globalThis, 'localStorage', { value: memory, configurable: true });
  return { memory, service: new StorageService() };
}

test('storage round-trips exact generation inputs and strips transient fields', () => {
  const { service } = setup();
  assert.deepEqual(service.load(), []);
  const params = passwordParams({ domain: ' EXAMPLE.com ', username: ' 用户 ', symbols: '!!@' });
  service.save([Object.assign(params, { masterSecret: 'never-save-me' })]);
  assert.equal(service.readRaw()?.includes('never-save-me'), false);
  assert.deepEqual(service.load(), [passwordParams({ domain: ' EXAMPLE.com ', username: ' 用户 ', symbols: '!!@' })]);
});

test('malformed settings are reported and never overwritten by save or deletion', () => {
  for (const raw of [
    '', '{broken', '{}',
    JSON.stringify([passwordParams(), passwordParams({ id: 'bad', length: 7 })]),
    JSON.stringify([passwordParams({ counter: 1.5 })]),
    JSON.stringify([{ ...passwordParams(), symbols: null }]),
    JSON.stringify([passwordParams(), passwordParams()]),
  ]) {
    const { service, memory } = setup(raw);
    const writes = memory.writes;
    assert.throws(() => service.load(), /damaged/);
    assert.throws(() => service.save([]), /damaged/);
    assert.throws(() => service.remove('site-1'), /damaged/);
    assert.equal(service.readRaw(), raw);
    assert.equal(memory.writes, writes);
  }
});

test('storage errors distinguish inaccessible data and failed writes', () => {
  const { service, memory } = setup();
  memory.getItem = () => { throw new Error('denied'); };
  assert.throws(() => service.load(), /Cannot read/);
  assert.throws(() => service.save([]), /Cannot read/);
  memory.getItem = () => null;
  memory.setItem = () => { throw new Error('quota'); };
  assert.throws(() => service.save([passwordParams()]), /Could not save/);
});
