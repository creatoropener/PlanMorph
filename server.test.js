import assert from 'node:assert';
import { test } from 'node:test';

test('TypeScript auto-discovery check', () => {
  const values: number[] =;
  assert.strictEqual(values.length, 3);
});
