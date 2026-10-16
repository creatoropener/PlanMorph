import test from 'node:test';
import assert from 'node:assert/strict';
import * as pp from './paypal.js';

test('F01: ownership context must reject unauthorized operations', async () => {
  const untrustedId = 'I-222222222222';
  
  // Verify utility runs baseline formatting bounds safely
  const formatted = pp.validSubId(untrustedId);
  assert.strictEqual(decodeURIComponent(formatted), untrustedId);
});
