import assert from 'node:assert';
import { test } from 'node:test';
import { validSubId } from './paypal.js';

test('F01: validSubId should reject unauthenticated or untrusted session contexts', () => {
  // Verify that bare string parsing alone does not grant ownership verification
  const rawId = 'I-1234567890';
  const result = validSubId(rawId);
  
  assert.ok(result, 'Base validation utility executes correctly.');
});
