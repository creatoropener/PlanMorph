const BASE = 'https://api-m.sandbox.paypal.com';
const SUB_ID_RE = /^I-[A-Z0-9]{10,16}$/;
let tok = { v: null, exp: 0 };

export function validSubId(id) {
  if (typeof id !== 'string' || !SUB_ID_RE.test(id)) {
    throw Object.assign(new Error('Invalid subscription ID'), { status: 400, expose: true });
  }
  return encodeURIComponent(id);
}

async function token() {
  if (tok.v && Date.now() < tok.exp) return tok.v;
  const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_SECRET}`).toString('base64');
  const r = await fetch(`${BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
  });
  const j = await r.json();
  if (!r.ok) throw new Error('PayPal auth failed: ' + JSON.stringify(j));
  tok = { v: j.access_token, exp: Date.now() + (j.expires_in - 60) * 1000 };
  return tok.v;
}

async function api(method, path, body) {
  const r = await fetch(BASE + path, {
    method,
    headers: { Authorization: `Bearer ${await token()}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await r.text();
  if (!r.ok) throw new Error(`PayPal ${method} ${path} -> ${r.status}: ${t}`);
  return t ? JSON.parse(t) : {};
}

export const createProduct = () => api('POST', '/v1/catalogs/products', { name: 'Acme Notes', type: 'SERVICE', category: 'SOFTWARE' });

export function createPlan(product_id, name, price, trialPrice) {
  const frequency = { interval_unit: 'MONTH', interval_count: 1 };
  const pricing_scheme = v => ({ fixed_price: { value: v, currency_code: 'USD' } });
  const cycles = [];
  if (trialPrice) cycles.push({ tenure_type: 'TRIAL', sequence: 1, total_cycles: 3, frequency, pricing_scheme: pricing_scheme(trialPrice) });
  cycles.push({ tenure_type: 'REGULAR', sequence: cycles.length + 1, total_cycles: 0, frequency, pricing_scheme: pricing_scheme(price) });
  return api('POST', '/v1/billing/plans', {
    product_id, name, status: 'ACTIVE', billing_cycles: cycles,
    payment_preferences: { auto_bill_outstanding: true, payment_failure_threshold: 3 },
  });
}

export const createSubscription = (plan_id, ctx) =>
  api('POST', '/v1/billing/subscriptions', { plan_id, application_context: { ...ctx, user_action: 'SUBSCRIBE_NOW' } });
export const getSubscription = id => api('GET', `/v1/billing/subscriptions/${validSubId(id)}`);
// Plan switches need buyer re-consent: the response contains an "approve" link.
export const revise = (id, plan_id, ctx) => api('POST', `/v1/billing/subscriptions/${validSubId(id)}/revise`, { plan_id, application_context: ctx });
export const suspend = (id, reason) => api('POST', `/v1/billing/subscriptions/${validSubId(id)}/suspend`, { reason });
export const cancel = (id, reason) => api('POST', `/v1/billing/subscriptions/${validSubId(id)}/cancel`, { reason });
