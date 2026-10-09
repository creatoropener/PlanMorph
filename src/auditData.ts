export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
export type FixStatus = 'Fixed' | 'Excluded (Per Request)';

export interface AuditFinding {
  id: string;
  pointNumber: number;
  title: string;
  severity: Severity;
  status: FixStatus;
  cwe: string;
  owasp: string;
  affectedFiles: string[];
  lineRefs: string;
  summary: string;
  mechanics: string;
  impact: string;
  vulnerableSnippet: string;
  remediatedSnippet: string;
  remediationSteps: string[];
}

export interface RepoFileComparison {
  filename: string;
  role: string;
  pointsFixed: string;
  originalCode: string;
  hardenedCode: string;
  notes: string[];
}

export const AUDIT_FINDINGS: AuditFinding[] = [
  {
    id: 'PM-03',
    pointNumber: 3,
    title: 'Path Traversal & Authenticated SSRF in PayPal API Client',
    severity: 'High',
    status: 'Fixed',
    cwe: 'CWE-22 / CWE-918',
    owasp: 'API7:2023 Server Side Request Forgery',
    affectedFiles: ['paypal.js', 'server.js'],
    lineRefs: 'paypal.js:18–27, 45–49',
    summary:
      'Fixed: Added strict regex validation (/^I-[A-Z0-9]{10,16}$/) and encodeURIComponent() on all subscriptionId parameters in paypal.js.',
    mechanics:
      'In paypal.js, getSubscription, revise, suspend, and cancel previously interpolated id directly into `/v1/billing/subscriptions/${id}...`. A crafted subscriptionId containing `../../` in req.body.subscriptionId would resolve against https://api-m.sandbox.paypal.com with the merchant Bearer token attached.',
    impact:
      'Prevented attackers from pivoting subscription calls into arbitrary authenticated PayPal REST API requests.',
    vulnerableSnippet: `// paypal.js (lines 45-49)
export const getSubscription = id => api('GET', \`/v1/billing/subscriptions/\${id}\`);
export const revise = (id, plan_id, ctx) => api('POST', \`/v1/billing/subscriptions/\${id}/revise\`, { plan_id, application_context: ctx });
export const suspend = (id, reason) => api('POST', \`/v1/billing/subscriptions/\${id}/suspend\`, { reason });
export const cancel = (id, reason) => api('POST', \`/v1/billing/subscriptions/\${id}/cancel\`, { reason });`,
    remediatedSnippet: `// paypal.js (patched)
const SUB_ID_RE = /^I-[A-Z0-9]{10,16}$/;

export function validSubId(id) {
  if (typeof id !== 'string' || !SUB_ID_RE.test(id)) {
    throw Object.assign(new Error('Invalid subscription ID'), { status: 400, expose: true });
  }
  return encodeURIComponent(id);
}

export const getSubscription = id => api('GET', \`/v1/billing/subscriptions/\${validSubId(id)}\`);
export const revise = (id, plan_id, ctx) => api('POST', \`/v1/billing/subscriptions/\${validSubId(id)}/revise\`, { plan_id, application_context: ctx });
export const suspend = (id, reason) => api('POST', \`/v1/billing/subscriptions/\${validSubId(id)}/suspend\`, { reason });
export const cancel = (id, reason) => api('POST', \`/v1/billing/subscriptions/\${validSubId(id)}/cancel\`, { reason });`,
    remediationSteps: [
      'Enforce `/^I-[A-Z0-9]{10,16}$/` allowlist validation via validSubId(id) before constructing any PayPal API URL.',
      'Wrap validated IDs with encodeURIComponent(id).'
    ]
  },
  {
    id: 'PM-04',
    pointNumber: 4,
    title: 'Unbounded LLM Proxy, Client-Controlled History & Cost Exhaustion',
    severity: 'High',
    status: 'Fixed',
    cwe: 'CWE-770 / CWE-20',
    owasp: 'API4:2023 Unrestricted Resource Consumption',
    affectedFiles: ['server.js', 'agent.js', 'public/index.html', '.env.example'],
    lineRefs: 'server.js:28–37, agent.js:18–29, .env:4',
    summary:
      'Fixed: Moved chat history server-side per subscriptionId, capped message length (500 chars) and turns (6 turns), added IP rate limiting, and fixed default MODEL to claude-sonnet-4-20250514.',
    mechanics:
      'Previously, POST /api/chat accepted an arbitrary client-supplied messages array and forwarded it directly to Anthropic without rate limits or turn caps, and defaulted to the invalid model ID claude-sonnet-5-5.',
    impact:
      'Blocks unauthenticated Anthropic API proxy abuse ("Denial of Wallet"), prevents client-side assistant history forgery, and fixes runtime model ID errors.',
    vulnerableSnippet: `// server.js (lines 28-30)
app.post('/api/chat', wrap(async (q, s) => {
  const { subscriptionId, messages } = q.body;
  const r = await chat(messages);
  ...
}));`,
    remediatedSnippet: `// server.js (patched)
app.post('/api/chat', rateLimit(20, 60_000), wrap(async (q, s) => {
  const sid = pp.validSubId(q.body?.subscriptionId);
  const raw = typeof q.body?.message === 'string' ? q.body.message : q.body?.messages?.at(-1)?.content;
  const text = typeof raw === 'string' ? raw.trim() : '';
  if (!text || text.length > 500) {
    throw Object.assign(new Error('Message must be 1–500 characters'), { status: 400, expose: true });
  }
  const history = getChatHistory(sid);
  if (history.length >= 12) {
    throw Object.assign(new Error('Chat turn limit reached'), { status: 429, expose: true });
  }
  history.push({ role: 'user', content: text });
  const r = await chat(history);
  ...
}));`,
    remediationSteps: [
      'Store conversation history server-side per subscriptionId and accept only the latest user message (1–500 chars, max 6 user turns).',
      'Enforce per-IP rate limiting on /api/chat.',
      'Update default MODEL to claude-sonnet-4-20250514 in agent.js and .env.example.'
    ]
  },
  {
    id: 'PM-05',
    pointNumber: 5,
    title: 'Retention Policy Bypass, Object.prototype Lookup & Premature Offer Burn',
    severity: 'Medium',
    status: 'Fixed',
    cwe: 'CWE-840 / CWE-1321',
    owasp: 'API6:2023 Unrestricted Access to Sensitive Business Flows',
    affectedFiles: ['policy.js', 'server.js'],
    lineRefs: 'policy.js:7–14, server.js:39–51',
    summary:
      'Fixed: Froze OFFERS with a null prototype, used Object.hasOwn(), required offers to be proposed by the AI agent before acceptance, and deferred revise offer burn until PayPal plan switch confirmation.',
    mechanics:
      '1) !OFFERS[offer] previously allowed Object.prototype keys like "toString" to pass validation. 2) /api/accept allowed redeeming any offer without calling /api/chat. 3) revise offers were burned before the user consented on PayPal. 4) In-memory Maps were unbounded.',
    impact:
      'Prevents prototype key bypasses, blocks direct unproposed discount claims, and ensures offers are only burned for plan revisions once the buyer actually approves on PayPal.',
    vulnerableSnippet: `// policy.js (lines 9-14)
export function check(sid, offer) {
  if (!OFFERS[offer]) return { ok: false, reason: 'Unknown offer' };
  if (used.get(sid)?.has(offer)) return { ok: false, reason: 'Offer already used' };
  return { ok: true };
}
export const burn = (sid, offer) => used.set(sid, (used.get(sid) || new Set()).add(offer));`,
    remediatedSnippet: `// policy.js (patched)
export const OFFERS = Object.freeze({
  __proto__: null,
  discount: { label: 'Next 3 months at 30% off ($7/mo), then $10/mo' },
  downgrade: { label: 'Switch to Basic at $5/mo' },
  pause: { label: 'Pause billing until you come back' },
});

export function check(sid, offer, { requireProposed = false } = {}) {
  if (typeof offer !== 'string' || !Object.hasOwn(OFFERS, offer)) return { ok: false, reason: 'Unknown offer' };
  if (used.get(sid)?.has(offer)) return { ok: false, reason: 'Offer already used' };
  if (requireProposed && !proposed.get(sid)?.has(offer)) return { ok: false, reason: 'Offer was not proposed' };
  return { ok: true };
}`,
    remediationSteps: [
      'Define OFFERS with __proto__: null and Object.freeze(), checking membership via Object.hasOwn(OFFERS, offer).',
      'Track proposed offers via propose(sid, offer) in /api/chat and enforce check(id, offerId, { requireProposed: true }) in /api/accept.',
      'Track pending plan revisions and finalize burn() when GET /api/subscription/:id confirms the updated plan_id.'
    ]
  },
  {
    id: 'PM-06',
    pointNumber: 6,
    title: 'Verbose Upstream Error & Exception Leakage to Client',
    severity: 'Medium',
    status: 'Fixed',
    cwe: 'CWE-209',
    owasp: 'API8:2023 Security Misconfiguration',
    affectedFiles: ['server.js', 'paypal.js', 'agent.js'],
    lineRefs: 'server.js:16, paypal.js:13, 25, agent.js:25',
    summary:
      'Fixed: Updated the Express error wrapper in server.js to log full upstream errors server-side while only returning safe messages (err.expose ? err.message : "Request failed") to clients.',
    mechanics:
      'Previously, `s.status(500).json({ error: e.message })` sent raw PayPal OAuth/REST error payloads, Anthropic billing/API errors, and filesystem ENOENT errors directly to the browser.',
    impact:
      'Eliminates leakage of sensitive upstream API responses, internal paths, and credential configuration state.',
    vulnerableSnippet: `// server.js (line 16)
const wrap = fn => (q, s) => fn(q, s).catch(e => {
  console.error(e);
  s.status(500).json({ error: e.message });
});`,
    remediatedSnippet: `// server.js (patched)
const wrap = fn => (q, s) => fn(q, s).catch(e => {
  console.error(e);
  const status = e.status || 500;
  s.status(status).json({ error: e.expose ? e.message : 'Internal server error' });
});`,
    remediationSteps: [
      'Keep full error logging on the server via console.error(e).',
      'Only expose error messages to the client when explicitly marked with expose: true (e.g. 400/429 validation errors).'
    ]
  },
  {
    id: 'PM-07',
    pointNumber: 7,
    title: 'Static Root Misconfiguration Risk, Sync File I/O & Unvalidated Redirects',
    severity: 'Medium',
    status: 'Fixed',
    cwe: 'CWE-552 / CWE-601',
    owasp: 'A05:2021 Security Misconfiguration',
    affectedFiles: ['server.js', 'public/index.html'],
    lineRefs: 'server.js:10, 12, index.html:26, 29',
    summary:
      'Fixed: Moved index.html into public/index.html, cached plans.json asynchronously instead of calling fs.readFileSync on every request, and validated PayPal redirect URLs on the client.',
    mechanics:
      '1) index.html was in the repo root while server.js served `express.static("public")`. 2) `fs.readFileSync("plans.json")` ran synchronously on every request. 3) `location = r.approveUrl` redirected without checking the URL hostname.',
    impact:
      'Prevents accidental root static exposure of server source files, removes event-loop blocking I/O, and blocks open redirects.',
    vulnerableSnippet: `// server.js (lines 10-12)
app.use(express.static('public'));
const plans = () => JSON.parse(fs.readFileSync('plans.json', 'utf8'));

// index.html (line 29)
$('sub').onclick=async()=>{const r=await post('/api/subscribe',{});location=r.approveUrl};`,
    remediatedSnippet: `// server.js (patched async cached plans loader)
let cachedPlans = null;
async function plans() {
  if (!cachedPlans) cachedPlans = JSON.parse(await fs.promises.readFile(new URL('./plans.json', import.meta.url), 'utf8'));
  return cachedPlans;
}

// public/index.html (validated PayPal redirect)
function goPayPal(u){
  try{
    const p=new URL(u);
    if(p.protocol==='https:'&&(p.hostname==='www.sandbox.paypal.com'||p.hostname==='www.paypal.com'))location.assign(p.href);
    else add('Blocked untrusted redirect URL');
  }catch{add('Invalid redirect URL');}
}`,
    remediationSteps: [
      'Move index.html into public/index.html (`mkdir -p public && git mv index.html public/index.html`).',
      'Load and cache plans.json asynchronously via fs.promises.readFile.',
      'Verify approveUrl hostname is www.sandbox.paypal.com or www.paypal.com before redirecting.'
    ]
  },
  {
    id: 'PM-08',
    pointNumber: 8,
    title: 'Tracked .env File with Missing .gitignore & Missing HTTP Security Headers',
    severity: 'Low',
    status: 'Fixed',
    cwe: 'CWE-540 / CWE-693',
    owasp: 'A05:2021 Security Misconfiguration',
    affectedFiles: ['.env.example', '.gitignore', 'server.js'],
    lineRefs: '.env:1–5, README.md:12, server.js:9',
    summary:
      'Fixed: Replaced tracked .env with .env.example, added .gitignore, bounded express.json({ limit: "16kb" }), and added security headers.',
    mechanics:
      'The repository tracked `.env` directly in Git and had no `.gitignore`, contradicting README.md (`cp .env.example .env`) and risking accidental secret commits.',
    impact:
      'Prevents developers from accidentally committing live PayPal and Anthropic secrets and hardens Express HTTP responses.',
    vulnerableSnippet: `# Tracked as /.env in git with no .gitignore
PAYPAL_CLIENT_ID=
PAYPAL_SECRET=
ANTHROPIC_API_KEY=
MODEL=claude-sonnet-5-5
BASE_URL=http://localhost:3000`,
    remediatedSnippet: `# 1. git mv .env .env.example (with MODEL=claude-sonnet-4-20250514)
# 2. Create .gitignore:
node_modules/
.env
.env.*
!.env.example
plans.json
*.log
.DS_Store`,
    remediationSteps: [
      'Run `git mv .env .env.example` and commit the new `.gitignore` file.',
      'Configure `express.json({ limit: "16kb" })` and set `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` headers.'
    ]
  },
  {
    id: 'PM-01',
    pointNumber: 1,
    title: 'Unauthenticated Endpoints & Broken Object Level Authorization (BOLA / IDOR)',
    severity: 'Critical',
    status: 'Excluded (Per Request)',
    cwe: 'CWE-306 / CWE-639',
    owasp: 'API1:2023 Broken Object Level Authorization',
    affectedFiles: ['server.js', 'public/index.html'],
    lineRefs: 'server.js:18–56',
    summary:
      'Intentionally left unchanged per your instruction ("except point 1 and 2 fix all issues") to keep the sandbox demo flow frictionless without login/session setup.',
    mechanics:
      'Endpoints accept subscriptionId directly without user authentication or session ownership binding.',
    impact:
      'Acceptable for local single-user sandbox demos; must be paired with user session authentication before production deployment.',
    vulnerableSnippet: `// Left unauthenticated for local demo simplicity per request`,
    remediatedSnippet: `// Excluded per request (Point 1)`,
    remediationSteps: [
      'Excluded per user instruction.'
    ]
  },
  {
    id: 'PM-02',
    pointNumber: 2,
    title: 'Unverified PayPal Webhook Signatures',
    severity: 'Critical',
    status: 'Excluded (Per Request)',
    cwe: 'CWE-345',
    owasp: 'API8:2023 Security Misconfiguration',
    affectedFiles: ['server.js'],
    lineRefs: 'server.js:58',
    summary:
      'Intentionally left unchanged per your instruction ("except point 1 and 2 fix all issues"), matching the note in README.md ("webhook signatures aren\'t verified yet").',
    mechanics:
      'POST /api/webhook logs the incoming event type and resource ID and returns 200 without verifying PayPal signature headers.',
    impact:
      'Acceptable while webhook handler only logs to console in sandbox; verify signatures before wiring fulfillment logic.',
    vulnerableSnippet: `app.post('/api/webhook', (q, s) => { console.log('webhook', q.body.event_type, q.body.resource?.id); s.sendStatus(200); });`,
    remediatedSnippet: `// Excluded per request (Point 2)`,
    remediationSteps: [
      'Excluded per user instruction.'
    ]
  }
];

export const REPO_FILES: RepoFileComparison[] = [
  {
    filename: 'server.js',
    role: 'Express HTTP Server (Points 4, 5, 6, 7, 8 Fixed; Points 1 & 2 Kept As-Is)',
    pointsFixed: 'Points 4, 5, 6, 7, 8',
    notes: [
      'Point 4 Fixed: Server-side chat session history (max 6 user turns, 500 chars/msg) + per-IP rate limiting on /api/chat.',
      'Point 5 Fixed: Records AI-proposed offers via propose(), enforces { requireProposed: true } on /api/accept, and defers revise offer burn until GET /api/subscription/:id confirms the plan change.',
      'Point 6 Fixed: Error wrapper logs full error server-side and only sends e.message to client when e.expose === true.',
      'Point 7 & 8 Fixed: Async cached plans.json reader, 16kb JSON body limit, and HTTP security headers (while keeping Points 1 & 2 unchanged).'
    ],
    originalCode: `import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import * as pp from './paypal.js';
import { chat } from './agent.js';
import { OFFERS, check, burn } from './policy.js';

const app = express();
app.use(express.json());
app.use(express.static('public'));

const plans = () => JSON.parse(fs.readFileSync('plans.json', 'utf8'));
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const ctx = { return_url: BASE_URL, cancel_url: BASE_URL };
const approve = o => o.links?.find(l => l.rel === 'approve')?.href;
const wrap = fn => (q, s) => fn(q, s).catch(e => { console.error(e); s.status(500).json({ error: e.message }); });

app.post('/api/subscribe', wrap(async (q, s) => {
  const sub = await pp.createSubscription(plans().standard, ctx);
  s.json({ id: sub.id, approveUrl: approve(sub) });
}));

app.get('/api/subscription/:id', wrap(async (q, s) => {
  const x = await pp.getSubscription(q.params.id);
  s.json({ status: x.status, plan_id: x.plan_id });
}));

app.post('/api/chat', wrap(async (q, s) => {
  const { subscriptionId, messages } = q.body;
  const r = await chat(messages);
  let offer = null;
  if (r.offer) {
    if (check(subscriptionId, r.offer).ok) offer = { id: r.offer, label: OFFERS[r.offer].label };
    else r.text = "I can't offer that again, but you can cancel any time with the button below.";
  }
  s.json({ text: r.text, offer });
}));

app.post('/api/accept', wrap(async (q, s) => {
  const { subscriptionId: id, offerId } = q.body;
  const v = check(id, offerId);
  if (!v.ok) return s.status(400).json({ error: v.reason });
  if (offerId === 'pause') {
    await pp.suspend(id, 'Customer accepted pause offer');
    burn(id, offerId);
    return s.json({ message: 'Billing paused.' });
  }
  const rev = await pp.revise(id, plans()[offerId === 'discount' ? 'retention' : 'basic'], ctx);
  burn(id, offerId);
  s.json({ approveUrl: approve(rev) }); // buyer must re-consent on PayPal
}));

app.post('/api/cancel', wrap(async (q, s) => {
  await pp.cancel(q.body.subscriptionId, 'Customer chose to cancel');
  s.json({ ok: true });
}));

app.post('/api/webhook', (q, s) => { console.log('webhook', q.body.event_type, q.body.resource?.id); s.sendStatus(200); });

app.listen(3000, () => console.log(\`PlanMorph on \${BASE_URL}\`));`,
    hardenedCode: `import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import * as pp from './paypal.js';
import { chat } from './agent.js';
import { OFFERS, check, propose, holdPendingRevision, syncRevisionState, burn } from './policy.js';

const app = express();
app.use(express.json({ limit: '16kb' }));
app.use((q, s, next) => {
  s.setHeader('X-Content-Type-Options', 'nosniff');
  s.setHeader('X-Frame-Options', 'DENY');
  s.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use(express.static('public', { dotfiles: 'ignore' }));

let cachedPlans = null;
async function plans() {
  if (!cachedPlans) cachedPlans = JSON.parse(await fs.promises.readFile(new URL('./plans.json', import.meta.url), 'utf8'));
  return cachedPlans;
}

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const ctx = { return_url: BASE_URL, cancel_url: BASE_URL };
const approve = o => o.links?.find(l => l.rel === 'approve')?.href;

// Safe error handler: logs full error server-side, only exposes client-safe messages
const wrap = fn => (q, s) => fn(q, s).catch(e => {
  console.error(e);
  s.status(e.status || 500).json({ error: e.expose ? e.message : 'Internal server error' });
});

// Lightweight in-memory rate limiter & server-side chat history store
const rateBuckets = new Map();
function rateLimit(maxReqs, windowMs) {
  return (q, s, next) => {
    const now = Date.now(), ip = q.ip || 'local';
    const b = rateBuckets.get(ip);
    if (!b || now > b.exp) {
      if (rateBuckets.size >= 5000) rateBuckets.clear();
      rateBuckets.set(ip, { count: 1, exp: now + windowMs });
      return next();
    }
    if (++b.count > maxReqs) return s.status(429).json({ error: 'Too many requests, please try again shortly.' });
    next();
  };
}

const chatSessions = new Map(); // subscriptionId -> [{ role, content }]
function getHistory(sid) {
  if (!chatSessions.has(sid)) {
    if (chatSessions.size >= 5000) chatSessions.delete(chatSessions.keys().next().value);
    chatSessions.set(sid, []);
  }
  return chatSessions.get(sid);
}

app.post('/api/subscribe', wrap(async (q, s) => {
  const p = await plans();
  const sub = await pp.createSubscription(p.standard, ctx);
  s.json({ id: sub.id, approveUrl: approve(sub) });
}));

app.get('/api/subscription/:id', wrap(async (q, s) => {
  const id = pp.validSubId(q.params.id);
  const x = await pp.getSubscription(id);
  syncRevisionState(id, x.plan_id);
  s.json({ status: x.status, plan_id: x.plan_id });
}));

app.post('/api/chat', rateLimit(20, 60_000), wrap(async (q, s) => {
  const subscriptionId = pp.validSubId(q.body?.subscriptionId);
  const raw = typeof q.body?.message === 'string' ? q.body.message : q.body?.messages?.at(-1)?.content;
  const userText = typeof raw === 'string' ? raw.trim() : '';
  if (!userText || userText.length > 500) {
    throw Object.assign(new Error('Message must be between 1 and 500 characters'), { status: 400, expose: true });
  }
  const history = getHistory(subscriptionId);
  if (history.length >= 12) {
    throw Object.assign(new Error('Maximum chat turns reached. You can accept an offer or cancel below.'), { status: 429, expose: true });
  }
  history.push({ role: 'user', content: userText });

  const r = await chat(history);
  let offer = null;
  if (r.offer) {
    if (check(subscriptionId, r.offer).ok) {
      propose(subscriptionId, r.offer);
      offer = { id: r.offer, label: OFFERS[r.offer].label };
    } else {
      r.text = "I can't offer that again, but you can cancel any time with the button below.";
    }
  }
  history.push({ role: 'assistant', content: r.text });
  s.json({ text: r.text, offer });
}));

app.post('/api/accept', wrap(async (q, s) => {
  const id = pp.validSubId(q.body?.subscriptionId);
  const { offerId } = q.body || {};
  const v = check(id, offerId, { requireProposed: true });
  if (!v.ok) return s.status(400).json({ error: v.reason });
  if (offerId === 'pause') {
    await pp.suspend(id, 'Customer accepted pause offer');
    burn(id, offerId);
    return s.json({ message: 'Billing paused.' });
  }
  const p = await plans();
  const targetPlan = offerId === 'discount' ? p.retention : p.basic;
  const rev = await pp.revise(id, targetPlan, ctx);
  holdPendingRevision(id, offerId, targetPlan); // finalized on return when PayPal plan_id updates
  s.json({ approveUrl: approve(rev) }); // buyer must re-consent on PayPal
}));

app.post('/api/cancel', wrap(async (q, s) => {
  const id = pp.validSubId(q.body?.subscriptionId);
  await pp.cancel(id, 'Customer chose to cancel');
  s.json({ ok: true });
}));

app.post('/api/webhook', (q, s) => { console.log('webhook', q.body.event_type, q.body.resource?.id); s.sendStatus(200); });

app.listen(3000, () => console.log(\`PlanMorph on \${BASE_URL}\`));`
  },
  {
    filename: 'paypal.js',
    role: 'PayPal Subscriptions API v1 Client (Point 3 Fixed)',
    pointsFixed: 'Point 3',
    notes: [
      'Added validSubId(id) enforcing /^I-[A-Z0-9]{10,16}$/ and encodeURIComponent(id) on all subscription endpoints.',
      'Throws client-safe 400 error if subscriptionId is malformed or contains path traversal characters.'
    ],
    originalCode: `const BASE = 'https://api-m.sandbox.paypal.com';
let tok = { v: null, exp: 0 };

async function token() {
  if (tok.v && Date.now() < tok.exp) return tok.v;
  const auth = Buffer.from(\`\${process.env.PAYPAL_CLIENT_ID}:\${process.env.PAYPAL_SECRET}\`).toString('base64');
  const r = await fetch(\`\${BASE}/v1/oauth2/token\`, {
    method: 'POST',
    headers: { Authorization: \`Basic \${auth}\`, 'Content-Type': 'application/x-www-form-urlencoded' },
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
    headers: { Authorization: \`Bearer \${await token()}\`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await r.text();
  if (!r.ok) throw new Error(\`PayPal \${method} \${path} -> \${r.status}: \${t}\`);
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
export const getSubscription = id => api('GET', \`/v1/billing/subscriptions/\${id}\`);
// Plan switches need buyer re-consent: the response contains an "approve" link.
export const revise = (id, plan_id, ctx) => api('POST', \`/v1/billing/subscriptions/\${id}/revise\`, { plan_id, application_context: ctx });
export const suspend = (id, reason) => api('POST', \`/v1/billing/subscriptions/\${id}/suspend\`, { reason });
export const cancel = (id, reason) => api('POST', \`/v1/billing/subscriptions/\${id}/cancel\`, { reason });`,
    hardenedCode: `const BASE = 'https://api-m.sandbox.paypal.com';
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
  const auth = Buffer.from(\`\${process.env.PAYPAL_CLIENT_ID}:\${process.env.PAYPAL_SECRET}\`).toString('base64');
  const r = await fetch(\`\${BASE}/v1/oauth2/token\`, {
    method: 'POST',
    headers: { Authorization: \`Basic \${auth}\`, 'Content-Type': 'application/x-www-form-urlencoded' },
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
    headers: { Authorization: \`Bearer \${await token()}\`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await r.text();
  if (!r.ok) throw new Error(\`PayPal \${method} \${path} -> \${r.status}: \${t}\`);
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
export const getSubscription = id => api('GET', \`/v1/billing/subscriptions/\${validSubId(id)}\`);
// Plan switches need buyer re-consent: the response contains an "approve" link.
export const revise = (id, plan_id, ctx) => api('POST', \`/v1/billing/subscriptions/\${validSubId(id)}/revise\`, { plan_id, application_context: ctx });
export const suspend = (id, reason) => api('POST', \`/v1/billing/subscriptions/\${validSubId(id)}/suspend\`, { reason });
export const cancel = (id, reason) => api('POST', \`/v1/billing/subscriptions/\${validSubId(id)}/cancel\`, { reason });`
  },
  {
    filename: 'policy.js',
    role: 'Retention Offer Guardrails (Point 5 Fixed)',
    pointsFixed: 'Point 5',
    notes: [
      'Uses Object.freeze({ __proto__: null, ... }) and Object.hasOwn(OFFERS, offer) to prevent Object.prototype property bypasses.',
      'Adds propose() and requireProposed validation so /api/accept only accepts offers proposed by the AI agent.',
      'Adds holdPendingRevision() and syncRevisionState() so revise offers are only burned once the buyer completes PayPal re-consent.'
    ],
    originalCode: `// Deterministic guardrails: the LLM can only pick from this catalog, and each offer is single-use.
export const OFFERS = {
  discount: { label: 'Next 3 months at 30% off ($7/mo), then $10/mo' },
  downgrade: { label: 'Switch to Basic at $5/mo' },
  pause: { label: 'Pause billing until you come back' },
};
const used = new Map(); // subscriptionId -> Set(offerId); in-memory for the demo

export function check(sid, offer) {
  if (!OFFERS[offer]) return { ok: false, reason: 'Unknown offer' };
  if (used.get(sid)?.has(offer)) return { ok: false, reason: 'Offer already used' };
  return { ok: true };
}
export const burn = (sid, offer) => used.set(sid, (used.get(sid) || new Set()).add(offer));`,
    hardenedCode: `// Deterministic guardrails: the LLM can only pick from this catalog, and each offer is single-use.
export const OFFERS = Object.freeze({
  __proto__: null,
  discount: { label: 'Next 3 months at 30% off ($7/mo), then $10/mo' },
  downgrade: { label: 'Switch to Basic at $5/mo' },
  pause: { label: 'Pause billing until you come back' },
});

const MAX_ENTRIES = 5000;
const proposed = new Map(); // subscriptionId -> Set(offerId)
const pending = new Map();  // subscriptionId -> { offerId, planId }
const used = new Map();     // subscriptionId -> Set(offerId); in-memory for the demo

function addSet(map, sid, val) {
  if (!map.has(sid) && map.size >= MAX_ENTRIES) map.delete(map.keys().next().value);
  map.set(sid, (map.get(sid) || new Set()).add(val));
}

export function check(sid, offer, { requireProposed = false } = {}) {
  if (typeof sid !== 'string' || !sid) return { ok: false, reason: 'Invalid subscriptionId' };
  if (typeof offer !== 'string' || !Object.hasOwn(OFFERS, offer)) return { ok: false, reason: 'Unknown offer' };
  if (used.get(sid)?.has(offer)) return { ok: false, reason: 'Offer already used' };
  if (requireProposed && !proposed.get(sid)?.has(offer)) return { ok: false, reason: 'Offer has not been proposed' };
  return { ok: true };
}

export const propose = (sid, offer) => {
  if (typeof sid === 'string' && sid && Object.hasOwn(OFFERS, offer)) addSet(proposed, sid, offer);
};

export const burn = (sid, offer) => addSet(used, sid, offer);

export function holdPendingRevision(sid, offerId, planId) {
  if (!pending.has(sid) && pending.size >= MAX_ENTRIES) pending.delete(pending.keys().next().value);
  pending.set(sid, { offerId, planId });
}

export function syncRevisionState(sid, activePlanId) {
  const p = pending.get(sid);
  if (!p) return;
  if (p.planId === activePlanId) burn(sid, p.offerId);
  pending.delete(sid);
}`
  },
  {
    filename: 'agent.js',
    role: 'Anthropic Messages API Client (Points 4 & 5 Fixed)',
    pointsFixed: 'Points 4, 5',
    notes: [
      'Fixes invalid default model ID from claude-sonnet-5-5 to claude-sonnet-4-20250514.',
      'Validates tool_use offer_id with Object.hasOwn(OFFERS, ...) before returning.'
    ],
    originalCode: `import { OFFERS } from './policy.js';

const SYSTEM = \`You are the retention assistant for Acme Notes (Standard plan, $10/mo). The customer wants to cancel.
If you don't know why, ask one short question. Then call propose_offer with the single best-fitting offer from:
\${Object.entries(OFFERS).map(([k, o]) => \`\${k} = \${o.label}\`).join('; ')}.
Never invent other discounts or promises. Be honest and brief. If they decline, don't push: tell them they can cancel with the button below.\`;

const tools = [{
  name: 'propose_offer',
  description: 'Present exactly one retention offer to the customer.',
  input_schema: {
    type: 'object',
    properties: { offer_id: { type: 'string', enum: Object.keys(OFFERS) }, message: { type: 'string' } },
    required: ['offer_id', 'message'],
  },
}];

export async function chat(messages) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: process.env.MODEL || 'claude-sonnet-5-5', max_tokens: 500, system: SYSTEM, tools, messages }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error('Anthropic API: ' + JSON.stringify(j));
  const call = j.content.find(b => b.type === 'tool_use');
  const text = j.content.filter(b => b.type === 'text').map(b => b.text).join('\\n');
  return { text: call?.input.message || text, offer: call?.input.offer_id };
}`,
    hardenedCode: `import { OFFERS } from './policy.js';

const SYSTEM = \`You are the retention assistant for Acme Notes (Standard plan, $10/mo). The customer wants to cancel.
If you don't know why, ask one short question. Then call propose_offer with the single best-fitting offer from:
\${Object.entries(OFFERS).map(([k, o]) => \`\${k} = \${o.label}\`).join('; ')}.
Never invent other discounts or promises. Be honest and brief. If they decline, don't push: tell them they can cancel with the button below.\`;

const tools = [{
  name: 'propose_offer',
  description: 'Present exactly one retention offer to the customer.',
  input_schema: {
    type: 'object',
    properties: { offer_id: { type: 'string', enum: Object.keys(OFFERS) }, message: { type: 'string' } },
    required: ['offer_id', 'message'],
  },
}];

export async function chat(messages) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: process.env.MODEL || 'claude-sonnet-4-20250514', max_tokens: 500, system: SYSTEM, tools, messages }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error('Anthropic API: ' + JSON.stringify(j));
  const call = j.content?.find(b => b.type === 'tool_use' && b.name === 'propose_offer');
  const text = (j.content || []).filter(b => b.type === 'text').map(b => b.text).join('\\n');
  const offerId = call?.input?.offer_id;
  const offer = typeof offerId === 'string' && Object.hasOwn(OFFERS, offerId) ? offerId : undefined;
  return { text: call?.input?.message || text, offer };
}`
  },
  {
    filename: 'public/index.html',
    role: 'Frontend Client moved to public/index.html (Points 4 & 7 Fixed)',
    pointsFixed: 'Points 4, 7',
    notes: [
      'Moved from /index.html to /public/index.html so express.static("public") serves it properly.',
      'Validates approveUrl hostname (www.sandbox.paypal.com or www.paypal.com) via goPayPal() before redirecting.',
      'Sends only the latest user message ({ subscriptionId, message }) with maxlength="500" instead of client-controlled conversation arrays.'
    ],
    originalCode: `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>PlanMorph demo</title>
<style>body{font:16px system-ui;max-width:560px;margin:2rem auto;padding:0 1rem}button{padding:.5rem 1rem;margin:.25rem 0}#log div{margin:.5rem 0;padding:.5rem .75rem;border-radius:8px;background:#eee}#log .me{background:#dbeafe}#log .ok{background:#dcfce7}input{width:65%;padding:.5rem}</style>
<h1>Acme Notes</h1><p id=status>Not subscribed.</p>
<button id=sub>Subscribe, $10/mo (PayPal sandbox)</button> <button id=cancel hidden>Cancel subscription</button>
<div id=chat hidden><div id=log></div><input id=msg placeholder="Reply…"> <button id=send>Send</button> <button id=cancelNow>Cancel anyway</button></div>
<script>
const $=id=>document.getElementById(id);
let sid=new URLSearchParams(location.search).get('subscription_id')||localStorage.sid, msgs=[];
if(sid){localStorage.sid=sid;history.replaceState({},'','/');}
const post=(u,b)=>fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
const add=(t,c)=>{const d=document.createElement('div');d.className=c||'';d.textContent=t;$('log').append(d)};
async function refresh(){
  if(!sid)return;
  const s=await fetch('/api/subscription/'+sid).then(r=>r.json());
  $('status').textContent=\`Subscription \${sid}: \${s.status} (\${s.plan_id})\`;
  $('sub').hidden=true;$('cancel').hidden=s.status!=='ACTIVE';
}
async function talk(text){
  msgs.push({role:'user',content:text});add(text,'me');
  const r=await post('/api/chat',{subscriptionId:sid,messages:msgs});
  if(r.error)return add(r.error);
  msgs.push({role:'assistant',content:r.text});add(r.text);
  if(r.offer){const b=document.createElement('button');b.textContent='Accept: '+r.offer.label;
    b.onclick=async()=>{const a=await post('/api/accept',{subscriptionId:sid,offerId:r.offer.id});
      if(a.approveUrl)location=a.approveUrl;else{add(a.message||a.error,'ok');refresh();}};
    $('log').append(b);}
}
$('sub').onclick=async()=>{const r=await post('/api/subscribe',{});location=r.approveUrl};
$('cancel').onclick=()=>{$('chat').hidden=false;talk('I want to cancel my subscription.')};
$('send').onclick=()=>{const t=$('msg').value.trim();if(t){$('msg').value='';talk(t)}};
$('cancelNow').onclick=async()=>{await post('/api/cancel',{subscriptionId:sid});add('Subscription cancelled.','ok');refresh()};
refresh();
</script>`,
    hardenedCode: `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>PlanMorph demo</title>
<style>body{font:16px system-ui;max-width:560px;margin:2rem auto;padding:0 1rem}button{padding:.5rem 1rem;margin:.25rem 0}#log div{margin:.5rem 0;padding:.5rem .75rem;border-radius:8px;background:#eee}#log .me{background:#dbeafe}#log .ok{background:#dcfce7}input{width:65%;padding:.5rem}</style>
<h1>Acme Notes</h1><p id=status>Not subscribed.</p>
<button id=sub>Subscribe, $10/mo (PayPal sandbox)</button> <button id=cancel hidden>Cancel subscription</button>
<div id=chat hidden><div id=log></div><input id=msg placeholder="Reply…" maxlength="500"> <button id=send>Send</button> <button id=cancelNow>Cancel anyway</button></div>
<script>
const $=id=>document.getElementById(id);
let sid=new URLSearchParams(location.search).get('subscription_id')||localStorage.sid;
if(sid){localStorage.sid=sid;history.replaceState({},'','/');}
const post=(u,b)=>fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
const add=(t,c)=>{const d=document.createElement('div');d.className=c||'';d.textContent=t;$('log').append(d)};
function goPayPal(u){
  try{
    const p=new URL(u);
    if(p.protocol==='https:'&&(p.hostname==='www.sandbox.paypal.com'||p.hostname==='www.paypal.com'))location.assign(p.href);
    else add('Blocked untrusted redirect URL');
  }catch{add('Invalid redirect URL');}
}
async function refresh(){
  if(!sid)return;
  const s=await fetch('/api/subscription/'+encodeURIComponent(sid)).then(r=>r.json());
  if(s.error)return add(s.error);
  $('status').textContent=\`Subscription \${sid}: \${s.status} (\${s.plan_id})\`;
  $('sub').hidden=true;$('cancel').hidden=s.status!=='ACTIVE';
}
async function talk(text){
  add(text,'me');
  const r=await post('/api/chat',{subscriptionId:sid,message:text});
  if(r.error)return add(r.error);
  add(r.text);
  if(r.offer){const b=document.createElement('button');b.textContent='Accept: '+r.offer.label;
    b.onclick=async()=>{const a=await post('/api/accept',{subscriptionId:sid,offerId:r.offer.id});
      if(a.approveUrl)goPayPal(a.approveUrl);else{add(a.message||a.error,'ok');refresh();}};
    $('log').append(b);}
}
$('sub').onclick=async()=>{const r=await post('/api/subscribe',{});if(r.approveUrl)goPayPal(r.approveUrl);else if(r.error)add(r.error)};
$('cancel').onclick=()=>{$('chat').hidden=false;talk('I want to cancel my subscription.')};
$('send').onclick=()=>{const t=$('msg').value.trim();if(t){$('msg').value='';talk(t)}};
$('cancelNow').onclick=async()=>{await post('/api/cancel',{subscriptionId:sid});add('Subscription cancelled.','ok');refresh()};
refresh();
</script>`
  },
  {
    filename: '.env.example & .gitignore',
    role: 'Environment Template & Git Ignore Rules (Points 4 & 8 Fixed)',
    pointsFixed: 'Points 4, 8',
    notes: [
      'Renames tracked .env to .env.example (`git mv .env .env.example`) and updates MODEL to claude-sonnet-4-20250514.',
      'Adds .gitignore so local .env secrets, node_modules/, and plans.json are never committed to Git.'
    ],
    originalCode: `# Previously committed as /.env (with no .gitignore in repo)
PAYPAL_CLIENT_ID=
PAYPAL_SECRET=
ANTHROPIC_API_KEY=
MODEL=claude-sonnet-5-5
BASE_URL=http://localhost:3000`,
    hardenedCode: `# === File 1: .env.example (run: git mv .env .env.example) ===
PAYPAL_CLIENT_ID=
PAYPAL_SECRET=
ANTHROPIC_API_KEY=
MODEL=claude-sonnet-4-20250514
BASE_URL=http://localhost:3000

# === File 2: .gitignore ===
node_modules/
.env
.env.*
!.env.example
plans.json
*.log
.DS_Store`
  }
];
