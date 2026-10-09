import 'dotenv/config';
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

// Final error handler: body-parser failures (malformed JSON, >16kb) never reach wrap(); without this Express sends an HTML stack trace.
app.use((err, q, s, next) => {
  if (s.headersSent) return next(err);
  console.error(err);
  const status = err.status === 413 ? 413 : err.status >= 400 && err.status < 500 ? 400 : 500;
  s.status(status).json({ error: status === 413 ? 'Request body too large' : status === 400 ? 'Invalid request' : 'Internal server error' });
});

app.listen(3000, () => console.log(`PlanMorph on ${BASE_URL}`));
