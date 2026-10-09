import 'dotenv/config';
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

app.listen(3000, () => console.log(`PlanMorph on ${BASE_URL}`));
