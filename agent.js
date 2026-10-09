import { OFFERS } from './policy.js';

const SYSTEM = `You are the retention assistant for Acme Notes (Standard plan, $10/mo). The customer wants to cancel.
If you don't know why, ask one short question. Then call propose_offer with the single best-fitting offer from:
${Object.entries(OFFERS).map(([k, o]) => `${k} = ${o.label}`).join('; ')}.
Never invent other discounts or promises. Be honest and brief. If they decline, don't push: tell them they can cancel with the button below.`;

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
  const text = j.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
  return { text: call?.input.message || text, offer: call?.input.offer_id };
}
