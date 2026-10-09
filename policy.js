// Deterministic guardrails: the LLM can only pick from this catalog, and each offer is single-use.
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
export const burn = (sid, offer) => used.set(sid, (used.get(sid) || new Set()).add(offer));
