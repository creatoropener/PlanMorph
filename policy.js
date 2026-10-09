// Deterministic guardrails: the LLM can only pick from this catalog, and each offer is single-use.
export const OFFERS = Object.freeze({
  __proto__: null,
  discount: { label: 'Next 3 months at 30% off ($7/mo), then $10/mo' },
  downgrade: { label: 'Switch to Basic at $5/mo' },
  pause: { label: 'Pause billing until you come back' },
});

const MAX_ENTRIES = 5000;
const PENDING_TTL_MS = 24 * 60 * 60 * 1000;
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
  pending.set(sid, { offerId, planId, at: Date.now() });
}

export function syncRevisionState(sid, activePlanId) {
  const p = pending.get(sid);
  if (!p) return;
  if (p.planId === activePlanId) { burn(sid, p.offerId); pending.delete(sid); }
  else if (Date.now() - p.at > PENDING_TTL_MS) pending.delete(sid); // buyer never approved
}
