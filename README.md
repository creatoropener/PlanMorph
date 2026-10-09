# PlanMorph

An AI retention agent for PayPal Subscriptions. When a subscriber clicks **Cancel**, the agent finds out why, proposes one offer (30% off for 3 months, downgrade, or pause), and on acceptance changes the live subscription through the PayPal Subscriptions API v1, with no re-signup. Same subscription ID throughout.

## How it works
- **AI:** Claude (Anthropic Messages API) with tool calling. The model can only call `propose_offer` with an ID from a fixed catalog.
- **Guardrails:** `policy.js` validates every offer server-side (known catalog only, single use per subscription). The LLM never touches PayPal directly.
- **PayPal (sandbox):** create product and plans, create subscription, `revise` (plan switch, needs buyer re-consent), `suspend`, `cancel`, webhook endpoint.

## Run it
1. Create a PayPal sandbox REST app (developer.paypal.com) and get a sandbox buyer account.
2. `cp .env.example .env` and fill in `PAYPAL_CLIENT_ID`, `PAYPAL_SECRET`, `ANTHROPIC_API_KEY`.
3. `npm install && npm run setup` (creates the product and plans, writes `plans.json`)
4. `npm start`, open http://localhost:3000, subscribe with the sandbox buyer, then click Cancel.

## Known limits
Offer usage is in-memory; webhook signatures aren't verified yet; plan changes require the buyer to approve on PayPal (by design of the API).

MIT licensed.
