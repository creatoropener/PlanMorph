# Apply to your repo (from the repo root)

    git rm --cached .env            # stop tracking .env (your local copy stays; the committed values were empty, so nothing to rotate)
    mkdir -p public && git mv index.html public/index.html
    # copy over from this folder: server.js paypal.js policy.js agent.js .env.example .gitignore  and  public/index.html
    npm install && npm run setup && npm start
    git add -A && git commit -m "Apply security audit fixes (PM-03..PM-08) + follow-ups"

Follow-ups beyond the audit workbench's patches:
1. server.js: final error middleware so malformed JSON / >16kb bodies return JSON instead of an HTML stack trace with file paths.
2. policy.js: keep a pending plan revision until PayPal reports the new plan_id (24h TTL) instead of dropping it on the first non-matching poll.
3. agent.js / .env.example: default MODEL stays claude-sonnet-5-5 (a valid model ID).
Still open by design: PM-01 (no auth on endpoints) and PM-02 (webhook signatures unverified).
