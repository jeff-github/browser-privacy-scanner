# Browser Privacy Scanner

Heuristic checks for potential sensitive-data exposure in browser storage, cookies,
URLs, DOM text, cache keys, IndexedDB names and observed fetch/XHR responses.
A Playwright wrapper writes JSON evidence and optionally fails on findings.

## Setup (Node.js 22+)
```powershell
npm ci
npx playwright install chromium
$env:TARGET_URL="http://localhost:3000"
npm test
```
Optional `LOGIN_EMAIL` / `LOGIN_PASSWORD` support a generic login flow; adapt selectors.
Set `PHI_FAIL_ON_FINDINGS=false` for exploratory reporting. For manual use, paste
`browser_phi_scanner_v2.js` into DevTools on an authorized test site and inspect
`window.__PHI_SCAN_RESULTS__`.

## Limits
Keyword matches require human review and do not establish PHI exposure or compliance.
Hooks observe traffic after injection. Results are page-local; the wrapper may follow
a link, so review navigation for your target. Evidence includes matched values and
must be treated as sensitive. Use synthetic data. CI validates syntax, not live sites.

## Status
Public portfolio edition of existing project code. Original credentials, captured
run data, and environment defaults are excluded. See the limitations above.
