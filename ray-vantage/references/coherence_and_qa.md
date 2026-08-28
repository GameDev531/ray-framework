# Coherence & QA — the matrix, the fixes, the verdict

The method behind `ray-vantage`: how to find where the app doesn't actually work
for a user, how to close the front-to-back gaps, how to score it, and how to
confirm the security fixes hold from the user's seat. (Rubric and output format
adapted from the `web-quality-skills` QA methodology — see `CREDITS.md`.)

## Table of Contents

- [1. The capability ↔ affordance matrix](#1-the-capability--affordance-matrix)
- [2. The three coherence gaps (with the scanner example)](#2-the-three-coherence-gaps-with-the-scanner-example)
- [3. Fixing the wiring (frontend only, minimal, idiomatic)](#3-fixing-the-wiring-frontend-only-minimal-idiomatic)
- [4. The QA rubric (1–5)](#4-the-qa-rubric-15)
- [5. Security-hold re-verification (report-only)](#5-security-hold-re-verification-report-only)
- [6. Output format](#6-output-format)

______________________________________________________________________

## 1. The capability ↔ affordance matrix

Coherence is provable, not a vibe. Build two inventories and diff them.

**Backend capabilities** — every user-facing thing the server can do. Grep the
route/handler definitions for the stack:

```
# examples — match to the framework in use
@app.route|@router.(get|post|put|delete)|app.(get|post)\(|fastapi|blueprint   # py/node
def (get|post|create|update|delete)_|urlpatterns|path\(                         # django
Controller|@(Get|Post)Mapping|@RequestMapping                                   # spring
resources :|namespace|get '|post '                                              # rails
```
Record each as `METHOD /path → what the user gets` (e.g. `POST /api/scan → run a
scan, return results`).

**Frontend affordances** — every way the UI lets a user trigger something, plus the
call behind it:

```
<button|<a |<form|onClick|onSubmit|role="button"|to=|href=          # the control
fetch\(|axios\.|useMutation|useQuery|\$\.ajax|XMLHttpRequest|api\.   # the call it makes
```
Record each as `affordance → endpoint it calls (or none)`.

**Diff → the matrix.** For every backend capability, is there an affordance that
reaches it? For every affordance, does it call a real endpoint that exists? Each
row lands in one of: **OK**, or one of the three gaps below.

______________________________________________________________________

## 2. The three coherence gaps (with the scanner example)

| Gap | Definition | Symptom in the browser |
|---|---|---|
| **Missing affordance** | A backend capability with **no UI path** — the feature exists but a user can't trigger it | The `/api/scan` endpoint works via curl, but there is **no scanner button anywhere** — the user literally cannot scan |
| **Dead affordance** | A UI element wired to **nothing** — a button/link/form that fires no request (or hits a route that doesn't exist) | The Scan button is on screen, but clicking it drains **no network event** — nothing happens |
| **Broken wiring** | Wired, but it **fails** — wrong method/URL/shape, or the response is never rendered | Click Scan → `POST /api/scan` returns 200, but the result list never appears (the response is fetched and dropped) |

**The worked example (the reason this stage exists).** An AI builds a scanner
platform: the backend has `POST /api/scan`, the design has a nice dashboard — but
**no scan button**. Statically, "the code exists and the design exists," so every
other check passes. Yet the product is unusable: there is no way for a person to
run a scan. That is a **missing-affordance** gap, and only driving the app as a
user (or building the matrix) reveals it. The fix is to add the button and wire it
to the endpoint that already exists (§3).

______________________________________________________________________

## 3. Fixing the wiring (frontend only, minimal, idiomatic)

You are **connecting the UI to backend capability that already exists** — not
inventing features, not changing backend behavior. The fix is bounded:

1. **Add the affordance** in the app's own framework and design system — a button/
   form/link that matches the existing components (reuse the app's button
   component, spacing, and styles; don't bolt on foreign markup).
2. **Wire it to the real endpoint** — the same METHOD/path/payload shape the
   backend expects (read the handler to get the contract right), through the app's
   existing data layer (its `api` client / `fetch` wrapper / query hook), not a
   bespoke call.
3. **Render the result** — show the response where a user expects it, and handle
   the **loading** and **error** states (a spinner while `/api/scan` runs; a
   readable message on failure). A feature that works only on the happy path is a 3,
   not a 5.
4. **Re-drive the flow** (`browser_ops.md`) and confirm on screen: the button
   exists, clicking it fires the request, and the result renders. Evidence before
   and after.

One coherent commit per gap, message naming the capability wired (e.g.
`feat(ui): wire Scan button to POST /api/scan and render results`). If closing a
gap would require a backend change or a new feature decision, **stop and report it**
— that is a product decision for the user, not a silent wiring fix.

______________________________________________________________________

## 4. The QA rubric (1–5)

Anchor the score to **task completion first**, then modify for errors and polish.
Looks never rescue a broken flow.

| Score | Meaning |
|---|---|
| **5** | Task completes flawlessly. No errors, no friction, responsive and polished. |
| **4** | Completes. Minor cosmetic/UX nits (slow load, one console warning) — nothing blocking. |
| **3** | Completes with real friction — a confusing step, a workaround, a non-blocking error, a rough edge. Usable, not good. |
| **2** | Only partially works. A significant bug blocks part of the flow, or success needs retries/luck. |
| **1** | Cannot be completed. Dead button, hard crash, infinite spinner, won't load, data lost. |

"It worked but threw three console errors" is a 3–4, not a 5. "Beautiful but the
submit button does nothing" is a **1**, not a 4. For several sub-tasks, score each,
then report an overall that reflects the **weakest critical path** — never average a
broken flow up because the homepage was nice.

______________________________________________________________________

## 5. Security-hold re-verification (report-only)

When handed the siege/domain findings, re-drive each **through the running UI** to
confirm the fix holds for a real user. You **verify and report**; you never patch a
security regression here (route it to `ray-siege`/`ray-bulwark`).

| Fixed class | Re-verify from the user's seat | Holds if… |
|---|---|---|
| **IDOR / BOLA** | Logged in as user A, navigate/enter user B's resource id in the real URL or UI | A gets `403/404`/redirect, never B's data |
| **Auth bypass** | Hit a protected route with no session / an expired one, in the browser | Bounced to login, not served |
| **Stored/reflected XSS** | Submit the unique inert marker payload through the actual form, reload, view it | The marker renders as **text**, no script executes (watch `drain_events` for no injected execution) |
| **CSRF** | Trigger the state-changing action without the token / cross-origin | Rejected |
| **Price/qty tampering** | Complete the flow with the tampered client value the finding used | Server recomputes; tampered value not honored |
| **Access control (BFLA)** | As a low-privilege user, try the admin action's UI path | Hidden and refused server-side |

A hold is confirmed with a screenshot + the network response. A **failure** (the
attack still works from the UI) is a regression — report it with evidence and route
it back; do not mark it fixed and do not fix it here.

______________________________________________________________________

## 6. Output format

Lead with the number; keep it skimmable and defensible.

```
Score: 3/5   (overall — weakest critical path: the Scan flow)

Coherence matrix:
  POST /api/scan        → [FIXED]    added Scan button + result list (was: missing affordance)
  GET  /api/history     → OK         History tab wired and rendering
  POST /api/export      → [REPORTED] no export UI; needs a product decision (not wired)
  "Refresh" button      → [FIXED]    was dead (no handler); wired to GET /api/status

Flows:
  Scan flow      Score: 4/5  — works after the wiring fix; ~4s run with a spinner now.
  Signup         Score: 2/5  — "email in use" renders as raw [object Object] on retry.

Security holds (re-verified in the UI):
  IDOR /invoices/:id   HOLDS ✓   as user A, /invoices/<B> → 403 (evidence 07.png)
  Stored XSS (comments) HOLDS ✓   marker rendered as text, no execution (08.png)

Issues:
  - [blocker] no —  signup error object not stringified (signup-03.png)
  - [console]       TypeError in analytics.js on every page (Runtime.exceptionThrown)

Evidence: workspace/vantage/evidence/scan-01..09.png
```

Keep it honest and specific — "the Scan button did nothing and logged a 500" beats
"scanning is broken." Cite screenshots and the actual error/network text so the
score and every matrix verdict are defensible.
