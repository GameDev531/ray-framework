---
name: ray-vantage
description: >-
  Verifies a web app from the real user's vantage: it drives an actual browser like a person would, proving every backend capability is reachable and works through the UI, closing front-to-back coherence gaps (a backend feature with no button, a button wired to nothing), and confirming the security fixes the other Ray stages made actually hold when the app is operated by hand. Dispatches the ray-usher browser subagent.
  Use after an app is built (especially AI-built) and you need to know it actually WORKS end-to-end for a user — not just that the code and design exist — or to re-verify siege/domain fixes through the running UI. Works against a local dev server or a URL you control.
  Don't use for static code review (ray-loupe), for finding new security holes (the domain suite / ray-siege), or against a site you don't own.
---

# Vantage (/ray-vantage)

## Authorized use

`ray-vantage` operates an app **you own** — a local dev server or a URL you
control — the way a normal user does: it opens pages, clicks buttons, fills forms,
and reads results. That is ordinary product QA, not an attack. It drives a **real
browser** (the pre-installed Chromium) against your own running app to prove it
works; it does not target third-party systems.

## System Goal

**Real-User Product Verifier.** An app can pass every static check and still be
**broken for a user**: the backend has a `/scan` endpoint but the frontend has no
scanner button, so nobody can scan; a button exists but calls nothing; a form
submits but the result never renders. Code and design can both be present and the
product still not *work*. This stage is the missing eyes-and-hands pass — it drives
the running app like a person and returns a verdict grounded in what actually
happened on screen, plus the fixes that make the app coherent.

It answers three questions, in order:

1. **Coherence** — does every backend capability have a working path in the UI, and
   does every UI affordance actually do something? (The "scanner button" problem.)
2. **It works** — can a real user complete the core flows, end to end, without
   dead ends, console errors, or failed requests?
3. **Security holds from the user's seat** — do the fixes the other Ray stages made
   actually stop the attack when the app is driven by hand (the IDOR really 403s,
   the XSS payload really renders inert)?

## Command Definition

- **Command:** `/ray-vantage`
- **Description:** Drives a real browser against your running app to prove
  front-to-back coherence, complete the core user flows, and re-verify security
  fixes — returning a 1–5 verdict with screenshot/console evidence, a
  capability↔affordance matrix, and the frontend wiring fixes for any gaps.
- **Arguments:**
  - **Target** (required) — a URL or local dev server (`localhost:5173`, `:3000`).
    If absent, ask before doing anything else.
  - **Flows** (optional) — what to exercise ("the scan flow", "signup + login").
    If omitted, test the most obvious happy paths and say which.
  - `--fix` (optional) — apply the frontend wiring fixes for coherence gaps found
    (default: report them; only write with this flag or explicit user go-ahead).
  - `--verify-findings <path>` (optional) — re-verify the siege/domain findings at
    this path through the running UI.

## Input/Output Contract

- **Reads**: the target app (running); its source (to build the capability↔
  affordance matrix and to write wiring fixes); optionally `workspace/findings/*`
  or a siege ledger to re-verify; this skill's `references/*.md`.
- **Writes**: the QA verdict + evidence to `workspace/vantage/` (STATE-RELATIVE);
  with `--fix`, minimal frontend wiring changes in the repo (one coherent commit
  per gap); screenshots under `workspace/vantage/evidence/`.
- **Never**: attacks a non-local/third-party target; changes backend behavior to
  "make a test pass"; fixes a *security* regression itself (it reports those and
  routes them to `ray-siege`/the domain skill).

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/browser_ops.md` | before driving the browser | How to drive the pre-installed Chromium (agent-browser CLI, or Playwright/CDP) in this environment; the field-tested gotchas (host-header, per-tab interstitial, DOM-coordinate clicks, clear-before-type, draining console/network events for non-visual failures); when a tunnel is and isn't needed; teardown |
| `references/coherence_and_qa.md` | at the matrix step and again at scoring | The capability↔affordance matrix method and the three gap types; the "scanner button" worked example; the idiomatic frontend wiring-fix pattern; the 1–5 rubric; the per-class security-hold re-verification; the output format |

## Instructions

### Step 0 — Confirm the target and reachability
Confirm the target is reachable (`curl -s -o /dev/null -w "%{http_code}"`), and
identify what the app is (title, README, framework) so you can frame sensible
flows. Local dev server not running? Detect the run mechanism (reuse
`ray-siege/references/siege_protocol.md` §2's detection) and start it, or ask the
user how.

### Step 1 — Build the capability↔affordance matrix
Per `coherence_and_qa.md`: inventory **backend capabilities** (route/handler
definitions) and **frontend affordances** (buttons, forms, links, the fetch/axios
calls behind them). Diff them into the three gap types — **missing affordance**
(backend feature, no UI), **dead affordance** (UI element, no wiring), **broken
wiring** (wired but fails). This is the coherence baseline the browser pass
confirms.

### Step 2 — Drive the app like a user (dispatch ray-usher)
Set up the real browser (`browser_ops.md`). Dispatch **ray-usher** for each flow
(or drive directly for a single flow): open the page, act as a user, screenshot
after every meaningful action, and **drain console/network events** so failures a
screenshot won't show are caught. Each flow returns a 1–5 with evidence and the
coherence observations (did the scanner button exist? did it call the API? did the
result render?).

### Step 3 — Close coherence gaps (with `--fix` or go-ahead)
For each gap, apply the **minimal idiomatic frontend wiring** (`coherence_and_qa.md`):
add the missing affordance, wire it to the **existing** backend endpoint, render
the result, handle loading/error states — in the app's own framework and style. Do
**not** invent new backend features; you are connecting the UI to capability that
already exists. Re-drive the flow to confirm the fix works on screen. One coherent
commit per gap.

### Step 4 — Re-verify security holds from the user's seat
If given findings (`--verify-findings`), re-drive each through the running UI per
`coherence_and_qa.md`'s security-hold table: as user A, actually try to open user
B's resource; submit the stored-XSS payload and watch it render inert; hit the
protected route unauthenticated. A fix that holds is confirmed with evidence; a fix
that **doesn't** hold is reported as a regression and routed back to
`ray-siege`/`ray-bulwark` — you do not patch security here.

### Step 5 — Verdict
Return per-flow `Score: N/5` and an **overall that reflects the weakest critical
path** (never average a broken flow up), the capability↔affordance matrix with each
gap's status (found / fixed / reported), the security-hold results, and the
evidence paths. Do not print raw screenshots into chat — reference their paths.

### Step 6 — Teardown
Stop the browser and anything you started (a tunnel, a dev server you launched).
Leave the working tree clean except the wiring fixes you committed.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Does the built app actually work for a user; front-to-back coherence; wiring fixes | `/ray-vantage` (this skill) |
| Static code review of a change | `/ray-loupe` |
| Finding new security vulnerabilities (static) | the domain suite (`ray-crucible`, `ray-turnstile`, …) |
| Breaking in for real + patching (live) | `/ray-siege` (agents ray-reaver / ray-bulwark) |
| Fixing a security regression this stage surfaced | back to `/ray-siege` / `/ray-bulwark` |
| Accessibility / performance / SEO quality | out of scope here (dedicated tools) |

`ray-vantage` verifies **product coherence and that fixes hold in the UI**;
`ray-siege` proves and fixes the vulnerabilities themselves. They meet on the
security-hold re-verification: vantage confirms from the user's seat what siege
fixed in the code.
