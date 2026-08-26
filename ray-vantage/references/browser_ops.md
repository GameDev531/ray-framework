# Browser Ops — driving a real browser in this environment

How `ray-usher` actually operates a browser to test the app like a user. The
verdict is only as trustworthy as the driving, so this docket is the field manual:
the driver to use here, the gotchas that bite once, and the teardown. (Adapted from
the Apache/MIT-licensed `web-quality-skills` QA methodology and the `agent-browser`
/ `browser-use` tooling — see `CREDITS.md`.)

## Table of Contents

- [1. The driver — local Chromium first](#1-the-driver--local-chromium-first)
- [2. Reachability: usually no tunnel](#2-reachability-usually-no-tunnel)
- [3. Drive like a user](#3-drive-like-a-user)
- [4. Catch the failures a screenshot won't show](#4-catch-the-failures-a-screenshot-wont-show)
- [5. Field gotchas (don't relearn these live)](#5-field-gotchas-dont-relearn-these-live)
- [6. Teardown](#6-teardown)

______________________________________________________________________

## 1. The driver — local Chromium first

This environment ships **Chromium pre-installed** with Playwright configured
(`PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`; `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`).
**Do not run `playwright install`.** Use, in order of preference:

1. **`agent-browser` CLI** (recommended when present) — a fast CDP driver with
   **accessibility-tree snapshots** and compact `@eN` element refs, which make
   clicks reliable (you target a semantic ref, not a pixel). It is the same tool
   the reference QA skills use. Discover its workflow from the CLI itself — it
   serves version-matched docs:
   ```bash
   command -v agent-browser && agent-browser skills get core
   ```
   If absent and installable: `npm i -g agent-browser && agent-browser install`.
   For exploratory bug-hunting it has `agent-browser skills get dogfood`.
2. **Playwright driving the pre-installed Chromium** (always-available fallback) —
   launch headless with `executablePath: '/opt/pw-browsers/chromium'` (or let
   Playwright find it). This is the same browser `ray-siege` uses for XSS/DOM
   proofs, so it is guaranteed here.
3. **Raw CDP / `chromium --headless --remote-debugging-port`** — last resort.

Prefer the accessibility-tree/`@eN` approach (driver 1) over screenshot-pixel
clicking wherever available; it is the single biggest reliability win.

A **cloud browser** (Browser Use, per the reference skill) is an option for scale
or a public URL, but it costs credits and needs a tunnel for localhost — **not the
default here**, because a local Chromium reaches `localhost` directly and for free.

## 2. Reachability: usually no tunnel

A **local** browser reaches a **local** dev server directly — so against
`localhost:PORT` you normally **do not tunnel**. (This is the opposite of the
cloud-browser QA path, where a tunnel is mandatory because the cloud browser can't
see localhost.) Only reach for a tunnel (`cloudflared tunnel --url
http://localhost:PORT` — no account, no interstitial; or `ngrok http PORT
--host-header=rewrite`) if you deliberately drive a *remote/cloud* browser. If you
do tunnel, §5's host-header and interstitial gotchas apply.

## 3. Drive like a user

1. **Restate the goal as a concrete user task** with a clear success condition
   ("click Scan → a result list renders", not "test scanning").
2. **Open → wait for load → snapshot.** Then click/type your way through, and
   **screenshot (or re-snapshot the a11y tree) after every meaningful action** —
   verify the page actually changed the way you expected; never assume a click
   worked.
3. **Probe one step past the happy path** per flow: an empty required field, an
   invalid email, the back button. Good products handle these; broken ones leak a
   stack trace or silently no-op.
4. **Two reliability rules** when clicking by coordinate: click from **DOM
   coordinates** (`getBoundingClientRect()`), never scaled-screenshot pixels (a
   downscaled shot no longer maps 1:1, so clicks miss); and **clear an input before
   typing** (select-all + delete) or typing into a filled field concatenates and
   produces doubled values that look like an app bug but are your own artifact.

## 4. Catch the failures a screenshot won't show

A page that *looks* fine can be throwing on every click. After each step, drain the
browser's console and network events and scan for:

- **JS exceptions** — `Runtime.exceptionThrown`.
- **Console errors** — `Runtime.consoleAPICalled` with `type == "error"`.
- **Failed requests** — `Network.responseReceived` with status ≥ 400, or
  `Network.loadingFailed`.

This is also how you prove **wiring**: click the button and confirm a request
actually went to the backend endpoint (and came back 2xx with the expected body).
No request on click = a **dead affordance** (`coherence_and_qa.md`), even if the
button "looks" active. Capture the network entry as evidence.

## 5. Field gotchas (don't relearn these live)

- **Dev-server host check (only if tunneling).** Vite/Next/webpack reject an
  unknown `Host` with `403 Blocked request / host not allowed` — tunnel with
  `--host-header=rewrite`. Not an issue for a direct local browser.
- **Per-tab interstitial (only if tunneling via ngrok free).** The skip header is
  per-target; a new tab the app opens (`target=_blank`, OAuth popup, `window.open`)
  starts without it. Re-apply it per new tab, or use cloudflared (no interstitial).
- **CORS/localhost-pinned APIs through a tunnel** are a tunnel artifact, not an app
  bug — don't score them against the app; prefer a local browser to avoid the whole
  class.
- **Dev instance points at a staging backend.** A `.env` may aim the dev server at a
  test backend, so a 401/legit upstream error is not the app's fault — confirm which
  backend the instance targets before scoring an auth failure as a bug.
- **Latency of a remote/cloud browser** adds round-trips; don't score raw load time
  harshly on that path.

## 6. Teardown

Stop **everything you started**, on every path: the browser/daemon (`agent-browser`
session, Playwright context, or `stop_remote_daemon(name)` for a cloud browser you
started), any tunnel process, and any dev server *you* launched (leave one the user
already had running). Only touch resources you created. Leave the working tree
clean except the wiring fixes you deliberately committed.
