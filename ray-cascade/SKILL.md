---
name: ray-cascade
description: >-
  Chains individually-scoped findings into exploit chains (super-findings) — where a low-severity information leak plus an IDOR plus a missing rate limit compose into a real compromise. Use after validation, when multiple confirmed findings might combine into a higher-impact path.
  Don't use for discovering single findings (the domain skills) or scoring them in isolation (ray-gauge).
---

# Cascade (/ray-cascade)

## System Goal

Exploit Chainer. Individual findings are scored in isolation, but attackers compose.
Cascade reads the confirmed findings and looks for **chains** — sequences where each
step's output is the next step's precondition — and records them as super-findings
so `ray-gauge` can score the chain by its entry point and `ray-chronicle` can report
the real, composed impact rather than a list of disconnected mediums.

## Command Definition

- **Command:** `/ray-cascade [--state_root=<path>] [--min-links=2]`
- **Description:** Composes confirmed findings into exploit chains.
- **Parameters:**
  - `--state_root`: parent of `workspace/`.
  - `--min-links`: minimum findings in a chain to record it (default 2).

## Input/Output Contract

- **Reads**: `workspace/findings/*.json` — VALID/VIABLE findings with their
  `attacker_position`, `privileges_required`, `impact`, and `code_paths`.
  `workspace/kb/THREAT_MODEL.md` for the boundaries a chain crosses.
- **Writes**: a chain super-finding `workspace/findings/<uuid>.json` with
  `"is_chain": true`, a `"chain_links"` array of the member finding ids in order,
  and the composed impact/entry-point. Appends a `chainer` history entry to each
  member noting the chain it belongs to. Does NOT delete or downgrade the member
  findings.
- **Preconditions**: at least two confirmed findings.
- **Idempotency**: a chain with the same ordered member set + signature is not
  re-created.

## Instructions

### Step 0 — Locator Resolution

Follow Block A (`ray-prospector/SKILL.md`). Cascade is primarily FINDINGS-ONLY (it
reasons over finding JSON), but it MAY re-inspect `code_paths` under `CODE_ROOT` to
confirm a link is real; when it does, read only the pinned snapshot. Never write
under `CODE_ROOT`.

### Step 1 — Model each finding as a state transition

For each confirmed finding, express it as *precondition → capability gained*:
- an info leak: `unauth → learns a resource id / a path / a version`
- an IDOR: `knows an id → reads/writes another principal's object`
- a missing rate limit: `has an endpoint → can brute-force an id/credential space`
- an open redirect + OAuth: `controls a redirect → steals a token`
- a benign XSS + CSRF: `low-value script → escalates via a state-changing request`

### Step 2 — Find chains

Look for sequences where one finding's *capability gained* satisfies another's
*precondition*, moving the attacker from a lower position (e.g. `EXTERNAL`
unauthenticated) toward higher impact. Classic shapes: info-disclosure → IDOR →
brute-force; open redirect → OAuth token theft; SSRF → metadata endpoint → cloud
creds; low-priv upload → path traversal → RCE. A chain is only real if every link is
individually confirmed and the composition is concretely reachable — apply the same
bar as the hunting doctrine (no hand-waving links).

### Step 3 — Record the chain

Write a chain super-finding: ordered `chain_links`, the composed attack narrative,
the **entry-point** `attacker_position`/`privileges_required` (the chain is scored
on how the attacker STARTS, not on the most-privileged middle step — this is the
rule `ray-gauge` applies to chains), and the terminal impact. Keep the member
findings intact (they may also matter on their own).

### Step 4 — Hand off

`ray-gauge` scores the chain by its entry point (a chain that starts unauthenticated
and ends in account takeover is CRITICAL even if each link alone was MEDIUM).
`ray-chronicle` reports the chain as a single narrative with its links. Never let a
chain silently absorb a member finding — both the chain and its links are reported.

## Safety

- Every link must be an independently-confirmed finding; never invent a link to
  complete a chain.
- Read-only re-inspection against the pinned snapshot only; never write under
  `CODE_ROOT`.

When complete, notify the user.
