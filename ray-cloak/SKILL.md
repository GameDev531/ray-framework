---
name: ray-cloak
description: >-
  A write-time secret guard and repository secret scanner. Use whenever you are writing or editing files in a project with databases, APIs, or credentials, and to sweep the working tree and git history for leaked secrets, tokens, keys, and connection strings.
  Runs any time, outside the audit pipeline. Don't use for first-party logic flaws (the domain skills) or dependency CVEs (ray-manifest).
---

# Cloak (/ray-cloak)

## System Goal

Secret Guard. Two jobs: (1) a **write-time guard** that stops a secret from being
committed to a file as you create or edit it, and (2) a **repository scan** that
sweeps the working tree — and, when available, the VCS history — for secrets that
already leaked. This is the framework's answer to the video's `.env`/Secrets-Audit
door: keys, tokens, and connection strings that must never reach a repository.

## Command Definition

- **Command:** `/ray-cloak [--scan-history] [--staged] [--path=<dir>] [--fix]`
- **Description:** Guards writes and scans for leaked secrets.
- **Parameters:**
  - `--scan-history`: also scan the full VCS history (not just the current tree).
  - `--staged`: scan only files staged for commit (pre-commit use).
  - `--path`: limit the scan to a subtree.
  - `--fix`: when a secret is found in a tracked file, propose the remediation
    (move to env, add to `.gitignore`, rotate) — never rewrite history silently.

## Input/Output Contract

- **Reads**: the working tree (or `--staged` set / `--path`); `.gitignore`; when
  `--scan-history`, the VCS log via the LIVE repo root (never a stripped snapshot
  copy — see Block A step 5).
- **Writes**: `workspace/findings/<uuid>.json` for confirmed leaks (schema per
  `ray-prospector`); optionally a `.gitignore` suggestion and a rotation checklist
  in chat. NEVER writes a secret value into a finding — redact to
  `<provider>:<last4>` form.
- **Preconditions**: none.
- **Idempotency**: re-running produces the same findings; a leak already reported
  with the same `signature` is not re-reported.

## Instructions

### Write-time guard (mode 1)

When invoked as a guard while files are being written/edited: before a file is
saved, scan the ADDED content for secret patterns (below). If a match is a real
secret (not a placeholder/example), STOP and tell the user exactly which line
carries what, and propose the safe form (reference an env var, keep the value in a
`.env` that is git-ignored). Distinguish real secrets from obvious placeholders
(`YOUR_API_KEY`, `xxxx`, `changeme`, example.com creds) — flag those only as a
reminder, not a blocker.

### Repository scan (mode 2)

**Step 0 — Locator Resolution.** Follow Block A (in `ray-prospector/SKILL.md`).
Secret scanning of the working tree reads under `CODE_ROOT`; a `--scan-history`
sweep runs in the LIVE repo root (Block A step 5 VCS carve-out) because the pinned
snapshot strips `.git`.

1. **Sweep the tree.** Grep the target for the pattern families below. If a
   dedicated scanner is available (`gitleaks`, `trufflehog`, `detect-secrets`),
   run it and treat its output as candidates; otherwise use the built-in patterns.
2. **Sweep history (when `--scan-history`).** In the live repo root, scan past
   commits — a secret removed from the current tree still lives in history and is
   still leaked. `git log -p`, or `gitleaks detect` over history. Report the commit
   and the redacted secret.
3. **Confirm before reporting.** A pattern hit is a candidate, not a finding: trace
   whether the value is a real credential (entropy, provider prefix, adjacent
   context) vs a test/placeholder. Check whether the file is git-ignored (a secret
   in a genuinely ignored `.env` never committed is lower severity than one in a
   tracked file or in history).
4. **Report.** For each confirmed leak, write a finding (`CWE-798` /
   `CWE-540`; OWASP `A05:2021`), severity by exposure (tracked-and-pushed >
   in-history > local-ignored), with the redacted secret, the file:line or commit,
   and the remediation: move to env/secret manager, add to `.gitignore`, and
   **rotate the credential** (a leaked secret is burned even after removal).

### Secret pattern families

Cloud keys (`AKIA…`, `ASIA…`, GCP `AIza…`, Azure connection strings), private keys
(`-----BEGIN … PRIVATE KEY-----`), tokens (`ghp_`, `github_pat_`, `xox[baprs]-`,
`sk-`/`sk-ant-`, Stripe `sk_live_`/`rk_live_`, JWT triples), database URLs
(`postgres://user:pass@…`, `mysql://…`, `mongodb+srv://…`), generic
`password=`/`secret=`/`api_key=` with a high-entropy value, and `.env`/`.pem`/
`.p12`/`credentials.json`/`id_rsa` files tracked in the repo. Also verify
`.gitignore` actually covers secrets, uploads, and local config.

## Safety

- NEVER write a real secret value into a finding, a log, an artifact, or chat —
  always redact to `<provider>:<last4>`.
- NEVER rewrite VCS history on your own to purge a secret; propose it and let the
  user decide (history rewrite is destructive and coordinates with collaborators).
- The only reliable remediation for a leaked-and-pushed secret is **rotation** —
  always say so.

When complete, notify the user.
