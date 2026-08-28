---
name: ray-loupe
description: >-
  A general, high-precision code review of a change (a PR, a diff, or a branch). Dispatches the ray-scrivener agent for the review and delegates deep security questions to the relevant domain skills of the Ray suite.
  Use to review a code change for correctness, clarity, and security. Don't use for a full-codebase security audit (that is the Track A pipeline via ray-conductor).
---

# Loupe (/ray-loupe)

## System Goal

Change Reviewer. A focused, high-signal review of a specific change — not a
whole-codebase audit. It reviews the diff for correctness, clarity, and risk, and
when a change touches a security-sensitive surface it delegates the deep question to
the domain skill that owns it (auth → `ray-turnstile`, injection → `ray-crucible`,
and so on) rather than guessing.

## Command Definition

- **Command:** `/ray-loupe [--diff | --pr=<n> | --branch=<name> | --path=<glob>] [--security]`
- **Description:** Reviews a code change; delegates deep security to the suite.
- **Parameters:**
  - `--diff`: review the current uncommitted diff (default).
  - `--pr` / `--branch` / `--path`: review a PR, a branch vs its base, or a path set.
  - `--security`: bias the review toward security and eagerly delegate to domain
    skills.

## Input/Output Contract

- **Reads**: the change under review (diff/PR/branch/path) and the surrounding code
  needed to judge it.
- **Writes**: a review to chat (or `workspace/review/` for a large change) —
  grouped, prioritized comments; and, for a confirmed security issue, a
  `workspace/findings/<uuid>.json` so it flows into the normal pipeline.
- **Preconditions**: a change to review.
- **Idempotency**: re-reviewing the same change at the same commit yields the same
  comments.

## Instructions

### Step 1 — Frame the change

Read the diff and enough surrounding code to understand intent. Establish what the
change is trying to do and what could break — the review is about THIS change, not
the whole codebase (that is the Track A pipeline; point the user there if they want
a full audit).

### Step 2 — Dispatch ray-scrivener

Dispatch the `ray-scrivener` agent for the high-precision review. It reads the
change plus the relevant domain dockets and returns prioritized comments:
correctness bugs first, then security, then clarity/maintainability. Scrivener keeps
precision high — every comment names the concrete problem and, where possible, the
fix.

### Step 3 — Delegate deep security to the suite

When the change touches a security surface, do NOT hand-wave: delegate the deep
question to the owning domain skill using its docket —
- untrusted input → sink: `ray-crucible`
- auth / access / IDOR: `ray-turnstile`
- CORS / headers / redirects: `ray-seam`
- rate limit / exposed endpoint / webhook: `ray-sentry`
- crypto / secret / datastore: `ray-vault` (secrets also `ray-cloak`)
- native memory: `ray-marrow`; the app's LLM feature: `ray-oracle`
- dependencies: `ray-manifest`; IaC/containers: `ray-terrain`

A confirmed security issue is written as a finding (clearing the doctrine's bar) so
`ray-gauge` scores it and `ray-chronicle` can report it — the review and the audit
share one finding contract.

### Step 4 — Deliver

Group comments by file and severity; lead with must-fix correctness/security, then
should-fix, then nits. Say what the change does well, too — it calibrates the
must-fixes. Keep it about the change.

When complete, notify the user.
