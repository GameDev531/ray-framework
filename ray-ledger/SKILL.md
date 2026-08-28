---
name: ray-ledger
description: >-
  Mines VCS history for security signal — past vulnerabilities, security fixes, reverted patches, and the files that keep breaking — and writes them to workspace/historical_insights.jsonl. Use at the start of a campaign on a repo with git/hg history so planning and digests can weight known-risky code.
  Don't use for analyzing current source (the domain skills) or writing patches.
---

# Ledger (/ray-ledger)

## System Goal

History Miner. Extracts durable security signal from the version-control history —
which files were touched by security fixes, which bugs were reverted and may have
regressed, which areas churn under CVE references — and records it as
`workspace/historical_insights.jsonl`. This is the producer that `ray-prism`,
`ray-blueprint`, and `ray-condenser` read as "past vulnerability metadata"; without
it, those stages simply see no history (which is fine, just blind to regressions).

## Command Definition

- **Command:** `/ray-ledger [--since=<rev|date>] [--state_root=<path>] [--max-commits=<n>]`
- **Description:** Mines VCS history into `workspace/historical_insights.jsonl`.
- **Parameters:**
  - `--since`: only mine history after this revision/date (default: full history,
    capped by `--max-commits`).
  - `--state_root`: parent of `workspace/`.
  - `--max-commits`: cap the number of commits scanned (default 2000).

## Input/Output Contract

- **Reads**: the LIVE repository history (git/hg/repo) in the live repo root —
  never a pinned snapshot copy, which strips VCS metadata (Block A step 5).
- **Writes**: `workspace/historical_insights.jsonl` (append/merge; one JSON object
  per line), STATE-RELATIVE under `--state_root`.
- **Preconditions**: a readable VCS history. If none exists (no `.git`/`.hg`/
  `.repo`), write an empty file and note it — absence of history is not an error.
- **Idempotency**: keyed by commit id + file; re-running does not duplicate an
  already-recorded insight.

## Instructions

### Step 0 — Locator Resolution

Follow Block A (canonical text in `ray-prospector/SKILL.md`). This is a
FINDINGS/HISTORY stage that reads VCS metadata: per Block A step 5, run every log/
diff/blame command in the **LIVE repository root**, not `CODE_ROOT` (the snapshot
copy has no `.git`). Do NOT stop merely because `CODE_ROOT` lacks a VCS dir. Write
only under `--state_root/workspace` (STATE-RELATIVE).

### Step 1 — Select security-relevant commits

Scan the history (bounded by `--since`/`--max-commits`). Flag a commit as
security-relevant when its message or diff shows any of:
- Security keywords: `CVE-`, `vuln`, `security`, `exploit`, `injection`, `XSS`,
  `SSRF`, `RCE`, `auth bypass`, `overflow`, `use-after-free`, `sanitize`, `escape`,
  `CWE-`, an advisory id.
- A revert of a prior security fix (a regression risk — the bug may be back).
- Churn hotspots: files that appear repeatedly across security-relevant commits.

Use `git log --all -p -S<term>` / `--grep`, `git log --follow` for renames, and
`hg log` equivalents. Rename-follow so a moved file keeps its history.

### Step 2 — Extract insights

For each security-relevant commit, record what changed, which files, the
vulnerability class if identifiable, and whether it was a fix or a revert. Prefer
concise, actionable entries over raw diffs.

### Step 3 — Write `historical_insights.jsonl`

Append one object per insight (dedup by commit+file). Suggested shape (aligns with
`schema.json`'s `trajectory_insight`):

```json
{"type": "vulnerability", "title": "SQLi fixed in user search", "code_paths": ["src/search.py"], "insight": "commit abc123 parameterized a raw query; class CWE-89; watch for regressions", "status": "FIXED"}
{"type": "false_assumption", "title": "reverted CSRF fix", "code_paths": ["web/csrf.py"], "insight": "commit def456 reverted the CSRF token check added in abc000 — possible regression"}
```

Downstream: `ray-prism` enriches directory digests with these; `ray-blueprint`
folds them into KB vulnerability pages; `ray-compass` weights planning toward
historically-risky files; `ray-condenser` deliberately does NOT dedup against this
file (so a reintroduced old bug is caught as a regression, not filtered).

## Safety

- Read-only against history; never rewrite it.
- Redact any secret encountered in an old diff to `<provider>:<last4>` (hand a real
  leaked-and-still-live secret to `ray-cloak` for rotation) — never copy a secret
  value into `historical_insights.jsonl`.

When complete, notify the user.
