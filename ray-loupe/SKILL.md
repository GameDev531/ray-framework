---
name: ray-loupe
description: >-
  Reviews a code change with high precision across correctness, performance, maintainability, tests, style, and documentation — dispatching an isolated per-file reviewer, running a falsify-don't-verify self-check to kill false positives, and using the AST index for cross-file findings. Delegates deep security to the domain suite.
  Use when you want a thorough, low-noise review of a diff, a commit, a branch range, or a set of files — the general code-review counterpart to Ray's security pipeline.
  Don't use for a deep security audit (use ray-crucible/ray-turnstile/the domain suite) or memory-safety (use ray-marrow); ray-loupe triages security and hands depth to them.
---

# Loupe (/ray-loupe)

## System Goal

Precision Code Reviewer. Reviews a change the way a senior engineer reviews a
pull request: file by file, in scope, commenting only where confident, across
every dimension that matters — correctness, performance, maintainability, tests,
style, and docs — and handing deep security to the domain suite.

The governing principle is **precision over recall**, borrowed from the best
open code-review practice and made sharper here: *a false alarm costs more
reviewer trust than a missed minor issue.* A reviewer that flags forty things,
ten of them wrong, gets muted; one that flags eight real things gets read. So
this skill is built to stay silent unless it has evidence, and it runs an
explicit self-check that can only *veto* a finding with counter-evidence.

Where general code-review tools stop, Ray goes further, and this skill leans on
that: it makes **cross-file and architectural** findings (a caller and a callee
changed inconsistently in the same change) using the `ray-lattice` AST index
rather than grep; it **delegates deep security** to `/ray-crucible`,
`/ray-turnstile`, and the rest of the suite instead of doing a shallow security
pass; it **reviews test files** rather than excluding them; and its reviewer
carries **curated memory** so it learns a project's house style and recurring
defects across runs.

## Command Definition

- **Command:**
  `/ray-loupe [--range <base>..<head>] [--commit <sha>] [--paths <glob,...>] [--scan] [--state_root=<path>] [--repo_root=<path>]`
- **Description:** Reviews a change set (working-tree diff by default) across the
  full review taxonomy and writes ranked findings, a review report, and a
  coverage ledger.
- **Arguments (all optional):**
  - `--range <base>..<head>`: review the merge-base diff of two refs (a branch
    review). Absent + no other target → the working tree (staged + unstaged).
  - `--commit <sha>`: review a single commit against its parent.
  - `--paths <glob,...>`: restrict to matching paths.
  - `--scan`: review whole files (no diff), for a first-pass audit of existing
    code; adds the dedupe + project-summary steps.
  - `--state_root`: parent of `workspace/` (state). Absent → `./workspace/...`.
  - `--repo_root`: the repository to review. Absent → current directory.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json` (optional); the repository at
  `--repo_root` (the diff via the VCS carve-out, plus the changed files and the
  context they need); `workspace/kb/structural_index/manifest.json` and
  `workspace/helpers/query_structural_index.py` (optional — `ray-lattice`, for
  cross-file symbol resolution); this skill's `references/*.md`; an optional
  `.ray/loupe.rules.md` in the repo (house-style / custom guidelines).
- **Writes**: `workspace/findings/<uuid>.json` (standard schema plus a
  `category` field); `workspace/reviews/<run>/report.md` (the human review
  packet); `workspace/ledgers/ray-loupe.json` (the coverage ledger — which files
  were in scope and each item's terminal state).
- **Preconditions**: the repo is readable and the target change resolves. This
  skill runs no code, executes no payloads, and posts nothing to a forge — it
  produces findings and a report; posting to a PR is a separate, explicit step.
- **Idempotency Guarantee**: findings are UUID files (`ray-condenser` semantics
  apply); the coverage ledger is archived per run and overwritten. `--scan`
  batches are resumable via the ledger's per-item state.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/review_taxonomy.md` | before Step 2, and by every reviewer | The 8 categories × 4 severities, and the cross-cutting discipline: precision-over-recall, the explicit "Do NOT report" lists, evidence-before-claim gates, deconfliction with linters/compilers, version/ecosystem awareness, and scope fencing |
| `references/lang/<language>.md` | by the reviewer, selected by the file's language | The per-language checklist (correctness, concurrency, resource lifecycle, performance, idiom, and the language's "do not report" traps). `default.md` covers any language without its own file |
| `references/findings_contract.md` | before writing findings, and at Step 5 | Findings schema with the `category` field, the four computed fields, the review-report shape, and the coverage-ledger format |

## Instructions

### Step 0: Locator Resolution (Block A — CODE-READING role)

```
LOCATOR RESOLUTION (before reading ANY target code or artifact):
0. ROLE: If this skill NEVER reads target source (report, calibrate, reflect),
   you are a FINDINGS-ONLY stage: skip steps 2-6; still read active_snapshot from
   state for provenance/annotation; NEVER stop merely because a code root is unset.
1. Determine CODE_ROOT, in this priority order:
   a. If --target_root is passed on THIS invocation, CODE_ROOT = --target_root.
      It is AUTHORITATIVE and OVERRIDES SNAPSHOT_ROOT and the state fallback
      (used when a caller hands you a prepared tree, e.g. a patched shadow).
   b. Else if --snapshot_root (or SNAPSHOT_ROOT) is passed, use it.
   c. Else read state_root/workspace/.ray_state.json (state_root from
      --state_root if passed, else ./workspace/... relative to the current dir)
      -> active_snapshot.root / .snapshot_id / .snapshot_pinned.
   d. Else (no arg AND no readable active_snapshot): CODE_ROOT = current directory,
      treat snapshot_pinned = false (MODE-OFF). Do NOT stop.
2. SENTINEL CHECK (only if snapshot_pinned is true AND you did NOT take path 1a):
   verify CODE_ROOT/.ray_snapshot_id exists and equals SNAPSHOT_ID. If missing
   or different -> STOP "snapshot sentinel mismatch". (A --target_root tree (1a) is
   deliberately mutated and is sentinel-EXEMPT.)
3. PATH FIELDS:
   - SNAPSHOT-RELATIVE (read under CODE_ROOT): code_paths entries; plan target_files
     that are file paths. Strip ONLY a trailing ":<digits>". A code_paths entry
     containing "://" is a URL/endpoint, NOT a file read. A code_paths entry that is
     NOT of the form <existing-path>:<integer> is a non-source LOCATOR
     (symbol/offset/endpoint): only check that the artifact/symbol exists; skip ALL
     line-range and line-existence logic.
   - STATE-RELATIVE (read/write under state_root/workspace, NEVER prefix CODE_ROOT):
     kb_references, repro_file_path, reattack_file_path, helper scripts, report
     files, and all state/findings JSON.
4. Never WRITE under CODE_ROOT when snapshot_pinned is true. Any command that
   compiles, generates, or writes artifacts MUST run in a PRIVATE SHADOW copy
   (mktemp -d from CODE_ROOT), never with cwd=CODE_ROOT. Read-only inspection may
   cd into CODE_ROOT.
5. VCS-METADATA CARVE-OUT: history-log extraction and any VCS diff/blame command
   run in the LIVE repository root (which still has .git/.hg/.repo), NOT CODE_ROOT
   (the snapshot copy strips VCS metadata). Do NOT stop merely because CODE_ROOT
   lacks .git/.hg/.repo.
6. Every shell command uses ABSOLUTE paths and sets its own working directory on
   that call. Do NOT assume the working directory persists between calls.
```

Skill notes: a diff review normally runs in MODE-OFF against the working tree,
and the diff itself comes from the VCS carve-out (step 5). `--repo_root` is the
review target. This skill's `references/*.md` sit beside `SKILL.md`.

### Step 1: Resolve the Change Set and Freeze Coverage

Compute the file set to review from the target (`--range` merge-base diff,
`--commit` vs parent, `--paths`, `--scan` whole files, or the working tree).
Filter out binaries and generated/vendored files (record why each was excluded).
Then **freeze the coverage denominator** into the ledger *before* dispatching:
the list of files that are supposed to be reviewed, so "how many did we cover"
cannot drift. Unlike general review tools, do **not** exclude test files — a bad
test is a real defect.

For a file whose diff is very large, prefer reviewing it in focused hunks over
skipping it; record any file you genuinely cannot cover as `failed(size)` in the
ledger rather than silently dropping it.

### Step 2: Dispatch Per-File Reviewers (ray-scrivener)

For each file in scope, dispatch a **ray-scrivener** subagent in isolation — its
charter is `agents/ray-scrivener.md`. Per-file isolation is the answer to the
failure mode where one agent reviewing a big change set cuts corners. Give each
reviewer: the file and its diff, the language docket (`references/lang/<lang>.md`)
and the taxonomy, the repo's `.ray/loupe.rules.md` house rules if present, and
the `ray-lattice` query helper path if the index exists.

Each reviewer applies **precision over recall**, comments only on changed lines
with evidence, and emits findings with a `category` and `severity`. It reviews in
scope: a real issue it notices in *another* file is recorded as a cross-file
candidate (Step 3), not commented in place.

### Step 3: Cross-File and Architectural Pass

This is where Ray beats a per-file-only reviewer. Using the `ray-lattice` index
(resolve symbol → callers/callees) and the cross-file candidates the reviewers
surfaced, check the change set as a whole for defects no single file shows:
a caller and callee changed inconsistently (a contract broken across the diff),
duplicated new logic across two new files, a shared type changed without updating
all consumers, an API signature change with a missed call-site. When the index is
absent, fall back to grep — but say so, and keep this pass narrow and evidenced.

### Step 4: The Falsify-Don't-Verify Self-Check

Run a single reflection pass over the collected findings that sees **only the
diff** (not the full context the reviewers gathered). Its job is asymmetric and
deliberately weaker than the reviewers: it may **drop only a finding it can prove
wrong from the diff alone**. A finding it merely doubts — but cannot disprove
without context it lacks — it must let pass, because the reviewer had context it
does not. This one-directional veto is the cleanest false-positive control there
is: it removes confidently-wrong comments without letting a low-context judge
kill good findings it simply can't verify.

Also here: **deconflict with tooling** — drop a finding that a compiler, linter,
formatter, or type checker would reliably report on its own, unless the change
shows a concrete consequence those tools won't express. Ray is not a linter.

### Step 5: Write Findings, Report, and the Coverage Ledger

Follow `references/findings_contract.md`. Findings carry the standard schema plus
`category`. Rank by severity, then category (correctness/security above
style/docs). For `security`-category findings, keep the comment to a **triage**
level and point at the domain skill that owns the depth (`/ray-crucible`,
`/ray-turnstile`, …) — do not attempt the deep audit here.

Write the human review report to `workspace/reviews/<run>/report.md` (summary,
findings grouped by file and severity, and — for `--scan` — the project-level
rollup: top issues, hotspots, cross-cutting concerns, quick wins). Write the
coverage ledger with each file's terminal state (`completed` / `reused` /
`failed(<class>)`), so a partial run is honest about what it did and did not
reach.

### Step 6: Complete

Report the counts by category and severity, files covered vs. in scope, anything
`failed`, and where security depth was deferred. Do not print the report body or
finding bodies into chat — they are on disk.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Deep security audit of the reviewed code (injection, authz, crypto, …) | the domain suite (`/ray-crucible`, `/ray-turnstile`, `/ray-custodian`, `/ray-seam`, `/ray-sentry`, `/ray-vault`, `/ray-citadel`) |
| Memory-safety of native/unsafe code | `/ray-marrow` |
| The target app's LLM integration | `/ray-oracle` |
| Proving a suspected bug by running it | `/ray-detonator` |
| Live attack + patch loop against a running app | `/ray-siege` |

`ray-loupe` is the general-review counterpart to the security pipeline. It
triages security and hands depth off; it does not replace the domain suite. When
its `security` findings overlap a domain skill's, `/ray-condenser` merges them.
