---
name: ray-conductor
description: >-
  Orchestrates a full Ray security-review pass: pins the code snapshot, drives every stage in order, and archives the pass. Use when you want to run the complete pipeline end-to-end on a codebase instead of invoking stages by hand.
  Don't use for a single-domain spot check (invoke that one domain skill directly) or for building a custom harness (that is ray-foundry).
---

# Conductor (/ray-conductor)

## System Goal

Deterministic Pass Orchestrator. Owns the **Pass Lifecycle Contract** every other
Ray skill assumes exists: it creates and advances `workspace/.ray_state.json`,
pins an immutable content-hashed snapshot of the target, stamps the sentinel,
runs each stage against that frozen snapshot, then archives the pass. Without a
conductor (or an equivalent custom harness built via `ray-foundry`), the snapshot
machinery in every stage stays inert (MODE-OFF) — this skill is what turns it on.

## Command Definition

- **Command:**
  `/ray-conductor [--target_root=<path>] [--state_root=<path>] [--sync] [--max-passes=<n>] [--domains=<list>] [--live] [--profile=<name>]`
- **Description:** Runs the static pipeline (Track A) end-to-end, and optionally
  the live attack+fix loop (Track B) when `--live` is passed and a runnable app
  is available.
- **Parameters:**
  - `--target_root`: the codebase to review (defaults to `.`).
  - `--state_root`: parent of `workspace/` (defaults to `.`). All Ray state lives
    under `<state_root>/workspace/`.
  - `--sync`: pin a fresh immutable snapshot for this pass (turns on PINNED mode).
    Absent → MODE-OFF (today's default; the pipeline runs against the live tree,
    no `discovery_commit`, no drift detection). Recommended for any real audit.
  - `--max-passes`: cap the number of passes (default 1).
  - `--domains`: comma-separated domain skills to run in the Audit band (default:
    inferred from the target — see Step 3). e.g.
    `crucible,turnstile,seam,sentry,vault`.
  - `--live`: after the static track, run Track B (`ray-siege`) against a
    disposable local instance to prove findings by exploitation.
  - `--profile`: a target profile that adjusts calibration (e.g. `web-app`,
    `native`, `library`). See `docs/coverage-map.md` and the profile's
    `Calibration Overrides` injected into the threat model.

## Input/Output Contract

- **Reads**:
  - `--target_root` (the codebase).
  - `workspace/.ray_state.json` (if a prior pass exists).
  - `workspace/archive/**` (prior findings/insights for carry-forward).
- **Writes**:
  - `workspace/.ray_state.json` — CREATES it on first run; this is the ONLY
    stage that creates and increments it. Fields: `pass_number`,
    `active_snapshot` (`{root, snapshot_id, snapshot_pinned, pass, vcs_type}`),
    `snapshot_history`, `kb_snapshot_id` (stamped by blueprint), `changed_files*`
    (stamped by compass).
  - `<snapshot_root>/.ray_snapshot_id` — the sentinel file every stage checks.
  - `workspace/archive/**` — per-pass archives of findings, KB, insights.
- **Preconditions**: the target must be readable. Nothing else — the conductor
  bootstraps everything the downstream stages require.
- **Idempotency Guarantee**: re-running the same pass number against the same
  snapshot is a no-op on state; a new `--sync` mints a new snapshot id and
  advances `snapshot_history`.

## Instructions

You are the orchestrator. Perform the **sync → pin → run → archive** lifecycle.
A drop-in reference implementation ships at
[scripts/ray_conductor.py](../scripts/ray_conductor.py) — you MAY run it directly for the
sync/pin/archive mechanics, or perform the steps yourself as below.

### Step 1 — Resolve state and pass number

- `STATE_ROOT` = `--state_root` or `.`. Ensure `<STATE_ROOT>/workspace/` exists.
- If `workspace/.ray_state.json` is absent, CREATE it:
  `{"pass_number": 0, "snapshot_history": []}`.
- `N` = `pass_number + 1`. This is the pass you are about to run.

### Step 2 — Pin the snapshot (only when `--sync`)

When `--sync` is passed:

1. Detect `vcs_type` in the LIVE target (`git`, `hg`, `repo`, else `none`).
2. Compute `SNAPSHOT_ID`:
   - If a clean VCS tree: `SNAPSHOT_ID` = the commit/revision id. If the tree is
     dirty (uncommitted changes), append a content hash of the working tree:
     `<rev>+content:<sha256-16>` so within-pass findings MATCH and cross-pass
     bare-commit findings do not.
   - If no VCS: `SNAPSHOT_ID` = `content:<sha256-16>` of the tree (a `content:`
     id). HALT mode uses a `live:<...>` id (present but unpinned).
3. Copy the target to an immutable snapshot root
   (`mktemp -d` or `workspace/snapshots/<SNAPSHOT_ID>/`), STRIP VCS metadata from
   the copy, and write the sentinel `<snapshot_root>/.ray_snapshot_id` containing
   `SNAPSHOT_ID` verbatim.
4. Write `active_snapshot = {root, snapshot_id: SNAPSHOT_ID, snapshot_pinned: true,
   pass: N, vcs_type}` into state, and append `SNAPSHOT_ID` to `snapshot_history`.
5. Set `pass_number = N`.

When `--sync` is absent: leave `active_snapshot` unset (MODE-OFF). Every stage's
Block A path 1d handles this — the pipeline still runs, just without snapshot
guarantees. **Re-pin on every pass** (never preserve `active_snapshot` across the
pass increment without re-pinning — the CURRENT-PASS CHECK in several stages
STOPs on a stale `pass` mismatch).

### Step 3 — Run the static track (Track A), in order

Pass `--snapshot_root=<snapshot_root> --snapshot_id=<SNAPSHOT_ID>
--state_root=<STATE_ROOT>` to EVERY stage (omit the snapshot flags in MODE-OFF).
Run each stage and wait for it to finish before the next:

1. **Map** — `ray-lattice` (optional, if a structural index helps), `ray-prism`,
   `ray-blueprint`.
2. **Plan** — `ray-perimeter`, `ray-compass`. Inject the `--profile` threat-model
   overrides here (Step 3a).
3. **Audit** — `ray-prospector` (always) plus the domain skills that fit the
   target. **Domain selection** (unless `--domains` was given):
   - Always: `ray-prospector`.
   - Untrusted input handling → `ray-crucible`.
   - Any auth/session/tenancy → `ray-turnstile`.
   - Client/server boundary, CORS, forms → `ray-seam`.
   - Public API, rate limits, webhooks → `ray-sentry`.
   - A datastore → `ray-vault`.
   - Multi-service / deployment topology → `ray-citadel`.
   - Handles personal data, cookies, TLS surface → `ray-custodian`.
   - Native/unsafe code (C/C++/Rust-unsafe/FFI) → `ray-marrow`.
   - An LLM/AI feature → `ray-oracle`.
   - A dependency manifest/lockfile → `ray-manifest`.
   - IaC / containers / cloud config → `ray-terrain`.
   - A long-lived operated service (patch cadence, DR) → `ray-steward`.

   Run the domain skills in parallel where the harness supports it; each writes to
   `workspace/findings/<uuid>.json`.
4. **Validate** — `ray-condenser`, `ray-arbiter`, `ray-magistrate`.
5. **Prove** — `ray-detonator`.
6. **Report** — `ray-gauge`, `ray-chronicle`, `ray-retrospective`.

Editing files during the run? Keep `ray-cloak` active as a write-time guard.

### Step 3a — Apply the target profile

If `--profile=<name>` is set, before running `ray-perimeter` write the profile's
`Calibration Overrides` into `workspace/kb/THREAT_MODEL.md` (ray-perimeter merges
them). This is how a `web-app` profile lifts the caps that would otherwise bury a
real CORS-wildcard, missing-rate-limit, or unreachable-CVE finding on a web SaaS.
See `docs/coverage-map.md` for the shipped profiles.

### Step 4 — Optional live track (Track B)

When `--live` is passed and a runnable app is available, after Report dispatch
`ray-siege`, which stands up a disposable local instance, seeds canaries, and runs
the `ray-reaver` (attack) / `ray-bulwark` (fix) loop. Siege owns its own authz
gate — never run it against anything you are not authorized to attack.

### Step 5 — Archive the pass

Ensure `workspace/archive/findings_pass_${N}/` exists and copy the pass's findings
into it. `ray-blueprint` and `ray-chronicle` archive the KB and report. Increment
is already done in Step 2 (or do it here in MODE-OFF). Notify the user with a
one-line summary: pass number, snapshot id (or `MODE-OFF`), domain skills run, and
the counts by priority from `ray-gauge`.

## Safety

- NEVER write under the snapshot root once pinned (Block A step 4) — every stage
  that compiles or generates runs in a private shadow.
- NEVER run the live track without explicit authorization for the target.
- The conductor re-pins every pass; a stage that sees `active_snapshot.pass !=
  pass_number` treats the snapshot as stale and degrades — that is the safety net
  for a mis-built custom harness.

When complete, notify the user.
