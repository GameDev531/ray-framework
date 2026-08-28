---
name: ray-marrow
description: >-
  Hunts native/unsafe memory-safety bugs: out-of-bounds read/write, use-after-free, double-free, integer overflow/underflow, type confusion, uninitialized memory, format strings, and unsafe FFI boundaries.
  Use when the target contains C/C++, Rust `unsafe`, Zig, assembly, kernel/driver, or native FFI code.
  Don't use for memory-safe web code (use the web domain skills).
---

# Marrow (/ray-marrow)

## System Goal

Memory-Safety Auditor. Finds the spatial and temporal memory-safety violations in native and `unsafe` code — the buffer that is written past its bounds, the pointer used after free, the length that overflows before the allocation — and the FFI boundaries where a safe language's guarantees stop.

## Command Definition

- **Command:** `/ray-marrow [--target_root=<path>] [--snapshot_root=<path>] [--snapshot_id=<id>] [--state_root=<path>]`
- **Description:** Reviews native/unsafe code for memory-safety violations and unsafe FFI boundaries.
- **Arguments (all optional; supplied by ray-conductor, consumed by Block A):**
  `--snapshot_root`/`--snapshot_id`/`--state_root`/`--target_root`. All absent →
  MODE-OFF (reads the live tree, omits `discovery_commit`), exactly as the rest
  of the suite.

## Input/Output Contract

- **Reads**:
  - `workspace/plan.json` — investigations whose class this skill owns (falls
    back to a full domain sweep of the target if the plan is missing/empty).
  - `references/marrow-docket.md` — this skill's vulnerable→safe pattern catalogue
    (read it BEFORE auditing).
  - `workspace/kb/THREAT_MODEL.md` and any `kb_references` on the investigation.
  - Target source files under the resolved `CODE_ROOT`.
- **Writes**:
  - `workspace/findings/<uuid>.json` (creates `workspace/findings/` if missing),
    conforming to the shared finding schema (`schema.json` at the repo root; the
    field list is in `ray-prospector/SKILL.md`). Set `cwe`, `owasp`, and a
    proposed `severity`; never set `ray_risk_score` (that is `ray-gauge`'s).
- **Preconditions**: target files must be accessible.
- **Idempotency Guarantee**: writes new findings as separate UUID files; relies
  on `ray-condenser` to merge duplicates across the domain sweeps.

## Instructions

### Step 0: Locator Resolution (run first)

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

This is a CODE-READING stage: Block A step 0's findings-only skip does NOT apply.
Resolve `CODE_ROOT`, honor the sentinel, and read every `target_files`/`code_paths`
entry under `CODE_ROOT`. `workspace/**` (plan, kb, findings, state) is
STATE-RELATIVE — never prefix `CODE_ROOT`. Never write under `CODE_ROOT` when
pinned; a repro harness compiles in a private shadow.

### Step 1: Scope & context

Read `references/marrow-docket.md`. From `workspace/plan.json`, take the
investigations tagged for this domain (or, if none, sweep the target for the
surfaces below). Read any `kb_references` for compounded context, and the threat
model's trust boundaries and any `Calibration Overrides` (a target profile may
lift caps that would otherwise bury a real finding in this domain).

### Step 2: Hunt — bounds, lifetimes, and integer math on untrusted sizes

For every buffer operation reachable from untrusted input, verify the length and
offset are checked against the allocation for ALL paths, including error and cleanup
paths. Track object lifetimes: is anything used after `free`/`drop`, freed twice, or
returned as a dangling pointer? Check every size/length computation for integer
overflow/underflow and signedness before it feeds an allocation or a copy. At FFI
boundaries, confirm the safe side validates what the unsafe side assumes (lengths,
null-termination, ownership). Where a public API documents a size contract, grep the
whole repo for its call sites and verify each honors it.

Apply the twelve hunting angles from the doctrine
(`ray-prospector/references/hunting-doctrine.md`) to each surface. Where the
target is locally runnable and a candidate is concrete, capture a reproduction
hint (or a minimal harness result) now — it shortens `ray-detonator` later.

### Step 3: Clear the bar before writing a finding

Write a finding ONLY when it clears ALL six: (1) a concrete attack (exact
inputs/requests/sequence); (2) meaningful impact; (3) no earlier layer already
blocks it (else it is a hardening note, not a finding); (4) the source is
attacker-controlled — cite the ingress file:line (server-config/env/constants are
NOT attacker-controlled); (5) any parser/runtime assumption is verified against
the spec or by execution; (6) it is not a designed behavior for a trusted actor.
 A memory-safety flaw in library code is VALID even if no current caller triggers it (intrinsic). But respect SIMD/padding contracts: an OOB access provably contained within guaranteed trailing padding is a false positive (mirrors ray-arbiter rule 11).

### Step 4: Write findings

For each surviving finding, write `workspace/findings/<uuid>.json` per the shared
schema. Set `title`, `description` (root-cause + the concrete attack),
`severity`, `cwe`, `owasp` (map to the OWASP catalog where one applies), `code_paths` (SNAPSHOT-RELATIVE `path:line`),
`attacker_position`, `privileges_required`, `user_interaction`,
`status: "PROVISIONALLY_VALID"`, `discovery_commit` (the pinned `SNAPSHOT_ID`;
omit in MODE-OFF), and the `signature`/`lineage_id` per `ray-prospector`'s
Step 5a. Put any reproduction hint in `repro_hints`. Do not print finding JSON in
chat.

When complete, notify the user with a one-line count by proposed severity.
