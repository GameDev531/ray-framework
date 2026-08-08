---
name: ray-marrow
description: >-
  Sweeps native and unsafe code for the memory-safety and systems-bug canon — out-of-bounds read/write, use-after-free, double-free, integer overflow and narrowing, type confusion, format strings, uninitialized reads, stack overflow, and low-level data races — by inventorying dangerous sinks and tracing each to an attacker-influenced size, index, lifetime, or pointer.
  Use when the target contains C, C++, Rust unsafe blocks, CGo, Objective-C, or any FFI/native layer and you need memory-safety findings written to workspace/findings/.
  Don't use for web/injection classes (use ray-crucible), authentication and tenancy (use ray-turnstile), or the target application's LLM integration (use ray-oracle).
---

# Marrow (/ray-marrow)

## System Goal

Memory-Safety & Systems Auditor. Inventories the operations where a program can
corrupt its own memory — every copy, allocation, index, free, cast, and shared
write — and traces each back toward an attacker-influenced size, count, index,
lifetime, or pointer. It reports the sites where nothing sound bounds them.

The method matters more than the class list, the same way it does in
`/ray-crucible`: scanning for "unsafe-looking C" produces noise; enumerating
sinks and then proving or disproving that an attacker controls the size/index/
lifetime that reaches them produces findings that survive `/ray-arbiter` and that
`/ray-detonator` can reproduce under a sanitizer. This stage is sink-driven by
construction.

`/ray-prospector` audits whatever the plan targets with memory safety in view;
`/ray-marrow` runs an exhaustive, class-by-class sweep of the native memory-safety
canon regardless of what the plan targets. The overlap is deliberate;
`/ray-condenser` merges the results. `/ray-marrow` is the discovery counterpart
to machinery the pipeline already has downstream: `/ray-detonator` compiles
sanitizer builds and hunts variants, `/ray-arbiter` carries the SIMD/allocator-
padding constraint, and `/ray-magistrate` judges release-build viability
(`NDEBUG`, assertion stripping). This skill's job is to make the *finding* of
these bugs systematic rather than incidental.

## Command Definition

- **Command:** `/ray-marrow`
- **Description:** Performs a sink-driven sweep for out-of-bounds access,
  use-after-free, integer overflow, type confusion, format strings, uninitialized
  reads, and low-level races, writing findings plus a sink ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: the `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--classes <csv>`: restrict the sweep to named classes (e.g. `oob,uaf,intover`).
    Absent → every class in `references/memory_safety_docket.md`. A restricted run
    MUST record the skipped classes as `NOT_ASSESSED` in the ledger — never let a
    narrowed run look like a clean one.
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json` (`pass_number`, `active_snapshot`);
  `workspace/plan.json` (optional — it may reorder the sweep, never narrow it);
  `workspace/kb/THREAT_MODEL.md` and `workspace/kb/entities/*.md` (optional);
  `workspace/kb/structural_index/manifest.json` and
  `workspace/helpers/query_structural_index.py` (optional, HINT-only: they rank
  and resolve callers, they never decide membership); this skill's
  `references/*.md`; target source and build files (`Makefile`, `CMakeLists.txt`,
  `Cargo.toml`, `*.gyp`, compiler flags); `workspace/ledgers/ray-marrow.json`
  from the previous pass.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-marrow.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-marrow_pass_${N}.json` before overwriting.
- **Preconditions**: target files readable. No exploitation and no compilation is
  performed here — no sanitizer build is run, no crash is triggered. Proof (the
  ASan/UBSan/TSan reproduction) belongs to `/ray-detonator`.
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges). The ledger is archived per pass and then
  deterministically overwritten.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/memory_safety_docket.md` | before Step 2, then per class in Steps 2–4 | One section per class: sink grep patterns, the safe pattern, the allocator/padding and "who controls the size" traps that decide most disputes, and the reproduction hint (which sanitizer, what evidence) to hand `/ray-detonator` |
| `references/findings_contract.md` | before writing the first finding, and again at Step 6 | Findings schema, the four computed fields, this domain's CWE set, evidence discipline, severity defaults, and the sink-ledger format |

The docket is per class, so read it a section at a time as you sweep — it puts
the allocator-contract and integer-provenance traps in front of you at the moment
you are deciding whether a `memcpy` is actually reachable with an attacker-
controlled length.

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

This is a CODE-READING stage, so the findings-only skip does not apply. This
skill's `references/*.md` sit beside `SKILL.md`, not under CODE_ROOT.

### Step 1: Load Context and Establish the Source Set

Read `pass_number`, `active_snapshot`, the threat model, and the docket's table
of contents. Then enumerate the **untrusted-length/index/pointer sources** — the
places where a value that later reaches a sink can be influenced by an attacker:
parsed file/network/IPC fields, `argv`/environment, lengths and counts decoded
from a header, values returned from FFI, sizes read from a device, and offsets in
a serialized format. Memory-safety is decided by *who controls the size, index,
or lifetime*, so this set is what every sink verdict is judged against.

Record the source inventory in the ledger, noting which sources cross a trust
boundary per `THREAT_MODEL.md`.

### Step 2: Build the Sink Inventory

For each class in `references/memory_safety_docket.md`, run its grep patterns
across CODE_ROOT and record every hit as a candidate sink with `file:line`. Use
the structural index, when available, to rank and to resolve callers of a
size-contracted function — but the grep sweep is the mandatory floor for
membership, and the index never removes a candidate from it. A class with zero
sinks is recorded as `NO_SINKS` **with the patterns run**, never silently
omitted.

### Step 3: Trace Each Sink To A Verdict

Every sink gets exactly one of four verdicts, recorded in the ledger:

| Verdict | Meaning |
|---|---|
| `REACHABLE_UNSAFE` | An attacker-influenced size/index/lifetime reaches it with no sound bound. A finding |
| `NEUTRALIZED` | A checked bound, a safe API, a type invariant, or an allocator contract intervenes. **Record the neutralizer's `file:line`** — that citation is what makes a clean verdict mean anything |
| `UNREACHABLE` | The size/index is a constant or derived only from trusted state. Say what makes it trusted |
| `UNKNOWN` | The provenance crosses something you cannot resolve statically (a function pointer, an opaque callback, inline asm). Write a `NEEDS_RESEARCH` finding stating what would resolve it — never round `UNKNOWN` down to safe |

Habits that keep the verdicts honest, drawn from the traps in the docket:

- **Follow the integer, not the variable name.** An overflow that happens
  *before* the `malloc` (`n * size` wrapping) is the bug; the allocation looks
  innocent. Trace width, signedness, and truncation across every assignment.
- **Respect the allocator contract before shouting.** An OOB access that lands
  inside a documented over-allocation (`png_malloc(rowbytes + 48)`, a
  `+ SIMD_WIDTH` pad) is not a bug — this is the exact trap `/ray-arbiter`
  rule 11 will use to reject the finding, so check it here. The docket names the
  common padding contracts.
- **Track the lifetime, not just the pointer.** A use-after-free needs a free on
  one path and a use on another reachable after it; a double-free needs two frees
  with no intervening null. Note the freeing site and the using site as two
  `code_paths`.
- **Check the cast's provenance.** Type confusion needs a value reinterpreted as
  a type it was not, reachable from input — a downcast without a tag check, a
  union read of the wrong arm, a `void*` re-cast.
- **Framework/language guarantees count.** A Rust safe slice index panics (a DoS
  at worst, not memory corruption); the sink is `unsafe`, `get_unchecked`,
  `from_raw_parts`, FFI, or a `union`. Cite the guarantee when you rely on it.

### Step 4: Class-Specific Depth Passes

Work through the docket class by class. Its sections carry the detail that
decides validity — the integer-provenance rules for `intover`, the padding
contracts for `oob`, the freeing/using discipline for `uaf`, the format-string
taint rule, the uninitialized-read data-flow, and the systems-concurrency menu
(data races, lock-ordering, atomicity violations, non-monetary TOCTOU). Each
section ends with the reproduction hint: which sanitizer proves it
(`ASan` for spatial/temporal, `UBSan` for integer/UB, `TSan` for races), and
what evidence counts.

### Step 5: Exhaustive Call-Site Sweep For Contracted APIs

For any target function that documents a size or safety contract (a decoder
expecting the caller to allocate `n` bytes, a parser that writes `len`
attacker-controlled bytes), a repo-wide grep for its name is the mandatory floor
of candidate call-sites; the structural index only re-ranks them. Audit the
union: every call-site must be checked for whether it honors the contract
globally. A single caller that passes an unchecked length is the finding, even
when every other caller is correct — this is where real CVEs hide.

### Step 6: Write Findings and the Ledger

Follow `references/findings_contract.md`. The rules that decide whether a finding
survives here: **anchor at the sink** and include the source of the bad
size/index/lifetime as a second `code_paths` entry; **state the bound or contract
you ruled out**; and **hand `/ray-detonator` a concrete reproduction hint** —
which sanitizer, which input field to grow, and the expected sanitizer signature.
Send no payloads and compile nothing here.

### Step 7: Complete

Report findings by severity and class, sinks by verdict, classes with
`NO_SINKS`, classes `NOT_ASSESSED`, and every `UNKNOWN` sink with what would
resolve it. Do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Web/injection canon (SQLi, XSS, SSRF, deserialization, traversal) | `/ray-crucible` |
| Authentication, authorization, tenancy, session/JWT | `/ray-turnstile` |
| The target app's LLM integration (prompt injection, unsafe output) | `/ray-oracle` |
| Sandboxed reproduction under sanitizers, variant hunting | `/ray-detonator` |
| Adversarial validation (incl. SIMD/allocator-padding rule) and release viability | `/ray-arbiter`, `/ray-magistrate` |
| General correctness/perf/maintainability review of the same code | `/ray-loupe` |

Memory-unsafe *deserialization* (a native parser reached from input) can appear
both here and in `/ray-crucible`'s `DESER` class; report where you found it and
let `/ray-condenser` merge. Concurrency that creates value in money flows is
`/ray-turnstile`'s TOCTOU; systems data races that corrupt memory are here.
