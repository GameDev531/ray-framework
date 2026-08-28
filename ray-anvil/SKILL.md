---
name: ray-anvil
description: >-
  Generates a minimal root-cause patch for a confirmed finding on a private shadow of the pinned snapshot, then drives ray-detonator --reattack (original PoC + boundary variants) to verify the fix holds. Use when a viable/reproduced finding needs a proposed fix in the static pipeline.
  Don't use for the live attack+fix loop (that is ray-siege/ray-bulwark) or for discovering new findings.
---

# Anvil (/ray-anvil)

## System Goal

Static-Track Patcher. The static pipeline's fix stage: for a confirmed finding, it
writes a minimal, idiomatic patch on a **private shadow** of the pinned snapshot,
re-attacks it through `ray-detonator --reattack`, and records a `patch_status` that
is only `VERIFIED_SECURE` when the re-attack gate (INV-1) is satisfied. This is the
caller `ray-detonator` already expects (it accepts `--snapshot_pinned=false` "set by
ray-anvil during re-attack on a patched shadow") and the stage `ray-compass`
references for its retry accounting.

## Command Definition

- **Command:**
  `/ray-anvil [--finding_id=<uuid>] [--target_root=<path>] [--snapshot_root=<path>] [--snapshot_id=<id>] [--state_root=<path>]`
- **Description:** Proposes and verifies a patch for a confirmed finding.
- **Parameters:**
  - `--finding_id`: the finding to patch (default: every VIABLE + reproduced
    finding without a terminal `patch_status`).
  - `--snapshot_root`/`--snapshot_id`/`--state_root`/`--target_root`: as Block A.
    Absent → LEGACY mode (operate against the live tree; the carve-out `ray-compass`
    references).

## Input/Output Contract

- **Reads**: `workspace/findings/<uuid>.json` (VIABLE + reproduced findings); the
  target source under `CODE_ROOT`; the owning domain docket's safe-pattern half.
- **Writes**: a patch file (`workspace/patches/<uuid>.diff`); updates the finding
  in-place with `patch_status`, `patch_base_snapshot`, and history. Drives
  `ray-detonator --reattack` which writes `reattack_*` fields. **Never writes under
  `CODE_ROOT`** — the patch is applied to a private shadow (`mktemp -d` copy),
  sentinel-exempt per Block A step 1a.
- **Preconditions**: at least one finding with `production_viability` VIABLE/
  CONDITIONAL_VIABLE and `repro_status` reproduced/statically_confirmed.
- **Idempotency**: re-running on a finding with a terminal `patch_status` and an
  unchanged snapshot is a no-op; a snapshot change re-verifies.

## Instructions

### Step 0 — Locator Resolution

Follow Block A (`ray-prospector/SKILL.md`). This stage READS the pinned snapshot but
MUTATES only a private shadow: copy `CODE_ROOT` to a `mktemp -d` shadow, apply the
patch there, and pass that shadow to `ray-detonator` as `--target_root`
(authoritative, sentinel-exempt) with `--snapshot_pinned=false`. Never write under
the read-only pinned `CODE_ROOT`.

### Step 1 — Select and understand the finding

Load the finding. Read its `code_paths`, `description` (root cause), `repro_hints`,
and the reproduction evidence. Read the owning domain docket's safe-pattern half so
the patch matches the framework's recommended shape (parameterize, encode for the
sink context, add the ownership check, pin the algorithm, bound the buffer…).

### Step 2 — Write the minimal root-cause patch (on the shadow)

Patch the **root cause and every sibling occurrence of the same class** — not just
the exact bytes the PoC used (over-narrow patches that guard the PoC are the
dominant failure mode; Step 3's variant re-attack exists to catch them). Keep the
change minimal and idiomatic. Write it to `workspace/patches/<uuid>.diff` and apply
it to the shadow. Never disable a test or weaken a check to make it pass.

### Step 3 — Re-attack to verify (INV-1 gate)

Invoke `ray-detonator --reattack --finding_id=<uuid> --target_root=<shadow>
--snapshot_pinned=false`. Detonator re-runs the original PoC PLUS ≥3 boundary
variants against the patched shadow and writes `reattack_status`/`reattack_variants`.
Set `patch_status` from the result, obeying the schema's `VERIFIED_SECURE` gate:
- `VERIFIED_SECURE` ONLY when `reattack_status == failed_to_bypass` AND ≥3 variants
  all `triggered=false` (INV-1). Never persist `VERIFIED_SECURE` otherwise.
- `VERIFICATION_FAILED` if a variant bypassed the patch → the class is not fixed;
  return to Step 2.
- `VERIFICATION_INCOMPLETE` if the baseline changed or the variant set was
  insufficient.
Record `patch_base_snapshot` = the SNAPSHOT_ID the patch was built against, and a
`patcher` history entry.

### Step 4 — Hand off

A `VERIFIED_SECURE` finding carries its `workspace/patches/<uuid>.diff` into
`ray-chronicle`'s report as a proposed fix. The patch is a **proposal on a shadow** —
`ray-anvil` never applies it to the user's live tree; the user reviews and applies
it. (For an apply-and-commit loop against a running app, that is `ray-siege` +
`ray-bulwark`, Track B.)

## Safety

- The patch lives on a private shadow and in `workspace/patches/` — never applied to
  `CODE_ROOT` or the user's live tree by this skill.
- `VERIFIED_SECURE` is gated by the re-attack (INV-1); never claim it without ≥3
  clean variants.
- Never weaken a test or check to make a re-attack pass.

When complete, notify the user.
