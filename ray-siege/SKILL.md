---
name: ray-siege
description: >-
  Runs a live attack-and-fix loop against your own locally-running app: stands up a disposable instance, seeds canaries, dispatches the ray-reaver agent to break in for real, then ray-bulwark to fix the root cause — rebuild, re-attack with boundary variants, repeat until clean.
  Use when you have a runnable app and want proof-by-exploitation plus a fix. Authorization and a disposable local target are mandatory — never against production or third-party systems.
---

# Siege (/ray-siege)

## System Goal

Live Exploitation Orchestrator. Track B of a complete audit: it proves findings by
actually exploiting a disposable local instance and then fixes them, closing the
loop that static analysis alone cannot. It orchestrates two agents — `ray-reaver`
(break in) and `ray-bulwark` (fix) — around a rebuild/re-attack cycle.

## Command Definition

- **Command:** `/ray-siege [--target=<local-url-or-dir>] [--from-findings] [--max-rounds=<n>] [--fix]`
- **Description:** Attack+fix loop against a disposable local app.
- **Parameters:**
  - `--target`: the locally-running app (URL) or a directory to build+run
    disposably. Must be local/loopback.
  - `--from-findings`: seed the attack from existing `workspace/findings/` (prove
    the static findings live) rather than hunting fresh.
  - `--max-rounds`: cap the attack→fix→re-attack cycles (default 3).
  - `--fix`: allow `ray-bulwark` to write fixes (default on); off = attack only.

## Input/Output Contract

- **Reads**: the local target; `workspace/findings/` (with `--from-findings`);
  the arsenal manifest of installed tools.
- **Writes**: proven findings to `workspace/findings/<uuid>.json` (each with a
  canary-backed `repro_output`); `ray-bulwark`'s fixes as commits on a working
  branch; a siege log under `workspace/siege/`.
- **Preconditions**: a disposable local target and authorization to attack it.
- **Idempotency**: each round is logged; a clean round (no new break-in) ends the
  loop.

## Instructions

### Step 0 — Authorization & isolation gate (MANDATORY)

Siege attacks for real. Before anything:
1. Confirm the target is a **disposable, local/loopback** instance the user owns —
   never production, never a third-party system, never a shared environment.
2. Confirm authorization explicitly. If the target is remote, not owned, or you
   cannot confirm disposability, STOP.
3. Stand up the instance in isolation (a throwaway container/dir), and **seed
   canaries** — unique marker records/files/tokens whose exfiltration or
   modification is unambiguous proof of a break-in.

### Step 1 — Attack (dispatch ray-reaver)

Dispatch the `ray-reaver` agent (red team). It recalls prior attack memory, checks
the installed arsenal, and drives tools through a gated runner (loopback-only,
non-destructive) to break in for real. Every break-in must be proven by a canary —
a reflected marker, an exfiltrated canary record, an unauthorized `200` on a canary
resource. Reaver performs only the local slice (initial access + local escalation)
and reports the rest of the kill chain as impact. Each proven break-in becomes a
finding with the canary evidence in `repro_output`.

### Step 2 — Fix (dispatch ray-bulwark, when `--fix`)

For each proven finding, dispatch `ray-bulwark` (blue team): it reads the finding,
finds the root cause and every sibling occurrence, writes the minimal idiomatic fix
(one finding, one commit), checks no secret leaked, and proposes the CI gate that
would have caught it.

### Step 3 — Rebuild → Re-attack → repeat

Rebuild the instance with the fix, then RE-ATTACK: re-run the original exploit plus
**≥3 boundary-mutated variants** (the same variant discipline `ray-detonator`
enforces) to be sure the fix addresses the class, not just the exact PoC bytes.
Loop until a clean round (no break-in) or `--max-rounds`. Record each round in the
siege log.

### Step 4 — Hand off

Proven findings carry canary evidence into the normal pipeline (`ray-gauge` scores
them, `ray-chronicle` reports them). A vector reaver could NOT break becomes an
insight for the next static pass. Reaver's kill-chain impact notes are the
detection targets `ray-warden`/`ray-vigil` hunt for.

## Safety

- Local, disposable, authorized targets ONLY — the gate in Step 0 is absolute.
- All tool calls are loopback-only and non-destructive against the disposable
  instance; never touch anything outside it.
- Never exfiltrate real data — canaries are the only thing proven moved.

When complete, notify the user.
