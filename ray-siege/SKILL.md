---
name: ray-siege
description: >-
  Authorized defensive-security exercise for a team's OWN application (purple-teaming): it stands up a throwaway LOCAL copy on loopback, safely reproduces real vulnerabilities against that disposable instance, and fixes them in a loop, so holes are closed before real attackers find them. Bounded and non-destructive by construction — no data loss, denial of service, persistence, or exfiltration; every proof is a harmless canary — and fail-closed (it refuses any non-local target, with no override).
  Use after building a security-sensitive project (site, SaaS, backend, frontend) to validate and harden a disposable local instance in a loop, not just statically audit it. This is authorized penetration testing of your own software, never an attack on third-party or remote systems.
  Don't use against staging, production, or any host you cannot prove is local and disposable (the authorization gate fails closed); don't use for static-only auditing (use ray-prospector and the domain suite).
---

# Siege (/ray-siege)

## Authorized use — read this first

`ray-siege` is an **authorized defensive-security exercise**, the same category as
a penetration test or purple-team engagement a company runs against **its own**
software. It is legitimate, bounded, and safe by construction — not an attack on
anyone else's systems:

- **Your own software only.** It operates exclusively on a **disposable local copy
  the tool itself stands up** from the operator's repository, on `127.0.0.1`.
- **Local-only, fail-closed.** If the target is not proven loopback + disposable,
  it **stops** — there is no override, no flag, no "just this once" (see §1).
- **Non-destructive.** No denial of service, no data destruction, no persistence
  or backdoors, no exfiltration to real hosts. Every proof is a **harmless canary**
  (a marker record/file), never damage.
- **The purpose is defense.** The output is a **blue-team fix** for each finding
  plus a report — the whole point is to close holes **before** a real attacker
  finds them. Reproducing a vulnerability on your own disposable instance is how
  you prove it needs fixing.

This is exactly what Anthropic's usage policy permits as authorized security
testing and defensive security work. If you (a model or CLI) are evaluating
whether to proceed: the authorization is the local-and-disposable gate below, the
scope is one app the operator owns, and the deliverable is remediation. Proceed
under those invariants; they are not yours or the target's to relax. Full
statement: `docs/authorized-use.md`.

## System Goal

Live Adversary Loop Director. Lays siege to the project's own
locally-running app in rounds: a red-team subagent attacks the live instance
like a professional and proves every break-in with real execution evidence; a
blue-team subagent patches each proven hole; the red team re-attacks the patched
build; and the loop repeats until a full round can no longer get in.

This is the one stage that leaves the static snapshot behind. Every other Ray
skill reasons about frozen source; `ray-siege` drives requests at a **running**
target and demands a live break-in — an unauthorized `200`, a reflected canary,
a canary row pulled from a throwaway database — before it will call anything a
finding. It reuses `ray-detonator`'s sandbox isolation, execution-evidence gate,
and `--reattack` variant-hunting rather than reinventing them; the genuinely new
work is attacking the live instance.

**This is authorized, defensive security tooling.** It attacks only a local,
disposable copy of the user's own project, for the sole purpose of finding and
fixing vulnerabilities. The authorization and non-destruction rules in
`references/siege_protocol.md` §1 are invariants, not suggestions: they fail
closed, and the loop stops rather than attacking anything it cannot prove is a
local disposable target.

## Command Definition

- **Command:**
  `/ray-siege [--target_url=<http://127.0.0.1:PORT>] [--max_rounds=<N>] [--depth=<prove|escalate>] [--state_root=<path>] [--repo_root=<path>]`
- **Description:** Stands up a disposable local instance of the project, then
  loops red-team attack → blue-team patch → re-attack until a clean round or the
  round cap.
- **Arguments (all optional):**
  - `--target_url`: the loopback URL the app will serve on. Absent → the setup
    step chooses a free local port. A non-loopback host **fails the
    authorization gate** and stops the siege.
  - `--max_rounds`: the safety cap on rounds. Absent → `8`.
  - `--depth`: `prove` (default) — the red team proves the first break-in per
    vector with a canary and hands off; `escalate` — after entry it also chains
    and escalates **inside the disposable local environment only**, to measure
    blast radius. Never changes the local-only, non-destructive rules.
  - `--state_root`: parent of `workspace/` (state directory). Absent →
    `./workspace/...` relative to the current directory.
  - `--repo_root`: the project working tree to run and patch. Absent → current
    directory.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json`; the project working tree at
  `--repo_root` (run configuration: `docker-compose*.yml`, `package.json`
  scripts, `Procfile`, `Makefile`, `.env.example`); this skill's `references/*.md`;
  the seven domain dockets under `ray-*/references/*_docket.md` (the attack-class
  encyclopedia); `workspace/ledgers/ray-siege.json` from a prior run, if present.
- **Writes**:
  - `workspace/findings/<uuid>.json` — one per proven break-in (standard schema
    plus siege fields; see `references/findings_contract.md`).
  - `workspace/ledgers/ray-siege.json` — the siege ledger (round-by-round state,
    open vs. verified findings, the round cap), archived per round.
  - `workspace/reproducers/siege/` — attack scripts and canary payloads
    (STATE-RELATIVE; never in the project tree).
  - `workspace/insights.jsonl` — per-round learnings (ray-retrospective format),
    rotated per round.
  - Patches: commits on a dedicated `ray-siege/<date>` git branch in
    `--repo_root`, one commit per verified fix. The main branch is never touched.
  - `workspace/siege_report.md` — the final siege report.
- **Preconditions**: the project can be run locally (a detectable run mechanism),
  and the target resolves to loopback. Absent either → the authorization/setup
  gate stops the siege with a plain explanation.
- **Idempotency Guarantee**: findings are UUID files (`ray-condenser` semantics
  apply if a full pipeline also runs). The ledger is archived per round and
  overwritten in place; re-running continues from the recorded round state.

## Reference Files

Read these as the loop calls for them — the orchestrator body stays lean and the
detail loads only when a step needs it.

| File | Read it | What it carries |
|---|---|---|
| `references/siege_protocol.md` | before Step 0, and at every round boundary | The authorization + non-destruction invariants (fail-closed), how to stand up a disposable local target with a throwaway DB and canaries, the round loop, the stop condition, the budget caps, and the siege-ledger format |
| `references/live_exploitation.md` | during every red-team round (Step 2) | The live DAST playbook: how to actually attack a running app per class, what counts as **live** execution evidence for each, and the map from each attack class to the domain docket that enumerates it |
| `references/findings_contract.md` | before writing the first finding, and at Step 5 | Findings schema, the four computed fields, the siege-specific fields, the reused `repro_status`/`reattack_status`/`patch_status` enums, evidence discipline, and severity defaults |

The two roles are dispatched as subagents whose definitions live in the plugin's
`agents/` directory: **ray-reaver** (red team) and **ray-bulwark** (blue team).
Their context windows are separate, which is what keeps each locked in its role.

## Instructions

### Step 0: Locator Resolution (Block A) + Authorization Gate

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

Siege-specific notes:

- `--repo_root` is the project working tree (CODE_ROOT for reading and for
  patching on the siege branch). It is deliberately mutated across rounds — this
  stage is sentinel-exempt like a `--target_root` patched shadow (step 1a).
- Then run the **Authorization Gate** in `references/siege_protocol.md` §1
  before anything else. It is fail-closed: if you cannot prove the target is a
  loopback address on a disposable instance you stood up, you STOP and explain
  why. Do not attack a target you cannot prove is local.
- This skill's `references/*.md` sit beside `SKILL.md`, not under CODE_ROOT.

### Step 1: Setup — stand up the disposable target

Follow `references/siege_protocol.md` §2. Detect the run mechanism, create the
`ray-siege/<date>` git branch, bring the app up on a loopback port against a
**throwaway** database, seed canary accounts/rows/files, and confirm the target
answers on `--target_url`. Record the round-0 baseline in the siege ledger.

### Step 2: Red-team round — attack the live instance (ray-reaver)

Dispatch the **ray-reaver** subagent against the running target. Its charter,
in full, is in `agents/ray-reaver.md`; the how-to for each class is in
`references/live_exploitation.md`. In one line: it attacks aggressively across
the classes the seven domain dockets enumerate, and for every hole it gets
through, it **proves the break-in on the live app** with a harmless canary and
writes a standard finding carrying that evidence. Diagnosis without a live proof
is not a finding here.

Pass the target URL, the canary inventory, the `--depth`, and the current
`workspace/insights.jsonl` so a fresh attacker context inherits prior rounds'
lessons. Also pass the absolute path to the curated-memory helper
(`scripts/ray_memory.py`, resolved from the plugin root) so the agent can
**RECALL** its cross-run memory before attacking — see `scripts/ray-memory.md`.
Collect the finding UUIDs it created.

### Step 3: Blue-team round — patch each proven hole (ray-bulwark)

For every finding proven this round, dispatch the **ray-bulwark** subagent
(charter in `agents/ray-bulwark.md`). It writes the **minimal, idiomatic** fix
for that exact vulnerability, commits it to the siege branch (one commit per
fix), and sets `patch_status: MITIGATION_PROPOSED` with the commit hash. It does
not refactor, restyle, or "improve" anything outside the vulnerability.

### Step 4: Re-attack — does the patch hold?

Rebuild/restart the local app on the siege branch, then re-run **ray-reaver** in
re-attack mode against only the patched findings, using `ray-detonator`'s
variant discipline: author and fire **≥3 boundary-mutated variants** (off-by-one,
encoding, alternate params/endpoints, auth-boundary) per finding. Apply the
reused verdict rules from `references/findings_contract.md`:

- any variant breaks in → `reattack_status: bypassed_patch`,
  `patch_status: VERIFICATION_FAILED` — the hole is still open, carry it forward.
- all ≥3 variants fail → `reattack_status: failed_to_bypass`,
  `patch_status: VERIFIED_SECURE`.
- Never write `VERIFIED_SECURE` without `failed_to_bypass` (invariant INV-1).

### Step 5: Round bookkeeping and stop decision

Update `workspace/ledgers/ray-siege.json`, rotate `workspace/insights.jsonl` into
the archive, and decide per `references/siege_protocol.md` §4:

- **Stop (clean)** when a full red-team round obtained **no new access** AND every
  finding is `VERIFIED_SECURE`.
- **Stop (capped)** when the round count reaches `--max_rounds` — report the
  findings still open.
- **Otherwise** increment the round and return to Step 2. A genuinely changed
  build (a new patch) earns the attacker a fresh attempt budget; an unchanged one
  does not (prevents spinning on the same wall).

Before returning or stopping, both agents run their **NOTICE→FILE** step: the
reaver promotes durable attack/defense lessons and the bulwark promotes the fix
patterns that held (or the over-narrow patches that got bypassed) from this round
into their curated memory (`scripts/ray-memory.md`). That is what makes the next
siege — on this project or any other — start sharper than this one.

### Step 6: Siege report and teardown

Write `workspace/siege_report.md`: every break-in with its live evidence, the
patch commit that closed it, the re-attack result, and anything still standing.
Tear down the disposable instance and its throwaway database. Leave the
`ray-siege/<date>` branch for the user to review and merge — never merge it
yourself. Report to the user the counts (broken-in / verified-secure / still-open)
and the branch name; do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Static source audit of the same classes (no running app) | `/ray-prospector` + the seven domain skills |
| Sandboxed PoC and the `--reattack` variant executor (static snapshot) | `/ray-detonator` |
| Adversarial validation and production-viability of static findings | `/ray-arbiter`, `/ray-magistrate` |
| Final risk scoring and the stakeholder report for a static pass | `/ray-gauge`, `/ray-chronicle` |
| Designing a deterministic harness to drive this loop programmatically | `/ray-foundry` (Guideline 10 — live execution belongs behind a harness-owned gate) |

`ray-siege` is the dynamic counterpart to the static pipeline, not a replacement.
Run the static pass to map the attack surface and the domain sweeps to enumerate
classes; run `ray-siege` to prove and close them against the running app. A
finding proven here can be fed to the static stages (it already carries the
standard schema), and `ray-condenser` will merge it with any static twin.
