---
name: ray-seam
description: >-
  Audits the trust seam between client and server: error leakage, backend-side validation, mass assignment, CORS, client-side storage of credentials, secrets in frontend bundles, sensitive data in logs, timeouts and payload limits, ReDoS, cache poisoning, postMessage, and client-supplied prices or quantities.
  Use when the target has a browser or mobile client talking to a backend and you need application-layer trust-boundary findings written to workspace/findings/.
  Don't use for injection sinks (use ray-crucible), auth and tenancy (use ray-turnstile), or rate limiting and monitoring (use ray-sentry).
---

# Seam (/ray-seam)

## System Goal

Trust-Seam Auditor. Audits the line where the client stops and the server
starts — the place where developers accidentally treat browser-side code,
browser-side storage, and browser-supplied values as if they were part of the
system they control.

Every defect in this stage has the same shape: **a decision that must be made on
the server is being made, kept, or trusted on the client** — or the reverse,
**something that must stay on the server is being handed to the client**. Price
in the request body. Role in a token nobody verifies. Session token in
`localStorage`. Service key in the bundle. Stack trace in the 500 response.
Validation only in the form.

That single frame is why these otherwise unrelated defect classes belong in one
stage: they are found by asking one question of each value that crosses the
boundary, in both directions.

## Command Definition

- **Command:** `/ray-seam`
- **Description:** Audits client/server trust-boundary defects across backend
  handlers, frontend code, logging, caching, and resource limits, writing
  findings plus a control ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: the `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json` (`pass_number`, `active_snapshot`);
  `workspace/plan.json` (optional, ordering hint only);
  `workspace/kb/THREAT_MODEL.md` and `workspace/kb/entities/*.md` (optional);
  this skill's `references/*.md`; target source (backend handlers and
  middleware, validation schemas, serializers, logger configuration, frontend
  source and build configuration, service workers, cache and CDN configuration);
  `workspace/ledgers/ray-seam.json` from the previous pass, if present.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-seam.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-seam_pass_${N}.json` before overwriting.
- **Preconditions**: target files readable. Where a built bundle is not in the
  snapshot, audit the build configuration and source instead and say so — never
  claim to have inspected a bundle you did not read.
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges). The ledger is archived per pass and then
  deterministically overwritten.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/seam_docket.md` | before Step 2, then per area through Step 3 | Every control this stage checks, organized by area: validation, mass assignment and serialization, error handling and fail-open paths, client storage and bundles, CORS and cross-origin messaging, logging hygiene, resource limits, caching, and the client-supplied-value table — each with the expected shape, the failing shape, and where it hides |
| `references/findings_contract.md` | before writing the first finding, and again at Step 4 | Findings schema, the four computed fields, this domain's CWE set, evidence discipline, severity defaults, and the ledger format with its control ids |

The docket is organized by area so you can read one section at a time as you
sweep, rather than loading the whole thing up front.

## Instructions

### Step 0: Locator Resolution (Snapshot-Aware Path Handling)

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

CODE-READING stage, so the findings-only skip does not apply. If you need to
build the frontend to inspect a bundle, build in a private shadow copy per
step 4 — though auditing the source and build configuration is usually enough to
establish that a secret is referenced from client code. This skill's
`references/*.md` sit beside `SKILL.md`, not under CODE_ROOT.

### Step 1: Load Context and Map the Seam

Read `pass_number` and `active_snapshot`, resolve the timestamp, hold
`snapshot_id`, read the threat model. Then map the seam itself — everything
after is scored against this map:

1. **Every request handler** and the shape it accepts (route, method, body
   schema, or the absence of one).
2. **Every response serializer** and the shape it emits.
3. **What the client holds**: tokens, personal data, feature flags, prices,
   permissions, identifiers.
4. **What the client sends back that the server uses in a decision.** This list
   is the highest-value artifact of the stage: every entry is a candidate
   finding until you locate the server-side revalidation.

### Step 2: Sweep The Docket, Area By Area

Work through `references/seam_docket.md`. Its areas, in the order that tends to
compound best:

| § | Area | The question it answers |
|---|---|---|
| 1 | Server-side validation | Is every entrypoint schema-validated, strictly, in the right order? |
| 2 | Mass assignment and serialization | Can the client write fields it should not, or read fields it should not? |
| 3 | Error handling | Do errors leak internals — and, more importantly, does anything **fail open**? |
| 4 | Client storage and bundles | Are credentials or private keys sitting where any script or any user can read them? |
| 5 | CORS and cross-origin messaging | Can another origin read authenticated responses or inject messages? |
| 6 | Logging hygiene | Is anything written that must never be written? |
| 7 | Resource limits | Can one request consume unbounded time, memory, or connections? |
| 8 | Caching | Can one user's response reach another? |

Section 3's fail-open sweep deserves particular attention: it is the reason
OWASP added *Mishandling of Exceptional Conditions* as A10:2025, and it is
invisible to a reviewer reading the happy path. Trace what happens when each
security-relevant call throws or times out.

### Step 3: Resolve The Client-Supplied Values

Walk the list you built in Step 1.4 against the table in `seam_docket.md` §9,
which gives the correct server behavior for each value class — prices and
totals, quantities and stock, identity and role, timestamps and state, file
metadata, cursors and sort fields, callback URLs, webhook contents.

Each entry with no server-side recomputation or revalidation is a finding
anchored at the handler line that consumes it. Record every value in the ledger
with `revalidated` true, false, or unknown, so the ones that are fine are on
record too.

### Step 4: Write Findings and the Ledger

Follow `references/findings_contract.md`. The rule specific to this domain:
**anchor at the server-side line that trusts the client, not at the client line
that sends the value.** The client is not the defect; the trust is. And trace
the whole chain before declaring validation absent — a global middleware, a
framework default like strong parameters or model binding, a gateway schema, or
a base serializer may already cover it.

### Step 5: Complete

Report findings by severity, controls by state, the count of client-supplied
values that are not revalidated, and every `UNKNOWN` with its blocker. Do not
print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Injection sinks, including a sort parameter reaching SQL and open redirect | `/ray-crucible` |
| Authentication, authorization, IDOR, tenancy | `/ray-turnstile` |
| Cookie flags, CSP, consent, retention, personal-data classification | `/ray-custodian` |
| Rate limiting, exposed internal endpoints, alerting, audit-log coverage | `/ray-sentry` |
| Database privileges and encryption | `/ray-vault` |
| Environment separation, CDN and infrastructure configuration | `/ray-citadel` |

Two overlaps are intentional. **Mass assignment** appears here and in
`/ray-turnstile`; when the field is `role` or `tenant_id` both stages may report
it. **Log hygiene** (what must never be written) is here, while log *coverage*
(what must always be written) is `/ray-sentry`'s. `ray-condenser` merges.
