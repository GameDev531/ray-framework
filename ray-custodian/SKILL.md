---
name: ray-custodian
description: >-
  Audits how a web surface protects personal data: TLS and response headers, cookie flags, consent and lawful basis, retention, data-subject rights, and third-party egress of PII (LGPD/GDPR).
  Use when the target serves a website, portal, or browser-facing app that collects or displays personal data and you need privacy/exposure findings written to workspace/findings/.
  Don't use for server-side injection classes (use ray-crucible), authentication and tenancy (use ray-turnstile), or database-layer exfiltration controls (use ray-vault).
---

# Custodian (/ray-custodian)

## System Goal

Personal-Data Custodian. Audits the browser-facing surface and the
personal-data lifecycle behind it, emitting standard Ray findings for every
control that is absent, weak, or unverifiable on the pinned snapshot.

Privacy defects are invisible to an auditor looking only for memory corruption
or injection: a `Set-Cookie` without `HttpOnly`, an analytics SDK firing before
consent, an export endpoint with no ownership check — all are perfectly valid
code. They are defects only against an external obligation. This stage carries
that obligation set so the rest of the pipeline does not have to.

## Command Definition

- **Command:** `/ray-custodian`
- **Description:** Audits web-surface exposure controls and the personal-data
  lifecycle (collection → storage → egress → retention → erasure), writing
  findings plus a control ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: the `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--regime <lgpd|gdpr|both>`: which regime to score against. Absent → `both`
    (conservative: any obligation existing under either regime is checked, and
    the finding names which one it comes from).
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json` (`pass_number`, `active_snapshot`);
  `workspace/plan.json` (optional, ordering hint only); `workspace/kb/THREAT_MODEL.md`
  and `workspace/kb/entities/*.md` (optional); this skill's `references/*.md`;
  target source (edge and proxy config, HTTP middleware, cookie writes,
  templates, client bundles, ORM models and migrations, IaC/DNS descriptors);
  `workspace/ledgers/ray-custodian.json` from the previous pass, if present.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-custodian.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-custodian_pass_${N}.json` before overwriting.
- **Preconditions**: target files readable. No network access to a live site is
  required or assumed — this stage audits the code and configuration that
  PRODUCE the surface, never a deployed host.
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges duplicates). The ledger is archived per pass and then
  deterministically overwritten, so re-running against an unchanged snapshot
  reproduces an equivalent ledger.

## Reference Files

Read these as the workflow calls for them rather than all at once — that is
what keeps this stage cheap on context and precise on judgement.

| File | Read it | What it carries |
|---|---|---|
| `references/privacy_docket.md` | before Step 2, and again per obligation in Steps 5–7 | Data classification taxonomy, lawful bases (LGPD art. 7/11, GDPR art. 6/9), minimization, consent quality tests, rights matrix, retention, incident deadlines, transfers, third-party egress, and the privacy control-ledger ids |
| `references/web_surface_baseline.md` | before Steps 3–4 | Where each header can be set (five layers), the graded TLS/header/cookie baseline, CSP in depth, grading rules, and the exposure control-ledger ids |
| `references/findings_contract.md` | before writing the first finding, and again at Step 8 | Findings schema, the four computed fields, this domain's CWE set, evidence discipline, severity defaults, and the ledger format |

The dockets are the authority on what each obligation requires. Score controls
from them, not from recollection — that is the whole reason they are separate
files you can re-read mid-pass.

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

This is a CODE-READING stage, so the findings-only skip does not apply. This
skill's `references/*.md` sit beside `SKILL.md` — never under CODE_ROOT, never
under `workspace/`.

### Step 1: Load Context

Read `pass_number` and `active_snapshot`, resolve the ISO 8601 timestamp, and
hold `snapshot_id` for `discovery_commit`. Absent or unpinned → DEGRADED mode;
do not stop. Read `THREAT_MODEL.md` for trust boundaries, then both dockets.

### Step 2: Build the Personal-Data Inventory

You cannot audit the protection of data you have not enumerated, so this comes
first and everything after keys off it.

Sweep schemas, migrations, ORM models, DTOs, validation schemas, GraphQL SDL,
form markup, and analytics calls for personal-data fields; classify each using
`privacy_docket.md` §1 (the field-name patterns to grep, including the
Portuguese ones real Brazilian codebases mix in, are listed there); then trace
each field's lifecycle — where it is collected, stored, sent onward, and
deleted or anonymized, or that no deletion path exists.

Record what you could not determine as `UNKNOWN` with the reason. `UNKNOWN` is a
legitimate outcome; a silent omission is not. If the sweep finds no personal
data at all, record the inventory control `NOT_APPLICABLE` with the evidence and
still run Steps 3–4 — transport and headers protect sessions, not just PII.

### Step 3: Transport and Response Headers

Find the layer that actually sets headers **before** judging anything absent.
`web_surface_baseline.md` §0 lists the five layers in order of authority (CDN →
proxy → framework middleware → per-route code → meta tags) with the grep
starters; §1–§2 carry the graded baseline for HTTPS enforcement, HSTS, TLS
versions, CSP, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, framing,
caching, and mixed content.

Grade rather than detect: a CSP containing `unsafe-inline` in `script-src` is
`PARTIAL`, not `PRESENT`. §4 explains how to judge a policy properly, including
which shapes look wrong but are deliberate.

### Step 4: Cookies and Client Storage

Score every `Set-Cookie` write — framework session config, `res.cookie(...)`,
`document.cookie`, and the auth library's defaults — against
`web_surface_baseline.md` §3: `HttpOnly`, `Secure`, `SameSite`, `Domain`/`Path`
scope, lifetime and revocation, prefixes, and signing. Personal data in
`localStorage` belongs here; a *credential* in `localStorage` belongs to
`/ray-seam`.

### Step 5: Consent, Lawful Basis, and Purpose

The mechanical, falsifiable test is **ordering**: does any non-essential
tracker load, or non-essential cookie get written, before a consent decision
exists? Trace load order through `<head>` partials, tag-manager containers,
layout components, and analytics initializers, and anchor the finding at the
line that injects the script.

`privacy_docket.md` §2 carries the lawful bases and the tests for each
(including that sensitive data cannot rest on legitimate interest), §3 the
minimization and purpose-limitation tests, and §4 the consent-quality checklist.

### Step 6: Retention, Erasure, and Rights

Look for any mechanism that actually deletes or anonymizes — a job, a TTL, a
bucket lifecycle rule — and remember that logs and backups are storage too.
Then audit each data-subject-rights path.

`privacy_docket.md` §5 has the rights matrix for both regimes and, importantly,
the section on **rights endpoints as exfiltration primitives**: an export route
without an ownership check is a bulk personal-data dump, and should be reported
as an access-control finding as well so `/ray-detonator` can prove it. §6 has
the retention tests.

### Step 7: Egress and Exposure

Check personal data in URLs and query strings, forwarding to analytics, session
replay, error trackers and inference APIs, dangling DNS delegations, and
unanonymized production copies in non-production environments.
`privacy_docket.md` §9 lists what each integration class typically leaks and the
scrubbing configuration to check; §7 covers the incident-detection capability
and §8 international transfers.

### Step 8: Write Findings and the Ledger

Follow `references/findings_contract.md`. In short: anchor every finding at a
line you actually read; when a control is missing everywhere, anchor at the
composition root and list where you looked; search the whole chain before
declaring absence, and use `NEEDS_RESEARCH` when the control could plausibly
live in infrastructure outside this repository. One control, one finding.

The ledger is what makes the *absence* of a finding meaningful — every control
id from both dockets appears in it exactly once, including the ones that passed
and the ones you could not determine.

### Step 9: Complete

Report the finding count by severity, controls by state, the size of the
personal-data inventory, and every `UNKNOWN` with its blocking reason. Do not
print finding bodies or the ledger into chat — they are on disk, and downstream
stages read them from there.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| XSS, CSRF, SQLi, SSRF and the rest of the input canon | `/ray-crucible` |
| Authentication, sessions, tenancy, authorization | `/ray-turnstile` |
| Tokens in `localStorage`, CORS, log hygiene, error leakage | `/ray-seam` |
| Rate limiting on rights/export endpoints, audit-log coverage | `/ray-sentry` |
| Encryption at rest, database privileges, backups | `/ray-vault` |
| Environment isolation, deploy pipeline, TLS termination point | `/ray-citadel` |

Overlap is expected, not an error: write the finding you can evidence and let
`ray-condenser` deduplicate.
