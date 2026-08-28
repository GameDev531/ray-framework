---
name: ray-crucible
description: >-
  Sweeps the codebase for the untrusted-input vulnerability canon — SQL injection, XSS, CSRF, SSRF, deserialization, path traversal, unsafe upload, open redirect, prototype pollution, timing leaks, and vulnerable dependencies — by inventorying sinks and tracing each back to a source.
  Use when you need a systematic OWASP-class sweep of a web or API codebase with findings written to workspace/findings/.
  Don't use for authentication and tenancy (use ray-turnstile), privacy obligations and headers (use ray-custodian), or infrastructure architecture (use ray-citadel).
---

# Crucible (/ray-crucible)

## System Goal

Untrusted-Input Auditor. Inventories every dangerous sink in the codebase,
traces each one back toward a request-controlled source, and reports the pairs
where nothing safe intervenes.

The method matters more than the class list. Scanning for "vulnerable-looking
code" produces noise; enumerating sinks and then proving or disproving a
source→sink path produces findings that survive `/ray-arbiter` and that
`/ray-detonator` can reproduce. This stage is sink-driven by construction.

`/ray-prospector` audits whatever the plan targets, with memory safety and
logical correctness in view. `/ray-crucible` runs an exhaustive sweep of the web
vulnerability canon regardless of what the plan targets. The overlap is
deliberate; `/ray-condenser` merges the results.

## Command Definition

- **Command:** `/ray-crucible`
- **Description:** Performs a sink-driven sweep for injection, XSS, CSRF, SSRF,
  deserialization, traversal, upload, redirect and related classes, writing
  findings plus a sink ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: the `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--classes <csv>`: restrict the sweep to named classes (e.g.
    `sqli,xss,ssrf`). Absent → every class in `references/injection_docket.md`.
    A restricted run MUST record the skipped classes as `NOT_ASSESSED` in the
    ledger — never let a narrowed run look like a clean one.
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json` (`pass_number`, `active_snapshot`);
  `workspace/plan.json` (optional — it may reorder the sweep, never narrow it);
  `workspace/kb/THREAT_MODEL.md` and `workspace/kb/entities/*.md` (optional);
  `workspace/kb/structural_index/manifest.json` and
  `workspace/helpers/query_structural_index.py` (optional, HINT-only: they rank
  and resolve callers, they never decide membership); this skill's
  `references/*.md`; target source, templates, dependency manifests and
  lockfiles; `workspace/ledgers/ray-crucible.json` from the previous pass.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-crucible.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-crucible_pass_${N}.json` before overwriting.
- **Preconditions**: target files readable. No exploitation is performed here —
  no payload is sent anywhere. Proof belongs to `/ray-detonator`.
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges). The ledger is archived per pass and then
  deterministically overwritten.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/injection_docket.md` | before Step 2, then per class in Steps 2–4 | One section per class: sink grep patterns, the safe pattern, the false-positive traps that decide most disputes, and the reproduction hint to hand `/ray-detonator` |
| `references/owasp_mapping.md` | at Step 6 and before writing the ledger | Top 10:2025 and API Top 10:2023 with the Ray skill that owns each, the class→CWE→category crosswalk, ASVS as a depth selector, and the coverage self-check |
| `references/findings_contract.md` | before writing the first finding, and again at Step 7 | Findings schema, the four computed fields, evidence discipline, severity defaults, the sink-ledger format |

The docket is per class, so read it a section at a time as you sweep. That is
cheaper than loading it whole, and it puts the traps in front of you at the
moment you are deciding a verdict — which is when they matter.

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

CODE-READING stage, so the findings-only skip does not apply. If dependency
scanning (Step 6) needs a tool that writes, run it in a private shadow copy per
step 4 — never with `cwd` = CODE_ROOT, and never letting it modify a lockfile.
This skill's `references/*.md` sit beside `SKILL.md`, not under CODE_ROOT.

### Step 1: Load Context and Establish the Source Set

Read `pass_number`, `active_snapshot`, the threat model, and the docket's table
of contents. Then enumerate **sources** — every place request-controlled data
enters the process — because every sink verdict is relative to this set:

route parameters, query strings, request bodies (JSON, form, multipart),
headers (including `Host`, `X-Forwarded-*`, `Referer`, `Origin`), cookies,
uploaded file names and contents, WebSocket messages, GraphQL variables, webhook
payloads, queue messages, imported files (CSV/XML/ZIP), external API responses,
environment values set by a lower-trust component, and — for stored-XSS and
second-order analysis — anything previously persisted from any of the above.

Record the source inventory in the ledger, noting which sources cross a trust
boundary per `THREAT_MODEL.md` and which are second-order.

### Step 2: Build the Sink Inventory

For each class in the docket, run its grep patterns across CODE_ROOT and record
every hit as a candidate sink with `file:line`. Where a structural index is
available, use it to rank which sinks to examine first and to resolve callers —
but the grep sweep is the mandatory floor for membership, and the index never
removes a candidate from it.

The inventory is what makes coverage auditable. A class with zero sinks is
recorded as `NO_SINKS` **with the patterns that were run**, not silently
omitted.

### Step 3: Trace Each Sink To A Verdict

Every sink gets exactly one of four verdicts, recorded in the ledger:

| Verdict | Meaning |
|---|---|
| `REACHABLE_UNSAFE` | A source reaches it and nothing neutralizes it. This is a finding |
| `NEUTRALIZED` | A parameterized query, escaping template, validated allowlist, safe API, or framework default intervenes. **Record the neutralizer's `file:line`** — that citation is what makes a clean verdict mean anything |
| `UNREACHABLE` | The input is a literal, a constant, or derived only from trusted configuration. Say what makes it trusted |
| `UNKNOWN` | The path crosses something you cannot resolve statically (dynamic dispatch, reflection, a plugin system). Write a `NEEDS_RESEARCH` finding stating what would resolve it — never round `UNKNOWN` down to safe |

Four habits keep the verdicts honest: follow the **value**, not the variable
name, through renames and destructuring; check the sanitizer's **context**
(HTML-escaping a value that lands in a JavaScript string or a URL attribute is
not protection — the context table is in the docket's XSS section); check its
**order** (validation after the sink, or escaping then decoding, is not
protection); and look for **second-order** flow, where input stored today is
rendered or executed tomorrow. Framework defaults count as neutralizers — cite
them, and check whether the specific call opts out.

### Step 4: Class-Specific Depth Passes

Work through the docket class by class. Its sections carry the detail that
decides validity — the identifier-allowlist rule for SQL `ORDER BY`, the XSS
context table, the CSRF applicability check (a Bearer-token API is not
vulnerable to classic CSRF; do not report it), the resolve-then-connect rule
for SSRF and why a URL regex is not a control, the content-based type validation
for uploads, the resolved-path prefix check for traversal, and the rest.

### Step 5: Second-Order and Chained Flows

Hunt explicitly for what a per-file review cannot see: input persisted and later
rendered in a different template, an email, a PDF, an admin panel, or a CSV
export; input that reaches a log line later parsed or displayed; input that
becomes part of a generated config, a downstream query, or a queue message;
values crossing service boundaries where the receiver trusts the sender.

For chains where one class enables another (SSRF → metadata credentials; upload
→ traversal → RCE; open redirect → OAuth code theft), report the primitive you
can evidence and describe the chain in `impact`. Do not claim the chain as
reproduced — that is `/ray-detonator`'s verdict.

### Step 6: Dependencies and Supply Chain

Enumerate manifests and lockfiles, then check the hygiene properties that are
assessable without network access — lockfile committed, versions pinned, no
unpinned git/URL dependencies, no suspicious install scripts, typosquat
near-misses, an update mechanism configured, an audit step in CI, registry
pinning, vendored copies frozen at old versions. The full checklist is in the
docket's `DEPS` section.

Where a known-vulnerable version is identified, **reachability decides
severity**: `ray-gauge`'s `third_party_reachability` rule caps a CVE whose
vulnerable path the application never invokes at LOW. Trace the call path, or
say plainly that you did not. Never fabricate CVE identifiers, CVSS scores, or
advisory text.

### Step 7: Write Findings and the Ledger

Follow `references/findings_contract.md`. The rules that decide whether a
finding survives here: **anchor at the sink** and include the source as a second
`code_paths` entry; **state the neutralizer you ruled out**; do not report
framework-default-protected code (React interpolation, auto-escaped templates,
parameterized ORM calls) — reporting it burns validation budget and trains
reviewers to ignore this stage; and **send no payloads anywhere**.

Before writing the ledger, run the coverage self-check in
`owasp_mapping.md` §5. It is what turns "I swept" into a statement someone can
audit.

### Step 8: Complete

Report findings by severity and class, sinks by verdict, classes with
`NO_SINKS`, classes `NOT_ASSESSED`, and every `UNKNOWN` sink with what would
resolve it. Do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| CSP, cookie flags, HSTS (the mitigations for XSS) | `/ray-custodian` |
| Authentication, IDOR, mass assignment, tenancy | `/ray-turnstile` |
| CORS, error leakage, cache poisoning, `postMessage`, ReDoS as availability | `/ray-seam` |
| Rate limiting, GraphQL cost limits, webhook signature verification | `/ray-sentry` |
| Database privileges that bound an injection's blast radius | `/ray-vault` |
| Pipeline gates that would catch vulnerable dependencies | `/ray-citadel` |
| General memory-safety and logic auditing against the plan | `/ray-prospector` |

Mass assignment looks like input handling but is a property-authorization
defect, so it belongs to `/ray-turnstile`. ReDoS and webhook URL handling appear
in two dockets by design; report where you found it and let `ray-condenser`
merge.
