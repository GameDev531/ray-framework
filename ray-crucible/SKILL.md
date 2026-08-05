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
code" produces noise; enumerating sinks and proving or disproving a source→sink
path produces findings that survive `/ray-arbiter` and can be reproduced by
`/ray-detonator`. This skill is sink-driven by construction.

`/ray-prospector` audits whatever the plan targets, with memory safety and
logical correctness in view. `/ray-crucible` runs a specific, exhaustive sweep
of the web application vulnerability canon regardless of what the plan targets.
The two overlap deliberately; `/ray-condenser` merges the results.

## Command Definition

- **Command:** `/ray-crucible`
- **Description:** Performs a sink-driven sweep for injection, XSS, CSRF, SSRF,
  deserialization, traversal, upload, redirect, and related classes, writing
  findings plus a sink ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--classes <csv>`: restrict the sweep to named classes (e.g.
    `sqli,xss,ssrf`). Absent → every class in
    `references/injection_docket.md`. A restricted run MUST record the skipped
    classes in the ledger as `NOT_ASSESSED` — never let a narrowed run look
    like a clean one.
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**:
  - `workspace/.ray_state.json` — `pass_number`, `active_snapshot`. Optional.
  - `workspace/plan.json` (optional) — prioritizes ordering, never membership.
    The sweep covers the codebase whether or not the plan mentions a file.
  - `workspace/kb/THREAT_MODEL.md`, `workspace/kb/entities/*.md` (optional).
  - `workspace/kb/structural_index/manifest.json` and
    `workspace/helpers/query_structural_index.py` (optional; HINT-only, used to
    rank and to resolve callers — never to decide membership).
  - `ray-crucible/references/injection_docket.md` and
    `ray-crucible/references/owasp_mapping.md` — read BOTH before sweeping.
  - Target source, templates, dependency manifests, and lockfiles.
  - `workspace/ledgers/ray-crucible.json` from the previous pass, if present.
- **Writes**:
  - `workspace/findings/<uuid>.json` — standard Ray findings schema.
  - `workspace/ledgers/ray-crucible.json` — sink inventory and per-class
    coverage for this pass.
  - `workspace/archive/ledgers/ray-crucible_pass_${N}.json` — copy of the
    previous ledger before overwrite.
- **Preconditions**:
  - Target files must be readable. No exploitation is performed here; a payload
    is never sent anywhere. Proof belongs to `/ray-detonator`.
- **Idempotency Guarantee**:
  - New UUID finding files each run (`ray-condenser` merges). Ledger archived
    per pass, then deterministically overwritten.

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

Skill-specific notes:

- CODE-READING stage: the findings-only skip does NOT apply.
- Dependency scanning (Step 6) reads manifests and lockfiles under CODE_ROOT.
  If it needs to run a tool that writes (an audit command producing a report),
  run it in a private shadow copy per Block A step 4 — never with `cwd`
  = CODE_ROOT, and never let it modify a lockfile.
- `references/*.md` live beside `SKILL.md`, not under CODE_ROOT.

### Step 1: Load Context and Establish the Source Set

Read `pass_number`, `active_snapshot`, the threat model, and both reference
files. Then enumerate **sources** — every place request-controlled data enters
the process. You will judge every sink against this set.

Typical sources: route parameters, query strings, request bodies (JSON, form,
multipart), headers (including `Host`, `X-Forwarded-*`, `Referer`,
`User-Agent`, `Origin`), cookies, uploaded file names and contents, WebSocket
messages, GraphQL variables, webhook payloads, queue messages, imported files
(CSV/XML/ZIP), external API responses, DNS/SSRF-adjacent lookups, environment
values set by a lower-trust component, and — for a stored-XSS analysis —
anything previously persisted from any of the above.

Record the source inventory in the ledger. Note explicitly which sources cross a
trust boundary per `THREAT_MODEL.md`, and which are second-order (persisted now,
rendered later).

### Step 2: Build the Sink Inventory

For each class in `references/injection_docket.md`, run its grep patterns across
CODE_ROOT and record every hit as a candidate sink with `file:line`. Use the
structural index, when available, to rank which sinks to examine first and to
resolve callers — but the grep sweep is the mandatory floor for membership, and
the index never removes a candidate from it.

The inventory is the deliverable that makes coverage auditable. A class with
zero sinks found is recorded as `NO_SINKS` with the patterns that were run — not
silently omitted.

Cover at minimum:

| Class | Representative sinks |
|---|---|
| SQL / NoSQL injection | string-concatenated queries, `.raw(`, `$where`, `$expr`, dynamic `ORDER BY`/table names |
| Command injection | `exec`, `spawn` with a shell, `system`, `popen`, backticks, `subprocess` with `shell=True` |
| XSS | `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `document.write`, `|safe`, `{{{ }}}`, `bypassSecurityTrustHtml` |
| Template injection | user input reaching a template *string* rather than a template *context* |
| SSRF | outbound HTTP clients taking a URL from input, webhook registration, URL preview/import, PDF/image fetchers, S3/proxy passthroughs |
| Deserialization | `pickle.loads`, `yaml.load`, `unserialize`, `ObjectInputStream`, `Marshal.load`, `JSON.parse` into a prototype-sensitive merge |
| Path traversal | `path.join`/`open`/`readFile`/`sendFile`/archive extraction with an input-derived path |
| File upload | multipart handlers, storage writes, MIME/extension checks |
| Open redirect | `res.redirect`, `Location` headers, `next`/`returnUrl` parameters |
| Prototype pollution | recursive merges, `Object.assign` chains, `lodash.merge`, query parsers |
| Timing leaks | `==`/`===`/`!=` on tokens, MACs, or secrets |
| ReDoS | regexes with nested quantifiers applied to input (also `/ray-seam`) |
| XXE | XML parsers with external entities enabled |
| CSRF | state-changing routes in a cookie-authenticated app |
| Dependencies | manifests and lockfiles |

### Step 3: Trace Each Sink

For every sink in the inventory, decide one of four verdicts — and record which:

1. **REACHABLE-UNSAFE** — a source reaches the sink and nothing neutralizes it.
   This is a finding.
2. **NEUTRALIZED** — a parameterized query, an escaping template, a validated
   allowlist, a safe API, or a framework default intervenes. Record the
   neutralizer's `file:line` in the ledger; this is the evidence that makes a
   "clean" verdict meaningful.
3. **UNREACHABLE** — the sink's input is a literal, a constant, or a value
   derived only from trusted configuration. Say what makes it trusted.
4. **UNKNOWN** — the path crosses a boundary you cannot resolve statically
   (dynamic dispatch, reflection, a plugin system, a value from an external
   service you cannot inspect). Write a `NEEDS_RESEARCH` finding stating what
   would resolve it. Do NOT round UNKNOWN down to safe.

Tracing rules that keep the verdicts honest:

- **Follow the value, not the variable name.** Rename chains, destructuring,
  and object spread hide provenance.
- **Check the sanitizer's context.** HTML-escaping a value that lands in a
  JavaScript string or a URL attribute is not protection — see the docket's
  context table.
- **Check the sanitizer's order.** Validation that runs after the sink, or
  escaping applied then decoded, is not protection.
- **Check for second-order flow.** Input stored today and rendered or executed
  tomorrow (stored XSS, second-order SQLi) is the class that spot checks miss.
- **Framework defaults count** — React escapes by default, Django templates
  auto-escape, an ORM parameterizes. Cite the default when you rely on it, and
  check whether the specific call opts out of it.

### Step 4: Class-Specific Depth Passes

Run the per-class procedures in `references/injection_docket.md`. The docket
carries, for each class: patterns to grep, the safe pattern, the false-positive
traps, and the reproduction hint to hand `/ray-detonator`. Points that
consistently decide a finding's validity:

- **SQL injection**: identifier interpolation (table/column/`ORDER BY`) cannot
  be parameterized — the safe pattern is an allowlist, and its absence is the
  finding. Check ORM escape hatches, and check that a "parameterized" call is
  not building the string first.
- **XSS**: classify as reflected, stored, or DOM-based, and name the exact
  context (HTML body, attribute, `href`/`src` URL, inline script, CSS, event
  handler). A `javascript:` URL in an `href` bound from input is XSS even
  though nothing was "injected" into HTML.
- **CSRF**: applies to cookie-authenticated state-changing requests. An API
  authenticated only by an `Authorization` header is not vulnerable to classic
  CSRF — do not report it. Check `SameSite`, token presence and validation
  (a token generated but never verified is common), and safe-method discipline
  (`GET` that mutates state bypasses every token scheme).
- **SSRF**: the correct control is resolve-then-validate-then-connect against a
  private/link-local denylist, applied at connection time to defeat DNS
  rebinding and redirect chains. A regex on the URL string is not a control.
  Flag cloud metadata reachability (`169.254.169.254`, `metadata.google.internal`)
  explicitly, and check whether IMDSv2 is required.
- **Deserialization**: any executable format (`pickle`, `yaml.load` without
  `SafeLoader`, PHP `unserialize`, Java `ObjectInputStream`, .NET
  `BinaryFormatter`) fed from a source is a HIGH finding on sight.
- **Upload**: content-based type validation (magic bytes) rather than
  extension or client `Content-Type`; random storage names; storage outside the
  webroot; served from a separate origin with `Content-Disposition`; SVG
  treated as active content; archive extraction bounded against zip-slip and
  zip bombs.
- **Path traversal**: `path.resolve(base, input)` followed by an explicit
  `startsWith(base + sep)` check — and note that the check must run on the
  resolved real path, after symlink resolution, to be sound.
- **Prototype pollution**: a recursive merge over parsed JSON that does not
  reject `__proto__`, `constructor`, and `prototype`, or a query parser that
  produces those keys.
- **Timing**: secret comparison with `===` in an auth or webhook path.
- **XXE**: parsers whose external-entity handling is enabled or defaulted on
  for the runtime version in use.

### Step 5: Second-Order and Chained Flows

Explicitly hunt the flows a per-file review cannot see:

1. Persisted input rendered in a different template, an email, a PDF, an admin
   panel, or a CSV export (CSV injection: a cell beginning `=`, `+`, `-`, `@`
   executes in a spreadsheet).
2. Input that reaches a log line that is later parsed or rendered (log
   injection, and log-viewer XSS).
3. Input that becomes part of a generated configuration, a query for another
   service, a webhook URL, or a message on a queue.
4. Values crossing microservice boundaries where the receiving service trusts
   the sender.
5. Chains where one class enables another (SSRF → metadata credentials; upload
   → traversal → RCE; open redirect → OAuth code theft). Report the primitive
   you can evidence, and describe the chain in the `impact` field; do not claim
   the chain as reproduced.

### Step 6: Dependencies and Supply Chain

1. Enumerate manifests and lockfiles (`package.json`/`package-lock.json`/
   `pnpm-lock.yaml`/`yarn.lock`, `requirements*.txt`/`poetry.lock`/`uv.lock`,
   `go.mod`/`go.sum`, `Gemfile.lock`, `pom.xml`, `Cargo.lock`, `composer.lock`).
2. Check hygiene, which is assessable without network access: are lockfiles
   committed; are versions pinned or floating (`^`, `*`, `latest`); are there
   direct git/URL dependencies; are there packages whose names are near-misses
   of popular ones (typosquatting); are install scripts present; is there an
   automated update mechanism (Dependabot/Renovate config) and a CI audit step?
3. Where a known-vulnerable version is identified, **reachability decides
   severity**: a CVE in a package whose vulnerable function the application
   never calls is LOW by the pipeline's own calibration rules
   (`third_party_reachability` in `ray-gauge`'s docket). Trace the call path or
   say plainly that you could not.
4. Do not fabricate CVE identifiers, CVSS scores, or advisory text. If you
   cannot verify an advisory from the snapshot or a tool you actually ran, say
   the version is outdated and let a scanner or `/ray-detonator` confirm.

### Step 7: Evidence Discipline

- **Anchor at the sink**, and include the source line as a second `code_paths`
  entry when you have identified it. A finding with only a class name and a file
  is not reviewable.
- **State the neutralizer you ruled out.** "No parameterization; the ORM's
  `.raw()` at line 44 bypasses the query builder used elsewhere in this module"
  is what makes a finding survive `/ray-arbiter`.
- **Do not report framework-default-protected code.** React interpolation,
  auto-escaped templates, and parameterized ORM calls are safe; reporting them
  burns validation budget and trains reviewers to ignore this stage.
- **Do not send payloads anywhere.** No requests to the target, no test payloads
  to third-party hosts, no DNS callbacks. Static analysis here; sandboxed proof
  in `/ray-detonator`. Put the reproduction recipe in `mitigation`/description
  so the detonator can build it.
- **One sink, one finding**, with all reaching sources listed. A single root
  cause across many sinks (an unsafe helper used in twenty places) is reported
  at the helper, with the call sites in `code_paths`.
- **Severity defaults**: RCE-capable classes (command injection, unsafe
  deserialization, upload-to-execute) HIGH by default; SQLi HIGH; SSRF reaching
  metadata or internal services HIGH, otherwise MEDIUM; stored XSS MEDIUM–HIGH,
  reflected/DOM XSS MEDIUM (see the docket and note that `ray-gauge` caps XSS
  aggressively); traversal MEDIUM–HIGH by what it reads; open redirect LOW;
  timing leaks LOW–MEDIUM. Never CRITICAL without a described,
  unauthenticated path to full compromise.

### Step 8: Compile and Write Findings

Create `workspace/findings/` if missing; one JSON object per file at
`workspace/findings/<uuid>.json`, no surrounding text.

Compute before writing:

1. **`cwe`** — this stage should almost always set it; see
   `references/owasp_mapping.md` for the class→CWE→OWASP crosswalk
   (`CWE-89` SQLi, `CWE-79` XSS, `CWE-352` CSRF, `CWE-918` SSRF, `CWE-502`
   deserialization, `CWE-22` traversal, `CWE-434` unrestricted upload,
   `CWE-601` open redirect, `CWE-1321` prototype pollution, `CWE-208` timing,
   `CWE-611` XXE, `CWE-78` command injection, `CWE-1333` ReDoS,
   `CWE-1395` vulnerable dependency).
2. **`signature`** — first 16 hex chars of
   `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`, with
   `normalized_title` = title lowercased and stripped to `[a-zA-Z0-9]` (empty →
   first 16 hex of `sha256(raw title)`), `cwe_part` = `cwe` or `""`,
   `primary_target` = first `code_paths` entry minus `:line`. Empty
   `primary_target` → hash over
   `normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(",")`.
   Order `code_paths` with the **sink first**, always, so the signature is
   stable across passes. Compute once; never recompute.
3. **`lineage_id`** — inherit from an archived finding with the same
   `signature` in `workspace/archive/findings_pass_*/` or
   `workspace/archive/loop*_findings/` (highest pass wins), else fresh UUIDv4.
   `ray-prospector` Step 5a's basename-rename fallback applies.
4. **`discovery_commit`** — `active_snapshot.snapshot_id` verbatim when pinned;
   omitted entirely in DEGRADED mode.

#### Findings Schema Format (per file)

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "SQL injection via unparameterized ORDER BY in report builder",
  "description": "The source (which request field, at which entrypoint), the path it takes to the sink, the sink itself, and which neutralizers were checked and ruled out. Name the framework default if one exists and explain why it does not apply here.",
  "impact": "What the primitive yields (e.g., arbitrary read of the users table; command execution as the app user; theft of cloud instance credentials via metadata).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["SINK FIRST, e.g. 'src/reports/query.ts:88'", "then the source, e.g. 'src/routes/reports.ts:19'"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-89",
  "signature": "First 16 hex chars of the sha256 defined above.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The safe pattern for this exact call, plus the reproduction recipe /ray-detonator should build (request shape, parameter, expected observable).",
  "vuln_class": "Optional. The docket class id, e.g. 'SQLI'.",
  "history": [
    {
      "stage": "crucible",
      "action": "created",
      "details": "Untrusted-input sweep finding recorded.",
      "pass_number": 1,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

### Step 9: Write the Sink Ledger

1. Resolve `N` from `pass_number`, else `max` archive pass + 1, else `1`.
2. Copy any existing `workspace/ledgers/ray-crucible.json` to
   `workspace/archive/ledgers/ray-crucible_pass_${N}.json` (`mkdir -p` first).
3. Write `workspace/ledgers/ray-crucible.json`:

```json
{
  "skill": "ray-crucible",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "classes_requested": "ALL",
  "sources": ["src/routes/**: query, body, params", "src/webhooks/stripe.ts:12"],
  "classes": [
    {
      "id": "SQLI",
      "state": "ASSESSED | NO_SINKS | NOT_ASSESSED",
      "patterns_run": ["\\.raw\\(", "query\\(`", "execute\\(f\""],
      "sinks": [
        {
          "location": "src/reports/query.ts:88",
          "verdict": "REACHABLE_UNSAFE | NEUTRALIZED | UNREACHABLE | UNKNOWN",
          "neutralizer": null,
          "finding_id": "<uuid or null>"
        }
      ]
    }
  ],
  "dependencies": {
    "manifests": ["package.json", "package-lock.json"],
    "lockfiles_committed": true,
    "floating_versions": ["lodash: ^4.17.0"],
    "install_scripts_present": false,
    "automated_updates": "renovate.json"
  }
}
```

Every class in the docket appears exactly once. `NOT_ASSESSED` is only valid
when `--classes` excluded it, and must name that reason.

### Step 10: Complete

Report: findings by severity and class, sinks by verdict, classes with
`NO_SINKS`, classes `NOT_ASSESSED`, and every `UNKNOWN` sink with what would
resolve it. Do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

- **CSP, cookie flags, HSTS** → `/ray-custodian`. Report the XSS here and the
  missing CSP there; they are different controls with different owners.
- **Authentication, authorization, IDOR, mass assignment, tenancy** →
  `/ray-turnstile`. Mass assignment is a property-authorization defect, not an
  injection one, even though it looks like input handling.
- **CORS, error leakage, ReDoS as an availability defect, cache poisoning,
  `postMessage`** → `/ray-seam`. ReDoS appears in both dockets; report where you
  found it and let `/ray-condenser` merge.
- **Rate limiting, GraphQL depth limits, webhook signature verification** →
  `/ray-sentry`. Webhook *signature* is there; webhook *URL handling* (SSRF) is
  here.
- **General memory-safety and logic auditing against the plan** →
  `/ray-prospector`.
