---
name: ray-custodian
description: >-
  Audits how a web surface protects personal data: TLS and response headers, cookie flags, consent and lawful basis, retention, data-subject rights, and third-party egress of PII (LGPD/GDPR).
  Use when the target serves a website, portal, or browser-facing app that collects or displays personal data and you need privacy/exposure findings written to workspace/findings/.
  Don't use for server-side injection classes (use ray-crucible), authentication and tenancy (use ray-turnstile), or database-layer exfiltration controls (use ray-vault).
---

# Custodian (/ray-custodian)

## System Goal

Personal-Data Custodian. Audits the browser-facing surface and the personal-data
lifecycle behind it — transport security, response headers, cookie flags,
consent capture, retention, data-subject rights, and PII egress to third
parties — and emits standard Ray findings for every control that is absent,
weak, or unverifiable on the pinned snapshot.

This stage exists because privacy defects are structurally invisible to a
code-reading auditor that only looks for memory corruption or injection: a
`Set-Cookie` without `HttpOnly`, an analytics SDK that fires before consent, or
an export endpoint with no `WHERE user_id = $1` are all perfectly valid code.
They are defects only against an external obligation. `/ray-custodian` carries
that obligation set (see `references/`) so the rest of the pipeline does not
have to.

## Command Definition

- **Command:** `/ray-custodian`
- **Description:** Audits web-surface exposure controls and the personal-data
  lifecycle (collection → storage → egress → retention → erasure) and writes
  findings plus a control ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: absolute path to the pinned, read-only
    code snapshot for this pass. This is the CODE_ROOT that every
    snapshot-relative path resolves against (Block A step 1b).
  - `--snapshot_id` / `SNAPSHOT_ID`: the pass snapshot identifier. Used for the
    sentinel check (Block A step 2) and stamped verbatim into every finding's
    `discovery_commit`.
  - `--state_root`: absolute path to the `workspace/` state directory
    (`plan.json`, `.ray_state.json`, `findings/`, `kb/`, `ledgers/`,
    `archive/`). STATE-RELATIVE — NEVER prefixed with CODE_ROOT.
  - `--target_root`: authoritative override (Block A step 1a), honored if
    supplied.
  - `--regime <lgpd|gdpr|both>`: which privacy regime to score obligations
    against. Absent → `both` (the conservative default: an obligation that
    exists under either regime is checked, and the finding names which regime
    it comes from).
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT falls back to the
    current directory, `snapshot_pinned` is treated as false, and no
    `discovery_commit` is written.

## Input/Output Contract

- **Reads**:
  - `workspace/.ray_state.json` — `pass_number` and `active_snapshot`
    (`{root, snapshot_id, snapshot_pinned}`). Optional; absent → degraded.
  - `workspace/plan.json` (optional). If it contains investigations whose
    `target_files` cover web entrypoints, prioritize them. Missing/empty → run
    the full discovery sweep in Step 2.
  - `workspace/kb/THREAT_MODEL.md` and `workspace/kb/entities/*.md` (optional)
    — for trust boundaries and prior privacy-relevant notes.
  - `ray-custodian/references/privacy_docket.md` and
    `ray-custodian/references/web_surface_baseline.md` (this skill's own
    reference files — read BOTH before scoring any control).
  - Target source: server/edge configuration, HTTP middleware, cookie writes,
    templates, client bundles, ORM models and migrations, IaC/DNS descriptors.
  - `workspace/ledgers/ray-custodian.json` from the previous pass, if present
    (to carry `UNKNOWN` reasons forward, never to skip a re-check).
- **Writes**:
  - `workspace/findings/<uuid>.json` — one file per finding, standard Ray
    findings schema (creates `workspace/findings/` if missing).
  - `workspace/ledgers/ray-custodian.json` — the control ledger for this pass
    (creates `workspace/ledgers/` if missing).
  - `workspace/archive/ledgers/ray-custodian_pass_${N}.json` — a copy of the
    PREVIOUS ledger, written before the live ledger is overwritten.
- **Preconditions**:
  - Target files must be readable. No network access to the live site is
    required or assumed: this stage audits the code and configuration that
    PRODUCE the surface, never a deployed host.
- **Idempotency Guarantee**:
  - Findings are new UUID-named files each run; `ray-condenser` clusters and
    merges duplicates across runs and passes. The ledger is archived per pass
    and then deterministically overwritten in place, so re-running a pass
    against an unchanged snapshot reproduces an equivalent ledger.

## Instructions

### Step 0: Locator Resolution (Snapshot-Aware Path Handling)

Run this BEFORE reading any target file. It fixes the single CODE_ROOT that
every configuration and source reference in this stage resolves against.

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

- This is a CODE-READING stage, so Block A step 0's findings-only skip does NOT
  apply — resolve CODE_ROOT and honor the sentinel.
- `plan.json` `target_files` and every finding `code_paths` entry are
  SNAPSHOT-RELATIVE (resolve under CODE_ROOT). `workspace/**` — including the
  ledger — is STATE-RELATIVE and is NEVER prefixed with CODE_ROOT.
- This skill's `references/*.md` live next to `SKILL.md` inside the skill
  directory, NOT under CODE_ROOT and NOT under `workspace/`.

### Step 1: Load Context

Read `pass_number` and `active_snapshot` from `workspace/.ray_state.json`, and
resolve the current ISO 8601 timestamp. Hold `active_snapshot.snapshot_id`: it
is the value stamped into every finding's `discovery_commit`. If
`active_snapshot` is absent or `snapshot_pinned` is false you are in
DEGRADED/legacy mode — do NOT stop; simply omit `discovery_commit`.

Read `workspace/kb/THREAT_MODEL.md` (if present) for trust boundaries, and both
files under `ray-custodian/references/`. Do not score a single control before
you have read the docket — the docket, not your recollection, is the authority
on what each obligation requires.

### Step 2: Build the Personal-Data Inventory (data mapping)

You cannot audit the protection of data you have not enumerated. Build the
inventory FIRST; every later step keys off it.

1. **Find the fields.** Sweep schemas, migrations, ORM models, DTOs, validation
   schemas (zod/pydantic/joi/class-validator), GraphQL SDL, protobufs, form
   markup, and analytics/telemetry call sites. Grep both English and
   Portuguese/Spanish field names — real Brazilian codebases mix them:
   `email`, `phone|telefone|celular`, `cpf|cnpj|rg|ssn|tax_id`,
   `address|endereco|cep|zip`, `birth|nascimento|dob`, `name|nome`,
   `card|cartao|iban|pix`, `ip_address`, `device_id`, `lat|lng|geo`,
   `health|saude|prontuario`, `biometric|biometria|face|digital`.
2. **Classify each field** using the taxonomy in
   `references/privacy_docket.md` §1: identifier, contact, financial,
   government ID, behavioral/observational, or SENSITIVE (LGPD art. 5 II /
   GDPR art. 9 — health, biometric, genetic, racial or ethnic origin,
   religious or philosophical belief, political opinion, union membership,
   sex life or orientation, and — under LGPD — data of children and
   adolescents). Sensitive fields raise the floor on everything downstream.
3. **Trace each field's lifecycle** and record it in the ledger:
   - collection point (route/handler/form),
   - storage location (table/column, cache, object storage, log sink),
   - egress points (third-party SDK, analytics, session replay, error
     tracker, LLM/API call, webhook, email/SMS provider, CSV export),
   - deletion or anonymization path (or the absence of one).
4. **Record what you could not determine** as `UNKNOWN` in the ledger with the
   reason. `UNKNOWN` is a legitimate outcome; a silent omission is not.

If the sweep finds NO personal data at all, say so explicitly in the ledger
(`controls: []` is wrong; write the inventory control with
`state: "NOT_APPLICABLE"` and the evidence that supports it), write zero
findings for the lifecycle controls, and still run Steps 3–4 (transport and
headers protect sessions, not just PII).

### Step 3: Transport and Response-Header Audit

Locate the layer that actually sets headers before you judge them absent. In
order of authority, check: edge/CDN config (Cloudflare/CloudFront IaC, `_headers`,
`vercel.json`, `netlify.toml`), reverse proxy (`nginx.conf`, `Caddyfile`,
Traefik labels, Apache `.htaccess`), framework middleware (`helmet`, Django
`SECURE_*` settings, Rails `config.force_ssl`, ASP.NET middleware,
`next.config.js` headers, Spring Security), and finally per-response code.

Score each control in `references/web_surface_baseline.md` §1–§2:

- **HTTPS enforcement**: is there a 301/308 redirect from HTTP, and does it
  cover every host and path (not just `/`)?
- **HSTS**: `Strict-Transport-Security` present, `max-age` ≥ 31536000,
  `includeSubDomains` when subdomains are in scope. Flag a
  `max-age` of 0 or a few hundred seconds — a token HSTS is a false sense of
  coverage.
- **TLS versions and ciphers**: TLS 1.2 minimum; flag explicit enabling of
  SSLv3/TLS 1.0/TLS 1.1 or `@SECLEVEL=0`-style downgrades in config.
- **CSP**: present, and non-trivial. A policy containing `unsafe-inline` or
  `unsafe-eval` in `script-src`, or a wildcard `default-src *`, is a WEAK
  control, not a present one — report it as such with the exact directive
  quoted. Check `object-src 'none'`, `base-uri 'none'`, and `frame-ancestors`.
- **`X-Content-Type-Options: nosniff`**, **`Referrer-Policy`** (at least
  `strict-origin-when-cross-origin`), **`Permissions-Policy`** for powerful
  features the app does not use, and clickjacking protection via
  `frame-ancestors` (preferred) or `X-Frame-Options: DENY`.
- **Mixed content**: grep templates, bundles, and CSS for `http://` asset URLs
  on a site that otherwise serves HTTPS.
- **Certificate lifecycle**: is renewal automated (certbot/ACME/managed cert),
  or is there a hand-rolled cert path with no renewal hook?

### Step 4: Cookie and Client-Storage Audit

Find every `Set-Cookie` write — framework session config, `res.cookie(...)`,
`document.cookie`, `SESSION_COOKIE_*` settings, and the auth library's
defaults — and score each against `references/web_surface_baseline.md` §3:

- `HttpOnly` on every cookie carrying a session or token. A session cookie
  readable by JavaScript converts any XSS into full account takeover.
- `Secure` on every cookie on an HTTPS origin.
- `SameSite`: `Lax` minimum for session cookies, `Strict` for
  state-changing-only flows; `SameSite=None` REQUIRES `Secure` and a stated
  cross-site reason — flag `None` without a documented third-party embed need.
- Scope: an over-broad `Domain=.example.com` shares the session with every
  subdomain, including one an attacker may take over. Flag it when the app
  does not need cross-subdomain sessions.
- Lifetime: a session cookie with a multi-year `Max-Age` and no server-side
  revocation is a persistent credential.
- Client storage: personal data or tokens written to `localStorage` /
  `sessionStorage` / IndexedDB. (Token-in-localStorage specifically is also
  ray-seam's territory — see "Boundary With Adjacent Skills"; report it here
  only when the stored value is personal data rather than a credential.)

### Step 5: Consent, Lawful Basis, and Purpose

The mechanical, falsifiable test — and the one that produces defensible
findings — is **ordering**: does any non-essential tracker load, or any
non-essential cookie get written, BEFORE a consent decision exists?

1. Enumerate third-party scripts and pixels in templates, `<head>` partials,
   tag-manager containers, and bundle entrypoints.
2. For each, determine whether it is gated on a consent state (a consent-mode
   flag, a `if (consent.analytics)` guard, a deferred loader) or fires
   unconditionally on page load. Unconditional loading of analytics,
   advertising, session replay, or fingerprinting is a finding under both
   regimes; anchor it at the exact line that injects the script.
3. Check consent quality against `references/privacy_docket.md` §4: is the
   banner opt-in (unchecked by default) rather than opt-out; is refusing as
   easy as accepting; is the choice recorded with a timestamp, the policy
   version, and the scope; is withdrawal possible?
4. For each personal-data field in the inventory, check whether the codebase
   or docs name a lawful basis (LGPD art. 7 / GDPR art. 6). A field collected
   with no discoverable basis is at minimum a documentation finding — record it
   as `UNKNOWN` in the ledger if the repository plausibly does not carry the
   privacy documentation, and as a finding when the repository DOES carry
   policy docs that omit the field.
5. Sensitive data (Step 2.2) collected under "legitimate interest" is a
   finding: LGPD art. 11 and GDPR art. 9 do not offer that basis.

### Step 6: Retention, Erasure, and Data-Subject Rights

1. **Retention**: search for any scheduled deletion or anonymization — cron
   jobs, task queues, TTL indexes, S3/GCS lifecycle rules, partition drops,
   `DELETE FROM ... WHERE created_at <` queries. If personal data is stored and
   NO retention mechanism exists anywhere, that is a finding anchored at the
   model/migration that defines the storage. Unbounded retention is the single
   cheapest way to enlarge a future breach.
2. **Logs and backups count as storage.** Check log retention config and backup
   lifecycle too — a 30-day deletion job that leaves PII in 5 years of backups
   deletes nothing.
3. **Rights endpoints** (LGPD art. 18 / GDPR ch. 3): is there any path for a
   subject to obtain confirmation, access, correction, portability
   (machine-readable export), anonymization/erasure, and information about
   sharing? Absence is a finding; presence with a defect is a WORSE finding —
   audit each rights endpoint for:
   - authorization (does it check the requester owns the subject record, or is
     it `GET /export?user_id=123`? that is a bulk-exfiltration primitive; also
     report it via the IDOR class so `ray-detonator` picks it up),
   - authentication strength (an export triggered by an unauthenticated email
     link is an enumeration and exfiltration channel),
   - completeness (does erasure cascade to caches, search indexes, analytics,
     and backups, or only to the primary row?).
4. **Erasure vs. soft delete**: a `deleted_at` flag is not erasure. Report the
   gap when the code claims deletion and performs a soft delete.

### Step 7: Egress and Exposure

1. **PII in URLs**: forms using `GET` for sensitive fields, tokens or documents
   in query strings, personal data in path segments that end up in access logs,
   browser history, and `Referer`. Grep route definitions and form `method`
   attributes.
2. **PII to third parties**: analytics/session-replay/error-tracker calls that
   forward request bodies, user objects, or full URLs. Check error-tracker
   `beforeSend`/scrubbing config: a Sentry integration with no PII scrubbing
   forwards whatever the exception carried.
3. **PII to model providers**: prompts, embeddings, and RAG payloads built from
   personal data, sent to an external inference API without a stated basis or a
   redaction step.
4. **Subdomain takeover**: scan committed DNS/IaC descriptors (Terraform
   `aws_route53_record`, `*.tf`, zone files, `CNAME` files) for CNAMEs
   pointing at platform hostnames (`*.herokuapp.com`, `*.s3-website-*`,
   `*.github.io`, `*.azurewebsites.net`, `*.cloudfront.net`, `*.netlify.app`)
   whose backing resource is NOT also declared in the same repository. Report
   as a dangling-delegation risk; do NOT claim an active takeover you have not
   reproduced — that verdict belongs to `ray-detonator`.
5. **Non-production copies**: seeds, fixtures, or scripts that clone production
   data into staging/dev without anonymization.

### Step 8: Evidence Discipline (read before writing any finding)

These rules are what keep this stage from producing a wall of "add helmet"
noise that the validation stages then have to grind through.

- **Anchor every finding at a line you actually read.** `code_paths` MUST point
  at a real file:line under CODE_ROOT. Never invent a line number, and never
  cite a file you did not open.
- **Absence-of-control findings need a composition-root anchor.** If a control
  is missing everywhere, anchor the finding at the file where it WOULD be
  installed (the middleware chain, the server config, the model definition) and
  say plainly in the description that the control was searched for and not
  found, listing exactly where you looked. A finding whose anchor is "nowhere"
  is unreviewable and will be dismissed downstream.
- **Search the whole chain before declaring absence.** Headers set at the CDN,
  cookies hardened by a framework default, retention enforced by a bucket
  lifecycle rule — all defeat a naive "not in the code" conclusion. If the
  control could plausibly live in infrastructure that is not in this
  repository, write the finding with `"status": "NEEDS_RESEARCH"` and state
  what would confirm or refute it. Fail conservative; never issue a clean
  verdict you cannot support.
- **One control, one finding.** Do not bundle "no HSTS, no CSP, no nosniff"
  into a single finding — the pipeline scores, reproduces, and tracks
  regressions per finding. Do not fragment either: one absent control affecting
  twelve routes is one finding with twelve `code_paths`.
- **Regime attribution.** When the obligation is legal rather than technical,
  name the article in the description (e.g. "LGPD art. 18 IV", "GDPR art. 33")
  and keep the legal claim narrow: describe the obligation, not a prediction of
  enforcement outcomes.
- **Severity, conservatively.** This is a discovery stage; `ray-gauge` applies
  the caps. Default to MEDIUM for a missing hardening header with no
  demonstrated exploit path, HIGH when personal data is demonstrably reachable
  by an unauthorized party, LOW for hygiene with no reachable impact. Do not
  mark CRITICAL without a concrete, described path to bulk personal-data access.

### Step 9: Compile and Write Findings

Create `workspace/findings/` if missing. For each finding, generate a UUID and
write one JSON object to `workspace/findings/<uuid>.json`, with no text before
or after the JSON.

Before writing each file, compute:

1. **`cwe` (optional)** — e.g. `CWE-311` (missing encryption of sensitive data),
   `CWE-315`/`CWE-1004` (sensitive cookie without HttpOnly), `CWE-614` (cookie
   without Secure), `CWE-1275` (SameSite misconfiguration), `CWE-359` (exposure
   of private information), `CWE-532` (information exposure through logs),
   `CWE-319` (cleartext transmission), `CWE-1021` (improper restriction of
   framed UI). Omit the field when no CWE applies.
2. **`signature`** — first 16 hex chars of
   `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`, where
   `normalized_title` is the title lowercased with all non-`[a-zA-Z0-9]`
   characters stripped (if that leaves it empty, use the first 16 hex chars of
   `sha256(raw title as UTF-8)`), `cwe_part` is the `cwe` value or the empty
   string, and `primary_target` is the first `code_paths` entry with any
   trailing `:line` stripped. If `primary_target` is empty, use
   `sha256(normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(","))`.
   Order `code_paths` deterministically (primary anchor first). Compute the
   signature ONCE at creation; never recompute it.
3. **`lineage_id`** — scan `workspace/archive/findings_pass_*/` and
   `workspace/archive/loop*_findings/` for an archived finding with the same
   `signature`; inherit its `lineage_id` (from the highest pass number if
   several match). Otherwise a fresh UUIDv4. The basename-rename fallback in
   `ray-prospector` Step 5a applies here identically. These paths are
   STATE-RELATIVE.
4. **`discovery_commit`** — `active_snapshot.snapshot_id`, copied verbatim,
   REQUIRED and non-empty when the snapshot is pinned. OMIT the key entirely
   (not `""`, not `null`) in DEGRADED/legacy mode.

`signature` and `lineage_id` are ALWAYS computed, in every mode.

#### Findings Schema Format (per file)

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Session cookie set without HttpOnly in [module]",
  "description": "Root-cause analysis: which personal data or session material is exposed, which control is absent or weak, exactly where it was searched for, and which layer would normally enforce it. Name the regime article when the obligation is legal.",
  "impact": "Concrete outcome (e.g., session theft via any XSS; bulk export of subject records by an unauthenticated caller; indefinite retention enlarging breach blast radius).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["SNAPSHOT-RELATIVE path under CODE_ROOT, e.g. 'src/server/session.ts:41'. Never invent a line number."],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit the key entirely in DEGRADED/legacy mode.",
  "cwe": "CWE-1004 (optional; omit if none applies)",
  "signature": "First 16 hex chars of the sha256 defined above. Computed once at creation.",
  "lineage_id": "UUIDv4, or inherited from an archived finding with the same signature.",
  "mitigation": "The corrective change, concretely: the directive, flag, or code shape to apply — plus, where one exists, the regression test that would keep it applied (e.g. 'assert Set-Cookie on /login contains HttpOnly; Secure; SameSite=Lax').",
  "privacy_control_id": "Optional. The control id from the ledger this finding was raised by, e.g. 'COOKIE-01'.",
  "history": [
    {
      "stage": "custodian",
      "action": "created",
      "details": "Privacy/exposure audit finding recorded.",
      "pass_number": 1,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

Use `"status": "PROVISIONALLY_VALID"` by default. Use `"NEEDS_RESEARCH"` only
when the control's state genuinely cannot be determined from the snapshot (for
example, headers that may be injected by a CDN configured outside the
repository) — and say what evidence would resolve it.

### Step 10: Write the Control Ledger

The ledger is what makes the absence of a finding meaningful: it records every
control that was checked, not just the ones that failed.

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`. If missing or
   invalid, scan `workspace/archive/` for `findings_pass_N` / `loopN_findings`
   folders and use `max_found + 1`, defaulting to `1`.
2. If `workspace/ledgers/ray-custodian.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-custodian_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-custodian.json`:

```json
{
  "skill": "ray-custodian",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "regime": "both",
  "generated_at": "<iso8601>",
  "personal_data_inventory": [
    {
      "field": "cpf",
      "classification": "GOVERNMENT_ID",
      "collected_at": ["src/routes/signup.ts:88"],
      "stored_at": ["migrations/0007_users.sql:12"],
      "egress": ["src/analytics/track.ts:34"],
      "erasure_path": null
    }
  ],
  "controls": [
    {
      "id": "TLS-01",
      "control": "HTTP redirected to HTTPS on every host and path",
      "state": "PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN",
      "evidence": "infra/nginx.conf:14",
      "finding_ids": [],
      "note": "Redirect covers the apex only; www vhost serves plaintext."
    }
  ]
}
```

Every control from `references/web_surface_baseline.md` and every applicable
obligation from `references/privacy_docket.md` MUST appear exactly once in
`controls`, including those that passed and those you could not determine.
`UNKNOWN` entries MUST carry a `note` saying what blocked determination.

### Step 11: Complete

Report to the user: the number of findings written by severity, the count of
controls by state, the size of the personal-data inventory, and every `UNKNOWN`
control with its blocking reason. Do not print the finding bodies or the ledger
into chat — they are on disk, and downstream stages read them from there.

## Boundary With Adjacent Skills

- **XSS, CSRF, SQL injection, SSRF and the rest of the untrusted-input canon**
  belong to `/ray-crucible`. CSP and cookie flags are audited here because they
  are exposure controls; the injection bug they mitigate is audited there.
- **Authentication, session lifetime, tenancy, and authorization** belong to
  `/ray-turnstile`. Audit rights-endpoint authorization here only to the extent
  needed to identify a personal-data exposure, and note the overlap so
  `ray-condenser` can merge the duplicate.
- **Tokens in `localStorage`, CORS, logging of secrets, and error-message
  leakage** belong to `/ray-seam`.
- **Encryption at rest, database privileges, and backups** belong to
  `/ray-vault`.
- **Environment isolation and the deploy pipeline** belong to `/ray-citadel`.

Overlap is expected and is not an error: write the finding you can evidence and
let `ray-condenser` deduplicate.
