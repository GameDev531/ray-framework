---
name: ray-turnstile
description: >-
  Audits SaaS identity and access control: credential storage, sessions and JWTs, MFA and credential stuffing, password reset and invite flows, IDOR/BOLA authorization, tenant isolation, secret handling, and races on critical operations.
  Use when the target is a multi-user or multi-tenant application and you need authentication, authorization, and tenancy findings written to workspace/findings/.
  Don't use for injection classes (use ray-crucible), privacy obligations and headers (use ray-custodian), or database privilege and backup hardening (use ray-vault).
---

# Turnstile (/ray-turnstile)

## System Goal

Access-Control Auditor. Establishes who the system believes you are, what it
lets you reach on that basis, and whether either belief can be forged, replayed,
escalated, or crossed between tenants.

The worst incident a SaaS can have is not a crash — it is customer A reading
customer B's data. That failure is almost never a missing subsystem; it is a
single query that forgot a `tenant_id`, one handler that trusted an id from the
URL, or one role check that lives only in the frontend. This stage sweeps for
exactly those, as populations rather than as spot checks.

## Command Definition

- **Command:** `/ray-turnstile`
- **Description:** Audits credential storage, session and token handling,
  authorization enforcement, tenant isolation, and secret management, writing
  findings plus a control ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: the `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--tenancy <shared_schema|schema_per_tenant|db_per_tenant|single_tenant|auto>`:
    the isolation model to audit against. Absent → `auto` (infer it in Step 4
    using the procedure in `tenancy_isolation.md` §1, and record the inference
    and its evidence in the ledger).
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json` (`pass_number`, `active_snapshot`);
  `workspace/plan.json` (optional, ordering hint only); `workspace/kb/THREAT_MODEL.md`
  and `workspace/kb/entities/*.md` (optional); this skill's `references/*.md`;
  target source (auth modules, middleware, route definitions, ORM models and
  query builders, migrations and RLS policies, background jobs, config and
  environment templates); `workspace/ledgers/ray-turnstile.json` from the
  previous pass, if present.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-turnstile.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-turnstile_pass_${N}.json` before overwriting.
- **Preconditions**: target files readable. This stage never authenticates
  against a live system and never runs credential tests — proving an
  authorization bypass is `/ray-detonator`'s job, on a sandboxed target.
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges). The ledger is archived per pass and then
  deterministically overwritten.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/identity_docket.md` | before Steps 2 and 5 | Password storage parameters, password policy (NIST SP 800-63B-4), session controls, the full RFC 8725 JWT checklist, MFA and anti-automation, recovery and invite flows, enumeration, federated identity (OAuth/OIDC/SAML), and the identity control-ledger ids |
| `references/tenancy_isolation.md` | before Steps 3 and 4 | Isolation models and how to infer one, the shared-schema population sweep, the Postgres RLS footgun list, isolation beyond the primary database, the cross-tenant regression test, and the authorization and tenancy control-ledger ids |
| `references/findings_contract.md` | before writing the first finding, and again at Step 8 | Findings schema, the four computed fields, this domain's CWE set, evidence discipline, severity defaults, and the ledger format |

Read the dockets rather than working from memory of them. The RLS footgun list
in particular decides verdicts that look identical in the code and are not — a
policy without `FORCE ROW LEVEL SECURITY` is silently inert when the app owns
the table.

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

CODE-READING stage, so the findings-only skip does not apply. Secret history
(Step 7) uses the VCS carve-out in the LIVE repo root. This skill's
`references/*.md` sit beside `SKILL.md`, not under CODE_ROOT.

### Step 1: Load Context and Map the Identity Surface

Read `pass_number` and `active_snapshot`, resolve the timestamp, hold
`snapshot_id`, read the threat model and both dockets.

Then map the identity surface, because you cannot audit enforcement without
knowing every way a request acquires an identity:

1. **Authentication entrypoints** — login, signup, reset, magic link, OAuth
   callback, SAML ACS, API key header, personal access token, service token,
   webhook receiver, admin impersonation, mobile refresh, WebSocket upgrade.
2. **Where identity is materialized** — the middleware, guard, or filter that
   turns a credential into a principal. Note *every* place that assigns it; a
   second assignment path is a second trust decision.
3. **Where identity is consumed** — and specifically which handlers read the
   tenant from the principal versus from request input. The latter set is the
   IDOR/BOLA population for Step 3.
4. **Unauthenticated routes**, enumerated explicitly (allowlists, `@Public`,
   `permitAll()`, wildcard matchers). A route that is unauthenticated by
   accident is the highest-yield bug in this whole stage.

Record the map in the ledger's `identity_surface` block; everything after is
scored against it.

### Step 2: Credentials, Sessions, and Tokens

Score against `identity_docket.md` §1–§4 and §7: password hashing algorithm and
parameters, password policy, session id entropy and regeneration, true
server-side invalidation, the RFC 8725 JWT checklist, refresh-token rotation and
reuse detection, and OAuth/OIDC/SAML validation.

Two habits decide accuracy here. Audit the **verification** path, not the
signing path — algorithm confusion and `alg: none` live in the verifier. And
check whether logout, password change, and role downgrade actually invalidate
anything; a long-lived stateless token with no denylist makes all three
cosmetic.

### Step 3: Authorization Enforcement

Audit enforcement, not intent. First identify the model in use
(middleware-per-route, decorator, policy objects, per-query scoping, or ad-hoc
`if` statements — ad-hoc is not automatically wrong, but it makes omission the
default failure mode, so sweep every handler when you find it).

Then work through the three authorization layers, which fail independently:

- **Object level (IDOR/BOLA)** — every handler that reads an identifier from
  request input must scope the lookup to the principal. Writes and deletes as
  much as reads; UUIDs are not a substitute for the check.
- **Function level (BFLA)** — privileged routes reachable by a normal
  principal: unguarded admin routers, UI-only role checks, method-specific gaps,
  GraphQL mutations bypassing the REST guard.
- **Property level (BOPLA)** — mass assignment inbound, over-serialization
  outbound. `tenancy_isolation.md` §6 (`AUTHZ-04`) carries the field list to
  verify is not settable.

Sweep the indirect paths too — background jobs, exports, webhooks, GraphQL
resolvers, batch endpoints, admin CLI — because they routinely skip the
middleware that guards the HTTP path.

### Step 4: Tenant Isolation

Confirm or infer the model, then run the population sweep in
`tenancy_isolation.md` §2: enumerate tenant-owned tables (including transitive
ones), enumerate every read and write against them across ORM calls, raw SQL,
views, jobs, reports and admin tooling, and classify each site as SCOPED,
SCOPED-BY-DEFAULT, UNSCOPED, or SPOOFABLE.

`SPOOFABLE` — a predicate whose tenant value comes from request input — deserves
its own finding text, because it looks correct in review.

Where RLS is used, run §3's footgun checklist; where it is not available (MySQL
and most non-Postgres engines), say so in the ledger and weight the sweep
accordingly, since without a database-level net every unscoped query is a live
defect rather than a defense-in-depth gap. §4 covers isolation beyond the
primary database: caches, object storage, search indexes, queues, quotas,
webhooks.

**Put the regression test from §5 in every tenancy finding's `mitigation`.**
A test asserting that a tenant-A principal gets 404 for a tenant-B resource is
worth more than most tooling, and it is the one control that survives
refactors. Record in the ledger whether such a test already exists.

### Step 5: MFA, Anti-Automation, and Account Recovery

Score against `identity_docket.md` §5–§6: MFA availability, admin enforcement,
enrollment and verification integrity, recovery codes, and — the part teams
miss — the **bypass paths** (reset flows that skip MFA, legacy API paths,
"remember this device" with no expiry or binding).

For anti-automation, both dimensions are needed: per-account limiting stops
password spraying, per-source limiting stops enumeration, and a limiter held in
process memory is per-instance and therefore ineffective behind a load balancer.
Then audit reset tokens, invite defaults (least privilege, not admin), and
enumeration oracles across login, signup, reset, and invite — in body, status
code, and timing.

### Step 6: Critical-Operation Integrity

Concurrency defects in money-adjacent code are security defects. Enumerate the
operations where a duplicate execution creates value or crosses a limit —
coupon redemption, withdrawal, credit consumption, seat assignment, invite
acceptance, plan upgrade, referral bonus — and for each look for a transaction
with a lock, an atomic conditional update, a database-level unique constraint,
or an idempotency key on the write endpoint.

A `SELECT` followed by a separate `UPDATE` outside a transaction is a
time-of-check/time-of-use window; report it with both line numbers. Verify the
constraint lives in the database, not only in application code — two instances
defeat an in-process guard.

### Step 7: Secrets

Sweep for committed secrets in source, config, notebooks, fixtures, CI
definitions, Dockerfiles, and manifests — and in VCS history via the Block A
step 5 carve-out, since a secret removed in a later commit is still exposed.

Look specifically for insecure fallbacks (`process.env.SECRET || 'dev'`), which
are the finding, because a misconfigured deploy silently gets them. Then check
runtime sourcing (secret manager via workload identity versus static keys), and
whether a signing key can be rotated without invalidating every session at once.

**Every leaked-secret finding must say in `mitigation` that the credential has
to be rotated** — removal from history is not remediation.

### Step 8: Write Findings and the Ledger

Follow `references/findings_contract.md`. The rule that matters most in this
domain: **trace the full request path for at least one representative route
before concluding that a check is missing**, and list what you traced in the
description. A guard may live in a base controller, a router-level middleware, a
policy object, an ORM default scope, an RLS policy, or an API gateway. This one
habit removes most false positives here.

Prefer one concrete site over a general claim, and report each site of a
sweeping class individually with the shared root cause repeated, so
`ray-condenser` can cluster without losing detail.

### Step 9: Complete

Report findings by severity, controls by state, the inferred tenancy model with
its evidence, the unscoped-query count, and every `UNKNOWN` with its blocker.
Do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| SQLi, XSS, CSRF, SSRF, timing-unsafe comparison | `/ray-crucible` |
| Cookie flags, consent, retention, rights obligations | `/ray-custodian` |
| CORS, tokens in `localStorage`, error leakage, credential logging | `/ray-seam` |
| General rate limiting, API key lifecycle at the gateway, audit-log coverage | `/ray-sentry` |
| Database roles, `BYPASSRLS`, encryption at rest | `/ray-vault` |
| Environment isolation, SSO for production access, secret-manager topology | `/ray-citadel` |

Login-specific rate limiting is audited here because it is an authentication
control; the general limiter is `/ray-sentry`'s. RLS policy *correctness for
tenancy* is here; RLS as a *privilege* concern is `/ray-vault`'s. Overlap is
merged by `ray-condenser`.
