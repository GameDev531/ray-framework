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
customer B's data. That failure is almost never a missing feature; it is a
single query that forgot a `tenant_id`, a single handler that trusted an id from
the URL, or a single role check that lives in the frontend. `/ray-turnstile`
sweeps for exactly those.

## Command Definition

- **Command:** `/ray-turnstile`
- **Description:** Audits credential storage, session and token handling,
  authorization enforcement, tenant isolation, and secret management, and writes
  findings plus a control ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: absolute path to the pinned, read-only
    code snapshot (CODE_ROOT for all snapshot-relative paths).
  - `--snapshot_id` / `SNAPSHOT_ID`: the pass snapshot identifier — sentinel
    check (Block A step 2) and `discovery_commit` stamp.
  - `--state_root`: absolute path to the `workspace/` state directory.
    STATE-RELATIVE — NEVER prefixed with CODE_ROOT.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--tenancy <shared_schema|schema_per_tenant|db_per_tenant|single_tenant|auto>`:
    the isolation model to audit against. Absent → `auto` (infer it in Step 3,
    and record the inference and its evidence in the ledger).
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT falls back to the
    current directory, `snapshot_pinned` is false, no `discovery_commit`.

## Input/Output Contract

- **Reads**:
  - `workspace/.ray_state.json` — `pass_number`, `active_snapshot`. Optional.
  - `workspace/plan.json` (optional). If investigations target auth or tenancy
    modules, prioritize them; missing/empty → full sweep.
  - `workspace/kb/THREAT_MODEL.md` and `workspace/kb/entities/*.md` (optional) —
    trust boundaries, attacker profiles, prior auth findings.
  - `ray-turnstile/references/identity_docket.md` and
    `ray-turnstile/references/tenancy_isolation.md` — read BOTH before scoring.
  - Target source: auth modules, middleware, route definitions, ORM models and
    query builders, migrations and RLS policies, background jobs, config and
    environment templates.
  - `workspace/ledgers/ray-turnstile.json` from the previous pass, if present.
- **Writes**:
  - `workspace/findings/<uuid>.json` — standard Ray findings schema.
  - `workspace/ledgers/ray-turnstile.json` — the control ledger for this pass.
  - `workspace/archive/ledgers/ray-turnstile_pass_${N}.json` — copy of the
    previous ledger, written before overwrite.
- **Preconditions**:
  - Target files must be readable. This stage never authenticates against a
    live system and never runs credential tests; proving an authorization
    bypass is `/ray-detonator`'s job, on a sandboxed target.
- **Idempotency Guarantee**:
  - Findings are new UUID files each run (`ray-condenser` merges duplicates).
    The ledger is archived per pass and then deterministically overwritten.

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

- CODE-READING stage: Block A step 0's findings-only skip does NOT apply.
- Secret scanning (Step 7) inspects committed files under CODE_ROOT and, for
  history, uses the VCS carve-out (Block A step 5) in the LIVE repo root.
- This skill's `references/*.md` sit next to `SKILL.md`, not under CODE_ROOT.

### Step 1: Load Context and Map the Identity Surface

Read `pass_number` and `active_snapshot` from `workspace/.ray_state.json`;
resolve the ISO 8601 timestamp; hold `snapshot_id` for `discovery_commit`.
Read the threat model and both reference dockets.

Then build the **identity surface map** — you cannot audit enforcement without
knowing every way a request acquires an identity:

1. **Authentication entrypoints**: login, signup, password reset, magic link,
   OAuth/OIDC callback, SAML ACS, API key header, personal access token,
   service-to-service token, webhook receiver, impersonation/"login as user"
   admin feature, mobile refresh endpoint, WebSocket upgrade handshake.
2. **Where identity is materialized**: the middleware, decorator, guard, or
   filter that turns a credential into a principal (`req.user`, `ctx.session`,
   `current_user`, `SecurityContext`). Note every place that ASSIGNS it — a
   second assignment path is a second trust decision.
3. **Where identity is consumed**: every handler, resolver, job, and query that
   reads the principal. Note which read the tenant from the principal and which
   read it from request input — the latter is the IDOR/BOLA population.
4. **Unauthenticated routes**: enumerate them explicitly (allowlists, `@Public`
   decorators, `permitAll()`, matchers with `**`). A route that is
   unauthenticated by accident is the highest-yield bug in this whole stage.

Record the map in the ledger's `identity_surface` block. Everything after this
step is scored against it.

### Step 2: Credentials, Sessions, and Tokens

Score against `references/identity_docket.md` §1–§4.

1. **Password storage**: find the hashing call. `argon2id` (or `scrypt`, or
   `bcrypt` at an adequate cost) is expected. MD5, SHA-1, SHA-256, unsalted
   digests, a home-rolled HMAC, or reversible encryption of passwords are all
   HIGH-severity findings anchored at the hashing line. Check the verification
   path too: a constant-time comparison of hashes, and a rehash-on-login path
   when parameters are raised.
2. **Password policy**: minimum length (see the docket — length beats
   composition), a maximum that does not truncate silently (bcrypt's 72-byte
   limit is a real, exploitable truncation), a breached-password check, and the
   absence of forced periodic rotation and of arbitrary composition rules.
3. **Sessions**: identifier entropy and generator (`Math.random()` for a session
   id is a finding), regeneration on privilege change (login, role change,
   impersonation — absence is session fixation), idle and absolute lifetimes,
   and true server-side invalidation on logout and on password change.
4. **JWT / self-contained tokens**: run the full RFC 8725 checklist in the
   docket — algorithm pinned on the verify call, `alg: none` rejected, HS/RS
   confusion impossible, key length, `exp`/`nbf`/`iat` validated, `iss` and
   `aud` validated, `kid` not used as a path or SQL lookup, and a revocation
   story for both access and refresh tokens. A stateless token with a long TTL
   and no denylist means logout is cosmetic.
5. **Refresh tokens**: rotation on use, reuse detection (a replayed refresh
   token should invalidate the family), storage as a hash, and binding to a
   device or client where applicable.
6. **OAuth/OIDC**: `state` validated (CSRF on the callback), PKCE for public
   clients, exact redirect-URI matching (prefix/wildcard matching is an account
   takeover primitive), ID-token signature and `aud`/`iss`/`nonce` validation,
   and no acceptance of tokens minted for a different client.

### Step 3: Authorization Enforcement

This is where most real SaaS breaches live. Audit enforcement, not intent.

1. **Determine the enforcement model**: middleware-per-route, decorator,
   policy/ability objects (CanCan, Pundit, Casbin, OPA), per-query scoping, or
   ad-hoc `if` statements. Ad-hoc is not automatically wrong, but it makes
   omission the default failure mode — sweep every handler when you find it.
2. **Object-level authorization (IDOR / BOLA)**: for every handler that reads an
   identifier from request input (path, query, body, header), verify the lookup
   is scoped to the principal:
   - Expected: `WHERE id = $1 AND tenant_id = $2` (or an equivalent policy check
     between the fetch and the response).
   - Failing shape: fetch by id, then return — the "authorization" being the
     fact that the UI never shows other ids.
   - UUIDs do **not** substitute for the check. Note that explicitly in the
     finding when the code comments claim otherwise; unguessable ids leak
     through referers, logs, exports, and shared links.
   - Check writes and deletes as well as reads. A scoped `GET` next to an
     unscoped `DELETE` is common and worse.
3. **Function-level authorization (BFLA)**: admin or privileged routes reachable
   by a normal principal. Look for admin routers mounted without a guard,
   role checks present on the UI but not the API, HTTP-method-specific gaps
   (`GET` guarded, `PATCH` not), and GraphQL mutations that bypass the REST
   guard entirely.
4. **Property-level authorization (BOPLA / mass assignment)**: handlers passing
   whole request bodies into an ORM (`User.update(req.body)`,
   `Model.objects.update(**data)`, `model.assign_attributes(params)`).
   Verify there is a field allowlist and that `role`, `tenant_id`, `is_admin`,
   `plan`, `balance`, `verified`, and price/quantity fields are not settable
   from input. Also check the reverse direction: serializers that return whole
   records (password hashes, internal flags, other tenants' ids).
5. **Frontend-only authorization**: a hidden button, a route guard in the SPA, a
   `v-if="isAdmin"`. Find the corresponding backend check; if it does not exist,
   the finding is the missing backend check, anchored at the handler.
6. **Indirect paths**: background jobs, exports, webhooks, GraphQL resolvers,
   batch endpoints, and admin CLI commands frequently skip the middleware that
   guards the HTTP path. Sweep them explicitly.

### Step 4: Tenant Isolation

Score against `references/tenancy_isolation.md`.

1. **Infer or confirm the model** (`--tenancy`): shared schema with a
   `tenant_id` column, schema-per-tenant, database-per-tenant, or single-tenant.
   Record the evidence for the inference.
2. **Shared-schema audit**: enumerate every table carrying tenant data, then
   enumerate every query touching those tables (ORM calls, query builders, raw
   SQL, migrations, reports, jobs, admin tools). Every one must be scoped. The
   ledger records the count of scoped vs. unscoped call sites — an unscoped
   count above zero is a finding per site, not one aggregate finding.
3. **Row-Level Security**: if RLS is used, run the footgun checklist in the
   reference — `FORCE ROW LEVEL SECURITY` when the app role owns the table, the
   app role lacking `BYPASSRLS` and not being a superuser, policies covering
   `SELECT`/`INSERT`/`UPDATE`/`DELETE` (a `USING` clause without `WITH CHECK`
   lets a tenant write rows into another tenant), and — critically — how the
   tenant context is set relative to connection pooling. `SET` (session-scoped)
   through a transaction-pooling PgBouncer leaks context between tenants under
   concurrency; `set_config(..., true)` / `SET LOCAL` inside the transaction is
   the correct shape.
4. **Cross-cutting stores**: caches (Redis keys without a tenant prefix), object
   storage paths, search indexes, queues, rate-limit counters, and exports.
   A cache key of `user:profile:123` in a shared-schema app is a cross-tenant
   read waiting for an id collision or a poisoning bug.
5. **The regression test.** For every tenancy control you find, put the
   corresponding test in the finding's `mitigation`: *a test where a principal
   of tenant A requests a resource of tenant B and MUST receive 404 or 403*.
   The guide this suite is built from puts it plainly, and it is true: that one
   test is worth more than most tooling. Note in the ledger whether such a test
   already exists in the repository — its absence is itself a MEDIUM finding.

### Step 5: MFA, Anti-Automation, and Account Recovery

1. **MFA**: is a second factor available at all (TOTP, WebAuthn/passkeys, push)?
   Is it enforceable for admins? Check enrollment (is the secret shown once and
   stored encrypted?), verification (is the TOTP window narrow, are used codes
   burned to prevent replay?), and recovery codes (single-use, hashed).
   **Check the bypass paths**: password reset that skips MFA, an API-key path
   that ignores it, "remember this device" cookies with no expiry or binding.
2. **Credential stuffing and brute force**: rate limiting on login **per account
   AND per IP** (per-IP alone is defeated by a botnet; per-account alone is
   defeated by spraying one password across many accounts), lockout or
   exponential backoff, CAPTCHA or proof-of-work escalation, and breached-
   password screening (k-anonymity range query — the docket describes the flow;
   never send a full password or full hash to a third party).
3. **Password reset**: token entropy ≥128 bits from a CSPRNG, single use,
   short expiry, stored hashed, invalidated on use and on password change, and
   delivered without leaking whether the account exists. The response and timing
   must be identical for existing and non-existing accounts.
4. **Account enumeration**: login, signup, reset, and invite responses that
   differ by existence — in body, status code, or measurable timing.
5. **Invites and onboarding**: default role for a new member. If it is admin or
   owner, that is a finding. Check that invite tokens are scoped to one email
   and one tenant, expire, and cannot be replayed to join a different tenant.
6. **Impersonation**: any "login as user" feature must be gated, audit-logged,
   time-boxed, and must not allow impersonating another tenant's owner. An
   unlogged impersonation feature is a privileged, invisible read of everything.

### Step 6: Critical-Operation Integrity

Concurrency defects in money-adjacent code are security defects.

1. Enumerate operations where a duplicate execution creates value or crosses a
   limit: coupon redemption, balance withdrawal, credit consumption, seat
   assignment, invite acceptance, plan upgrade, referral bonus, quota check.
2. For each, look for a **transaction with a lock** (`SELECT … FOR UPDATE`, or
   an atomic conditional `UPDATE … WHERE balance >= $1`), a **unique
   constraint** at the database level, or an **idempotency key** on the write
   endpoint. A `SELECT` followed by a separate `UPDATE` outside a transaction is
   a time-of-check/time-of-use window; report it with the two line numbers.
3. Check that the constraint is in the **database**, not only in application
   code — two application instances defeat an in-process guard.
4. Note where the state machine allows a backwards transition (refund after
   refund, activation after cancellation).

### Step 7: Secrets

1. **Committed secrets**: sweep for private keys, API tokens, cloud
   credentials, database URLs with passwords, JWT signing keys, and webhook
   secrets in source, config, notebooks, test fixtures, CI definitions,
   Dockerfiles, and Kubernetes manifests. Check `.gitignore` actually excludes
   `.env`, and check VCS history via the Block A step 5 carve-out — a secret
   removed in a later commit is still exposed.
2. **Default and weak values**: `JWT_SECRET=secret`, `changeme`, a signing key
   short enough to brute force, a development fallback that activates when the
   environment variable is unset (`process.env.SECRET || 'dev'`) — that fallback
   is the finding, because a misconfigured deploy silently gets it.
3. **Runtime sourcing**: secrets pulled from a manager (Vault, Secrets Manager,
   Parameter Store, Doppler) via a workload identity, versus static keys on disk
   or in image layers. Check CI for static cloud keys where OIDC federation is
   available.
4. **Rotation and revocation**: is there any mechanism to rotate the signing key
   without invalidating every session at once (key id + overlap window)? Its
   absence guarantees that a leaked key will not be rotated promptly.
5. **In every leaked-secret finding**, state in `mitigation` that removal from
   history is NOT sufficient — the credential must be rotated, because it is
   already compromised.

### Step 8: Evidence Discipline

- **Anchor every finding at a line you read.** `code_paths` MUST resolve under
  CODE_ROOT. Never invent a line.
- **Follow the chain before declaring a check missing.** A guard may live in a
  base controller, a router-level middleware, a policy object, an ORM default
  scope, a database RLS policy, or an API gateway. Trace the full request path
  for at least one representative route before concluding that authorization is
  absent, and list in the description what you traced. This single rule
  eliminates most false positives in this domain.
- **Prefer one concrete site over a general claim.** "Authorization is
  inconsistent" is unactionable. "`GET /api/invoices/:id` at
  `src/routes/invoices.ts:42` loads by primary key with no tenant predicate,
  while the sibling `list` handler at line 20 scopes correctly" is a finding
  that survives validation and can be reproduced.
- **Enumerate the population.** For sweeping classes (unscoped queries,
  unguarded routes) report each site, with the shared root cause repeated in
  each description so `ray-condenser` can cluster them without losing detail.
- **Do not test credentials against anything live.** No login attempts, no
  password spraying, no token replay against a deployed host. Reproduction is
  `/ray-detonator`'s job in a sandbox; give it a precise `mitigation` and a
  crisp description instead.
- **Severity, conservatively.** Cross-tenant data access reachable by an
  authenticated user: HIGH, and CRITICAL only when you can describe an
  unauthenticated or trivially scalable path to bulk data. Weak password hashing:
  HIGH. Missing MFA option: MEDIUM. Enumeration oracles: LOW–MEDIUM.
  `ray-gauge` applies the final caps.

### Step 9: Compile and Write Findings

Create `workspace/findings/` if missing; write one JSON object per finding to
`workspace/findings/<uuid>.json`, no text around the JSON.

Compute before writing each file:

1. **`cwe` (optional)** — common ones here: `CWE-639`/`CWE-284`/`CWE-863`
   (authorization), `CWE-566` (ACL bypass via key), `CWE-915`/`CWE-1321`
   (mass assignment / prototype pollution), `CWE-916`/`CWE-759`/`CWE-327`
   (weak or unsalted hashing), `CWE-384` (session fixation), `CWE-613`
   (insufficient session expiration), `CWE-347` (improper signature
   verification), `CWE-798` (hardcoded credentials), `CWE-307` (improper
   restriction of authentication attempts), `CWE-640` (weak recovery),
   `CWE-204`/`CWE-203` (observable discrepancy / enumeration), `CWE-367`
   (TOCTOU), `CWE-269` (improper privilege management).
2. **`signature`** — first 16 hex chars of
   `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`;
   `normalized_title` = title lowercased with all non-`[a-zA-Z0-9]` stripped
   (empty result → first 16 hex of `sha256(raw title)`); `cwe_part` = the `cwe`
   value or `""`; `primary_target` = first `code_paths` entry without its
   `:line`. Empty `primary_target` → hash
   `normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(",")`.
   Compute once; never recompute.
3. **`lineage_id`** — inherit from an archived finding in
   `workspace/archive/findings_pass_*/` or `workspace/archive/loop*_findings/`
   with the same `signature` (highest pass number wins); otherwise a fresh
   UUIDv4. `ray-prospector` Step 5a's basename-rename fallback applies
   identically. STATE-RELATIVE paths.
4. **`discovery_commit`** — `active_snapshot.snapshot_id` verbatim when pinned;
   omit the key entirely in DEGRADED mode.

#### Findings Schema Format (per file)

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Missing tenant predicate in invoice lookup handler",
  "description": "Root cause: which identity or authorization decision is wrong, the exact request path traced (entrypoint -> middleware -> handler -> query), and what an attacker controls at each hop. State explicitly which guards you checked and ruled out.",
  "impact": "Concrete outcome (e.g., any authenticated user reads any tenant's invoices by iterating an id; forged tokens grant admin; logout does not revoke access).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["src/routes/invoices.ts:42", "src/db/queries/invoices.ts:17"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-639 (optional)",
  "signature": "First 16 hex chars of the sha256 defined above.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The corrective change AND the regression test that keeps it: e.g. 'scope the query to the session tenant; add a test where a tenant-A principal requests a tenant-B invoice id and asserts 404'.",
  "access_control_id": "Optional. Ledger control id, e.g. 'AUTHZ-02'.",
  "history": [
    {
      "stage": "turnstile",
      "action": "created",
      "details": "Identity/authorization audit finding recorded.",
      "pass_number": 1,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

Default `"status": "PROVISIONALLY_VALID"`. Use `"NEEDS_RESEARCH"` when
enforcement plausibly lives outside the snapshot (an API gateway policy, an
external authorization service) and say what artifact would resolve it.

### Step 10: Write the Control Ledger

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`; if missing,
   `max` of the archive pass folders + 1, defaulting to `1`.
2. If `workspace/ledgers/ray-turnstile.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-turnstile_pass_${N}.json`.
3. Write `workspace/ledgers/ray-turnstile.json`:

```json
{
  "skill": "ray-turnstile",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "tenancy_model": {
    "value": "shared_schema",
    "source": "inferred",
    "evidence": ["migrations/0003_add_tenant_id.sql:5"]
  },
  "identity_surface": {
    "auth_entrypoints": ["src/auth/login.ts:22", "src/auth/oauth/callback.ts:14"],
    "principal_assignments": ["src/middleware/session.ts:31"],
    "unauthenticated_routes": ["GET /health", "POST /webhooks/stripe"],
    "tenant_scoped_tables": ["invoices", "projects"],
    "unscoped_query_sites": ["src/reports/monthly.ts:88"]
  },
  "controls": [
    {
      "id": "AUTHZ-02",
      "control": "Object lookups scoped to the principal's tenant",
      "state": "PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN",
      "evidence": "src/db/queries/invoices.ts:17",
      "finding_ids": [],
      "note": "12 of 14 call sites scoped; 2 unscoped, reported individually."
    }
  ]
}
```

Every control id from `references/identity_docket.md` §8 and
`references/tenancy_isolation.md` §6 MUST appear exactly once, including passing
and `UNKNOWN` ones.

### Step 11: Complete

Report: findings by severity, controls by state, the inferred tenancy model with
its evidence, the unscoped-query count, and every `UNKNOWN` with its blocker.
Do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

- **SQL injection, XSS, CSRF, SSRF** → `/ray-crucible`. A CSRF token missing on
  a state-changing form is there, not here; a session cookie without `SameSite`
  is `/ray-custodian`.
- **Cookie flags, consent, retention, rights endpoints** → `/ray-custodian`.
  Report the authorization defect on a rights endpoint here; the privacy
  obligation there.
- **CORS, tokens in `localStorage`, error-message leakage, logging of
  credentials** → `/ray-seam`.
- **Rate limiting as a service-protection concern, API key scoping and
  rotation at the gateway, audit-log completeness** → `/ray-sentry`. Login-
  specific rate limiting is audited here because it is an authentication
  control; the general limiter is there.
- **Database roles, RLS at the privilege level, encryption at rest** →
  `/ray-vault`. RLS *policy correctness for tenancy* is audited here.
- **Environment isolation, SSO for production access, secret manager topology**
  → `/ray-citadel`.
