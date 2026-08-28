# Findings Contract — ray-turnstile

How this stage writes its output. Read it before writing the first finding of a
pass, and again when assembling the ledger.

The mechanics matter because two downstream stages depend on them:
`ray-condenser` clusters on `signature`, and `ray-arbiter` re-reads the
`code_paths` anchors and actively tries to disprove the finding. In this domain
especially, a finding that does not say which guards were checked and ruled out
will be bounced as unproven — the reviewer's first move is to look for the
middleware you might have missed.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults](#2-severity-defaults)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. CWE Set For This Domain](#4-cwe-set-for-this-domain)
- [5. Findings Schema](#5-findings-schema)
- [6. Control Ledger](#6-control-ledger)

______________________________________________________________________

## 1. Evidence Discipline

**Anchor every finding at a line you read.** `code_paths` must resolve under
CODE_ROOT. Never invent a line number.

**Follow the chain before declaring a check missing.** A guard may live in a
base controller, a router-level middleware, a decorator, a policy object, an ORM
default scope, a database RLS policy, or an API gateway. Trace the full request
path for at least one representative route, and list what you traced in the
description. This single habit eliminates most false positives in this domain,
and it is also what makes the finding survive review.

**Prefer one concrete site to a general claim.** "Authorization is inconsistent"
is unactionable. "`GET /api/invoices/:id` at `src/routes/invoices.ts:42` loads by
primary key with no tenant predicate, while the sibling list handler at line 20
scopes correctly" can be reproduced.

**Enumerate the population.** For sweeping classes — unscoped queries, unguarded
routes, spoofable tenant values — report each site, repeating the shared root
cause in each description so `ray-condenser` clusters them without losing the
per-site detail a fix needs.

**Never test credentials against anything live.** No login attempts, no
password spraying, no token replay against a deployed host. Reproduction belongs
to `/ray-detonator` in a sandbox; give it a crisp description and a precise
`mitigation` instead.

**Status.** Default `PROVISIONALLY_VALID`. Use `NEEDS_RESEARCH` when enforcement
plausibly lives outside the snapshot (a gateway policy, an external
authorization service) and name the artifact that would resolve it.

**Rotation language.** Any finding about a leaked or committed secret must state
in `mitigation` that the credential is compromised and has to be rotated —
removing it from history is not remediation, and a reader who takes the wrong
lesson here is left with a live credential.

______________________________________________________________________

## 2. Severity Defaults

Discovery-stage defaults; `ray-gauge` applies the final caps.

| Situation | Default |
|---|---|
| Cross-tenant data access reachable by an authenticated user | HIGH |
| Cross-tenant or bulk access reachable unauthenticated, or trivially scalable | CRITICAL (only with the path described concretely) |
| Weak or unsalted password hashing; reversible password encryption | HIGH |
| JWT verification accepting `alg: none`, unpinned algorithms, or an unvalidated `aud`/`iss` | HIGH |
| Unsigned session payload carrying identity or role | HIGH |
| Mass assignment reaching `role`, `tenant_id`, `is_admin`, or a balance field | HIGH |
| Committed secret, or an insecure default/fallback secret | HIGH |
| Sessions surviving password change or reset | HIGH |
| Reset flow: host-header-derived link, plaintext token storage, or no expiry | MEDIUM–HIGH |
| No MFA option on an application holding sensitive or financial data | MEDIUM |
| Per-instance auth rate limiter behind a load balancer | MEDIUM |
| New members defaulting to admin | MEDIUM |
| TOCTOU on a value-creating operation | MEDIUM–HIGH by what it yields |
| Account-enumeration oracle | LOW–MEDIUM |

______________________________________________________________________

## 3. The Four Computed Fields

**`cwe`** (optional) — from §4. Omit when nothing applies. Decide it first; it
is an input to the signature.

**`signature`** — first 16 hex characters of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:

- `normalized_title` = `title` lowercased with every non-`[a-zA-Z0-9]`
  character stripped; if that leaves it empty, use the first 16 hex chars of
  `sha256(<raw title as UTF-8>)` so distinct non-ASCII titles do not collide.
- `cwe_part` = the `cwe` value or the empty string.
- `primary_target` = the first `code_paths` entry with any trailing `:line`
  stripped; if it is empty or a non-source LOCATOR, hash
  `normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(",")`
  instead.

Order `code_paths` deterministically — for this domain, the **enforcement site
first** (the handler or query that should have checked), then the supporting
sites. Keep that order stable across passes. Compute the signature once at
creation and never recompute it.

**`lineage_id`** — inherit from an archived finding with the same `signature`
under `workspace/archive/findings_pass_*/` or
`workspace/archive/loop*_findings/` (highest pass number wins); otherwise a
fresh UUIDv4. `ray-prospector/SKILL.md` Step 5a's basename-rename fallback
applies unchanged. STATE-RELATIVE paths.

**`discovery_commit`** — `active_snapshot.snapshot_id` verbatim when the
snapshot is pinned; **omit the key entirely** in DEGRADED mode (an absent value
is read downstream as NOT_MATCHED, the conservative branch; an empty string
corrupts matching).

`signature` and `lineage_id` are always computed; only `discovery_commit` is
mode-dependent.

______________________________________________________________________

## 4. CWE Set For This Domain

| CWE | Use for |
|---|---|
| `CWE-639` | Authorization bypass through a user-controlled key (IDOR/BOLA) |
| `CWE-863` | Incorrect authorization |
| `CWE-862` | Missing authorization |
| `CWE-284` | Improper access control (general) |
| `CWE-269` | Improper privilege management (invite defaults, role changes) |
| `CWE-915` | Improperly controlled modification of object attributes (mass assignment) |
| `CWE-213` | Exposure of sensitive information due to incompatible policies (over-serialization) |
| `CWE-916` | Password hash with insufficient computational effort |
| `CWE-759`/`CWE-760` | Missing or predictable salt |
| `CWE-327` | Broken or risky cryptographic algorithm |
| `CWE-347` | Improper verification of a cryptographic signature (JWT, SAML) |
| `CWE-345` | Insufficient verification of data authenticity |
| `CWE-384` | Session fixation |
| `CWE-613` | Insufficient session expiration |
| `CWE-330` | Use of insufficiently random values (session ids, reset tokens) |
| `CWE-307` | Improper restriction of excessive authentication attempts |
| `CWE-640` | Weak password recovery mechanism |
| `CWE-203`/`CWE-204` | Observable discrepancy (account enumeration) |
| `CWE-798` | Use of hard-coded credentials |
| `CWE-1188` | Insecure default initialization (fallback secrets) |
| `CWE-367` | Time-of-check/time-of-use race |
| `CWE-602` | Client-side enforcement of server-side security |
| `CWE-601` | Open redirect in an OAuth `redirect_uri` |

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Missing tenant predicate in invoice lookup handler",
  "description": "Root cause: which identity or authorization decision is wrong, the exact request path traced (entrypoint -> middleware -> handler -> query), what the attacker controls at each hop, and which guards you checked and ruled out.",
  "impact": "Concrete outcome (e.g., any authenticated user reads any tenant's invoices by iterating an id; forged tokens grant admin; logout does not revoke access).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["src/routes/invoices.ts:42", "src/db/queries/invoices.ts:17"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-639",
  "signature": "16 hex chars, per §3.",
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

`mitigation` carries unusual weight in this domain. Authorization fixes are
one-line changes that the next refactor silently undoes; naming the assertion
that would catch the regression is what makes the fix durable. For tenancy
findings, use the test recipe in `tenancy_isolation.md` §5.

______________________________________________________________________

## 6. Control Ledger

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`; if missing or
   invalid, scan `workspace/archive/` for `findings_pass_N` / `loopN_findings`
   and use `max_found + 1`, defaulting to `1`.
2. If `workspace/ledgers/ray-turnstile.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-turnstile_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-turnstile.json`.

```json
{
  "skill": "ray-turnstile",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "generated_at": "<iso8601>",
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

Every control id appears exactly once: the identity ids from
`identity_docket.md` §8 and the authorization/tenancy ids from
`tenancy_isolation.md` §6. `UNKNOWN` entries must carry a `note` saying what
blocked determination — including `NOT_APPLICABLE` for the RLS ids on engines
that have no row-level security, which is a real and common answer.
