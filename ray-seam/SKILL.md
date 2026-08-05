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
in the request body. Role in the JWT nobody verifies. Token in `localStorage`.
API key in the bundle. Stack trace in the 500 response. Validation only in the
form.

## Command Definition

- **Command:** `/ray-seam`
- **Description:** Audits client/server trust-boundary defects across backend
  handlers, frontend code, logging, caching, and resource limits, writing
  findings plus a control ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**:
  - `workspace/.ray_state.json` — `pass_number`, `active_snapshot`. Optional.
  - `workspace/plan.json` (optional; ordering hint only).
  - `workspace/kb/THREAT_MODEL.md`, `workspace/kb/entities/*.md` (optional).
  - Target source: backend handlers and middleware, validation schemas,
    serializers, logger configuration, frontend source and build configuration,
    service workers, cache and CDN configuration.
  - `workspace/ledgers/ray-seam.json` from the previous pass, if present.
- **Writes**:
  - `workspace/findings/<uuid>.json` — standard Ray findings schema.
  - `workspace/ledgers/ray-seam.json` — control ledger for this pass.
  - `workspace/archive/ledgers/ray-seam_pass_${N}.json` — copy of the previous
    ledger before overwrite.
- **Preconditions**:
  - Target files must be readable. Where a built bundle is not present in the
    snapshot, audit the build configuration and source instead, and say so —
    never claim to have inspected a bundle you did not read.
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

Skill-specific note: if you need to build the frontend to inspect a bundle,
build in a PRIVATE SHADOW copy (Block A step 4) — never with `cwd` = CODE_ROOT.
Prefer auditing the source and build configuration; a build is rarely necessary
to establish that a secret is referenced from client code.

### Step 1: Load Context and Map the Seam

Read `pass_number`, `active_snapshot`, and the threat model. Then map the seam
itself, because every later step is scored against it:

1. **Every request handler** and the shape it accepts (route, method, body
   schema or absence of one).
2. **Every response serializer** and the shape it emits.
3. **What the client holds**: tokens, personal data, feature flags, prices,
   permissions, identifiers.
4. **What the client sends back** that the server then uses in a decision. This
   list is the highest-value artifact in this stage: every entry is a candidate
   finding until you find the server-side revalidation.

### Step 2: Server-Side Validation

1. **Schema validation at every entrypoint.** Look for a declarative schema
   (zod, yup, joi, pydantic, class-validator, JSON Schema, Rails strong
   parameters, ASP.NET model validation) applied to body, query, params, and
   headers that feed logic. A handler that reads `req.body.x` with no schema is
   the finding; anchor at the handler.
2. **Strictness.** A schema that permits unknown keys (`.strict()` /
   `additionalProperties: false` / `extra="forbid"` absent) lets extra fields
   through to whatever consumes the object — the enabling half of mass
   assignment.
3. **Type and range.** Numbers bounded, strings length-capped, enums closed,
   arrays size-capped, dates sane. An unbounded array or string is a
   denial-of-service and a storage-abuse vector.
4. **Validation only on the client.** A form with `required`, `maxlength`, and a
   regex, and no server counterpart, is the classic case. Report the missing
   server check, not the client one.
5. **Validation in the wrong order.** Validation applied after the value was
   already used, or after a side effect.

### Step 3: Mass Assignment and Over-Serialization

Both directions of the same mistake.

- **Inbound**: `Model.update(req.body)`, `Object.assign(user, req.body)`,
  `**request.data`, `assign_attributes(params)`, `patchValue(...)`. Confirm an
  explicit allowlist exists and that `role`, `is_admin`, `tenant_id`, `plan`,
  `credits`, `balance`, `verified`, `price`, and `status` are not settable.
  (When the field crosses into authorization, `/ray-turnstile` also owns it —
  report and let `/ray-condenser` merge.)
- **Outbound**: a serializer that dumps the model. Look for password hashes,
  reset tokens, internal notes, other users' identifiers, soft-deleted records,
  and fields the UI never displays. The classic tell is a mobile or SPA response
  containing far more than the screen shows.
- **GraphQL**: check that field-level authorization exists and that introspection
  and suggestions are disabled in production (limits are `/ray-sentry`).

### Step 4: Error Handling and Information Leakage

1. **Production error responses**: generic message plus a correlation id, with
   details logged internally. Grep for stack traces reaching the client
   (`err.stack`, `traceback.format_exc`, `printStackTrace`, `DEBUG = True`,
   `app.debug`, `NODE_ENV` not enforced, framework debug pages).
2. **Detailed messages that are themselves oracles**: "user not found" vs
   "wrong password"; "tenant B does not exist" vs "forbidden"; a validation
   error echoing the database constraint name.
3. **Fail-open handling** — the highest-value defect in this step and the reason
   OWASP added A10:2025. A `catch` that logs and then continues, a permission
   check inside a `try` whose `catch` returns `true`, a timeout on the
   authorization service that defaults to allow, a feature flag lookup failing
   open. Trace what happens when each security-relevant call throws.
4. **Debug and introspection endpoints** reachable in production builds
   (`/debug`, source maps served publicly, framework profilers). Endpoint
   exposure in general is `/ray-sentry`; report the ones the frontend build
   itself ships.

### Step 5: Client-Side Storage and Bundles

1. **Credentials in web storage.** Tokens in `localStorage`/`sessionStorage` are
   readable by any script the page runs, so any XSS becomes account takeover.
   The recommended shape is an `HttpOnly` cookie for the session, or an
   in-memory token with a cookie-based refresh. Report the storage site, and
   note in `mitigation` that the refresh flow must change with it.
2. **Personal data cached client-side** and not cleared on logout (see also
   `/ray-custodian` `STORE-01`).
3. **Secrets in the bundle.** Any build-time variable exposed to the client
   (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`,
   `NUXT_PUBLIC_*`) is public. Enumerate every one and classify: publishable
   keys (fine), private API keys, database URLs, signing secrets, service-role
   keys (findings). A service-role key in a frontend bundle is a HIGH finding
   with a one-line exploit.
4. **Source maps in production** exposing server-side code or comments.
5. **Hidden UI as a control**: a component gated on `isAdmin` with no
   corresponding server check (the server check is `/ray-turnstile`'s finding;
   note it here and cross-reference).
6. **Client-side "encryption"** of values the server must trust, or obfuscation
   presented as a security control.

### Step 6: CORS and Cross-Origin Messaging

1. **CORS**: `Access-Control-Allow-Origin: *` combined with
   `Allow-Credentials: true` is rejected by browsers, but the pattern it hides —
   **reflecting the request `Origin` header** — is the real defect: it is
   equivalent to allowing every origin, with credentials. Grep for
   `origin: true`, `callback(null, true)`, `req.headers.origin` echoed into the
   header, and regex origin matching (`/example\.com$/` also matches
   `evilexample.com`).
2. Check `Allow-Methods`, `Allow-Headers`, `Expose-Headers`, and preflight
   caching for over-permissiveness, and whether `null` origin is allowed
   (sandboxed iframes and local files send it).
3. **`postMessage`**: every `addEventListener('message', …)` must check
   `event.origin` against an expected value before using `event.data`, and every
   `postMessage(data, targetOrigin)` must pass a specific `targetOrigin` rather
   than `'*'`.
4. **`window.opener`**: links with `target="_blank"` to untrusted destinations
   without `rel="noopener"` (modern browsers default to `noopener`, so this is
   LOW — report it only where the code explicitly re-enables opener access).
5. **Embedded third-party frames** receiving data via query string or fragment.

### Step 7: Logging Hygiene

1. **What must never be logged**: passwords, tokens, session ids, API keys,
   full card numbers, government ids, health data, full request bodies of auth
   routes, `Authorization` and `Cookie` headers.
2. Check the logger's **redaction configuration** (pino `redact`, winston
   formats, structlog processors, Rails `filter_parameters`, Django
   `SENSITIVE_POST_PARAMETERS`). Its absence in an app that logs request bodies
   is the finding.
3. Check **error trackers** for the same problem: local variables in stack
   frames, request bodies, and cookies are shipped by default in several SDKs
   unless a scrubbing hook is set.
4. Check **log injection**: unescaped newlines in user input forge log entries;
   user input rendered in a log viewer without escaping is XSS in the tooling.
5. Personal data in logs is also a retention obligation — cross-reference
   `/ray-custodian` `RET-03`.

### Step 8: Resource Limits and Availability-Adjacent Defects

1. **Body size limits** on every body-parsing middleware
   (`express.json({ limit })`, `client_max_body_size`, multipart limits,
   GraphQL payload size).
2. **Timeouts**: server request timeout, database statement timeout, and — most
   often missing — timeouts on **outbound** calls to third parties. A hung
   upstream with no timeout exhausts the connection pool and takes the service
   down; add circuit-breaker/retry-budget notes where applicable.
3. **Retries without backoff or jitter**, and retry storms amplifying an
   incident.
4. **Unbounded work from a single request**: pagination without a maximum
   `limit`, an export that materializes an entire table, a recursive expansion,
   an image resize with no dimension cap (a decompression bomb).
5. **ReDoS**: nested quantifiers over user input (shared with `/ray-crucible`
   `REDOS`).
6. **Concurrency**: unbounded parallel fan-out from one request.

### Step 9: Caching and Response Correctness

1. **Authenticated responses cached publicly**: `Cache-Control: public` or a
   long `max-age` on personalized content, at the app, the CDN, or a reverse
   proxy. This serves one user's data to another and is a HIGH finding.
2. **`Vary` correctness**: a response varying by `Authorization`, `Cookie`, or a
   tenant header must declare it, or a shared cache will mix users.
3. **Cache key completeness**: keys that ignore a parameter that changes the
   response body, or that include an unkeyed header an attacker can set — the
   basis of cache poisoning and cache deception (`/account.css` served and
   cached as a static asset while returning account data).
4. **Client-side caches**: a service worker caching authenticated responses that
   outlive the session.

### Step 10: Client-Supplied Values In Server Decisions

Walk the list from Step 1.4. For each value the client sends that the server
uses in a decision, verify the server recomputes or revalidates it:

| Value from the client | Correct server behavior |
|---|---|
| Price, discount, tax, shipping, total | Recompute from product ids and the current price table; never accept a submitted amount |
| Quantity, stock, seat count | Validate against inventory inside the transaction |
| `user_id`, `tenant_id`, `role`, `plan` | Take from the authenticated session, never from the payload (`/ray-turnstile` overlaps) |
| Currency, locale, feature flags | Validate against an allowlist; do not let them alter authorization or price |
| Timestamps, expiry, "already paid" | Server clock and server state only |
| File metadata (size, type, checksum) | Recompute from the stored bytes |
| Pagination cursors, sort fields | Validate against an allowlist; do not interpolate into a query (`/ray-crucible` `SQLI`) |
| Callback/redirect URLs | Allowlist (`/ray-crucible` `REDIR`) |
| Webhook payload contents | Verify the signature first (`/ray-sentry`) |

Each unverified entry is a finding anchored at the handler line that consumes it.

### Step 11: Evidence Discipline

- **Anchor at the server-side line that trusts the client**, not at the client
  line that sends the value. The client is not the defect; the trust is.
- **Trace the whole chain before declaring validation absent.** A global
  validation middleware, a framework default (Rails strong parameters, ASP.NET
  model binding attributes), a gateway schema, or a base serializer may cover
  it. State what you checked.
- **Do not report defense-in-depth as if it were exploitable.** A missing
  `rel="noopener"` on a modern browser default, or a timing nuance with no
  attacker path, should be LOW with the limitation stated plainly.
- **Severity defaults**: service-role secret in a client bundle HIGH;
  authenticated response cached publicly HIGH; client-supplied price accepted
  HIGH; fail-open authorization HIGH; mass assignment reaching a privilege field
  HIGH; permissive CORS with credentials MEDIUM–HIGH; token in `localStorage`
  MEDIUM (HIGH where an XSS is confirmed nearby); stack traces in production
  LOW–MEDIUM; missing body limits LOW–MEDIUM. `ray-gauge` applies the caps.
- Never mark CRITICAL without a described unauthenticated path to system or
  bulk-data compromise.

### Step 12: Compile and Write Findings

Create `workspace/findings/` if missing; one JSON object per file at
`workspace/findings/<uuid>.json`, nothing around the JSON.

Compute before writing:

1. **`cwe`** — `CWE-209` (verbose errors), `CWE-532` (sensitive data in logs),
   `CWE-915`/`CWE-1321` (mass assignment / prototype pollution), `CWE-942`
   (permissive CORS), `CWE-522` (insufficiently protected credentials),
   `CWE-798` (hardcoded credentials in a bundle), `CWE-20` (improper input
   validation), `CWE-602` (client-side enforcement of server-side security),
   `CWE-770` (allocation without limits), `CWE-1333` (ReDoS), `CWE-524`/
   `CWE-525` (cache exposure), `CWE-636` (fail-open), `CWE-345` (insufficient
   verification of data authenticity). Omit when none applies.
2. **`signature`** — first 16 hex chars of
   `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`;
   `normalized_title` = title lowercased, stripped to `[a-zA-Z0-9]` (empty →
   first 16 hex of `sha256(raw title)`); `cwe_part` = `cwe` or `""`;
   `primary_target` = first `code_paths` entry without `:line`. Empty →
   hash over `normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(",")`.
   Order `code_paths` with the server-side anchor first. Compute once.
3. **`lineage_id`** — inherit from an archived finding with the same
   `signature` in `workspace/archive/findings_pass_*/` or
   `workspace/archive/loop*_findings/` (highest pass wins), else fresh UUIDv4.
   `ray-prospector` Step 5a's basename fallback applies. STATE-RELATIVE.
4. **`discovery_commit`** — snapshot id verbatim when pinned; omitted in
   DEGRADED mode.

#### Findings Schema Format (per file)

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Order total accepted from the request body without server-side recomputation",
  "description": "Which client-supplied value is trusted, the handler that consumes it, what the server should have recomputed or revalidated, and which existing validation you checked and ruled out.",
  "impact": "Concrete outcome (e.g., a buyer sets any price via DevTools; one user's cached invoice is served to another; a hung upstream exhausts the connection pool).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["server anchor first, e.g. 'src/api/orders.ts:57'", "then the client site, e.g. 'web/src/checkout.tsx:120'"],
  "discovery_commit": "snapshot id verbatim; omit entirely in DEGRADED mode.",
  "cwe": "CWE-602 (optional)",
  "signature": "First 16 hex chars of the sha256 defined above.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The corrective change plus the regression test that keeps it (e.g. 'POST /orders with a tampered total must return the server-computed total; assert the stored order price equals the catalogue price').",
  "seam_control_id": "Optional. Ledger control id, e.g. 'TRUST-01'.",
  "history": [
    {
      "stage": "seam",
      "action": "created",
      "details": "Client/server trust-seam finding recorded.",
      "pass_number": 1,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

### Step 13: Write the Control Ledger

1. Resolve `N` from `pass_number`, else `max` archive pass + 1, else `1`.
2. Copy any existing `workspace/ledgers/ray-seam.json` to
   `workspace/archive/ledgers/ray-seam_pass_${N}.json` (`mkdir -p` first).
3. Write `workspace/ledgers/ray-seam.json` with the same structure the other
   domain skills use: `skill`, `pass_number`, `snapshot_id`, `generated_at`, a
   `client_supplied_values` array (each with `value`, `consumed_at`,
   `revalidated` true/false/unknown), and a `controls` array where each entry is
   `{id, control, state, evidence, finding_ids, note}` with `state` one of
   `PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN`.

Control ids for this stage — each appears exactly once:

| ID | Control |
|---|---|
| `VAL-01` | Schema validation on every entrypoint (body, query, params) |
| `VAL-02` | Schemas reject unknown keys |
| `VAL-03` | Numeric, length, enum, and array bounds enforced |
| `VAL-04` | No validation that exists only on the client |
| `ASSIGN-01` | Write paths use an explicit field allowlist |
| `ASSIGN-02` | Privilege/price/tenant fields not settable from input |
| `ASSIGN-03` | Serializers emit an explicit field set |
| `ERR-01` | Production errors are generic with a correlation id |
| `ERR-02` | No stack traces, framework debug pages, or source maps in production |
| `ERR-03` | No security-relevant fail-open paths |
| `ERR-04` | Error text is not an existence or state oracle |
| `STORE-01` | No credentials in `localStorage`/`sessionStorage` |
| `STORE-02` | Client caches cleared on logout |
| `BUNDLE-01` | No private secrets in client-exposed build variables |
| `BUNDLE-02` | No source maps exposing server code in production |
| `CORS-01` | Explicit origin allowlist; `Origin` never reflected |
| `CORS-02` | Credentials allowed only where required |
| `CORS-03` | Methods, headers, and preflight cache scoped |
| `MSG-01` | `postMessage` receivers validate `event.origin` |
| `MSG-02` | `postMessage` senders pass a specific `targetOrigin` |
| `LOG-01` | Redaction configured for sensitive fields |
| `LOG-02` | Auth-route bodies and credential headers never logged |
| `LOG-03` | Error tracker scrubbing configured |
| `LOG-04` | Log entries escape user-controlled newlines |
| `LIMIT-01` | Body size limits on all parsers |
| `LIMIT-02` | Request and database statement timeouts set |
| `LIMIT-03` | Outbound call timeouts and retry budgets set |
| `LIMIT-04` | Pagination and export result sets bounded |
| `LIMIT-05` | Regexes over user input are linear-time or length-capped |
| `CACHE-01` | Authenticated responses marked `private, no-store` |
| `CACHE-02` | `Vary` declares every credential-bearing header |
| `CACHE-03` | Cache keys complete; no unkeyed attacker-controlled input |
| `CACHE-04` | Service workers do not cache authenticated responses |
| `TRUST-01` | Prices, totals, and discounts recomputed server-side |
| `TRUST-02` | Quantities and stock validated transactionally |
| `TRUST-03` | Identity and role taken from the session, never the payload |
| `TRUST-04` | Timestamps and state transitions decided server-side |
| `TRUST-05` | File metadata recomputed from stored bytes |

### Step 14: Complete

Report: findings by severity, controls by state, the count of client-supplied
values that are not revalidated, and every `UNKNOWN` with its blocker. Do not
print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

- **Injection sinks (including ReDoS as an injection-class regex, SQLi via a
  sort parameter, open redirect)** → `/ray-crucible`. Overlap on ReDoS and on
  mass assignment is intentional; `/ray-condenser` merges.
- **Authentication, authorization, IDOR, tenancy** → `/ray-turnstile`. When a
  mass-assignment field is `role` or `tenant_id`, both stages may report it.
- **Cookies, CSP, consent, retention, personal-data classification** →
  `/ray-custodian`.
- **Rate limiting, exposed internal endpoints, audit logging completeness,
  alerting** → `/ray-sentry`. Logging *hygiene* (what must never be written) is
  here; logging *coverage* (what must always be written) is there.
- **Environment separation, CDN and infrastructure configuration** →
  `/ray-citadel`.
