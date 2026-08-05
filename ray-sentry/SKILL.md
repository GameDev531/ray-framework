---
name: ray-sentry
description: >-
  Audits service protection and observability: rate limiting and abuse control, exposed internal endpoints, service-to-service authentication, API key scoping and rotation, GraphQL cost limits, webhook signature verification, security audit logging, and anomaly alerting.
  Use when the target exposes APIs or internal services and you need abuse-resistance and detection findings written to workspace/findings/.
  Don't use for authentication mechanics (use ray-turnstile), injection sinks (use ray-crucible), or infrastructure topology and pipelines (use ray-citadel).
---

# Sentry (/ray-sentry)

## System Goal

Service Exposure and Detection Auditor. Answers two questions the rest of the
pipeline does not: **what can an attacker do at volume before anything stops
them**, and **would anyone ever find out**.

Most of this stage's findings are absences rather than defects: no limiter on
the endpoint that calls a paid model, no signature check on the webhook that
marks invoices paid, no audit event when a role changes, no alert when 401s go
vertical. Absences are exactly what a file-by-file review misses, because
nothing is there to read.

## Command Definition

- **Command:** `/ray-sentry`
- **Description:** Audits rate limiting and abuse controls, internal-endpoint
  exposure, service and key authentication, webhook verification, and security
  logging and alerting, writing findings plus a control ledger.
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
  - `workspace/kb/THREAT_MODEL.md`, `workspace/kb/entities/*.md` (optional) —
    especially the availability tiers, which set the severity floor for
    consumption findings.
  - Target source: route definitions, gateway and proxy configuration, IaC,
    middleware, queue and worker code, logging and metrics configuration,
    alerting rules, GraphQL schema and server options, webhook receivers.
  - `workspace/ledgers/ray-sentry.json` from the previous pass, if present.
- **Writes**:
  - `workspace/findings/<uuid>.json` — standard Ray findings schema.
  - `workspace/ledgers/ray-sentry.json` — the endpoint inventory and control
    ledger for this pass.
  - `workspace/archive/ledgers/ray-sentry_pass_${N}.json` — copy of the previous
    ledger before overwrite.
- **Preconditions**:
  - Target files must be readable. This stage performs **no** load testing, no
    request flooding, and no probing of any host. Every verdict comes from
    configuration and code.
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

Skill-specific note: an endpoint reachable "from the internet" is a deployment
property. Judge it from IaC, ingress definitions, service manifests, and bind
addresses in the snapshot. When the snapshot cannot settle it, write the finding
as `NEEDS_RESEARCH` naming the artifact that would — never probe a live host.

### Step 1: Build the Endpoint Inventory

Everything in this stage is scored per endpoint, so build the inventory first.
This inventory is also the answer to API9:2023 (Improper Inventory Management),
which no code pattern reveals on its own.

For each entry record: path and method, protocol (REST/GraphQL/gRPC/WebSocket/
queue consumer/cron), authentication requirement, expected caller (public user,
authenticated user, another service, an operator, a third-party provider), and
its **cost class**:

| Cost class | Examples | Why it matters |
|---|---|---|
| `CHEAP` | static read, health check | Volume alone is the only risk |
| `DB_HEAVY` | search, report, export, aggregate | One request can occupy the database for seconds |
| `PAID` | model inference, SMS, email, geocoding, third-party API | Each request spends money; abuse is a bill, not just load |
| `SIDE_EFFECT` | signup, invite, password reset, order, webhook delivery | Abuse creates state and reaches third parties (spam, enumeration) |
| `PRIVILEGED` | admin actions, impersonation, key issuance | Abuse escalates |

Also enumerate: routes with no authentication, routes present in code but absent
from any API documentation in the repo, deprecated/versioned duplicates
(`/v1` still live beside `/v2`), and anything bound to `0.0.0.0` that the
architecture treats as internal.

### Step 2: Rate Limiting and Abuse Control

Score each endpoint against the layered model. A single global limiter is not
sufficient, and its presence should not be recorded as covering the endpoints
that need their own.

1. **Layer 1 — edge**: CDN/WAF or `nginx limit_req`. Coarse, per-IP, protects
   against floods. Check it exists and that the application is not reachable
   bypassing it (a direct origin address is a common bypass; note it and
   cross-reference `/ray-citadel`).
2. **Layer 2 — application**: per authenticated principal, per API key, per
   tenant. This is the layer that actually protects `PAID` and `SIDE_EFFECT`
   endpoints, because an attacker with one account and many IPs sails through
   layer 1.
3. **Layer 3 — per endpoint class**: login and reset far tighter than reads;
   `PAID` endpoints tied to a quota; `DB_HEAVY` endpoints with concurrency caps.
4. **Counter storage**: an in-process counter (a JS `Map`, a Python dict, the
   default `express-rate-limit` memory store) is per-instance. Behind a load
   balancer with N instances the effective limit is N×, and after a restart it
   is zero. This is one of the most common real defects here — check for a
   shared store (Redis, the gateway) whenever the app runs more than one
   replica.
5. **Response correctness**: `429` with `Retry-After`, and limit headers where
   the API is public. A limiter that returns `500` or silently drops is an
   availability bug of its own.
6. **Quotas and cost ceilings**: is there any per-tenant or per-key monthly
   cap on paid operations? Its absence on a `PAID` endpoint is a finding
   regardless of the request-rate limiter — a rate limit bounds requests per
   second, not spend per month.
7. **Business-flow abuse (API6:2023)**: flows that assume a human — free-trial
   signup, referral bonuses, coupon redemption, invite sending, review posting,
   ticket purchase. Check for a control appropriate to the flow (proof of work,
   verification, device fingerprint, velocity limits), and note that a plain
   rate limit rarely covers these.
8. **Amplification**: endpoints where one request causes many outbound requests
   or messages (bulk endpoints, fan-out notifications, webhook retries), which
   turn a small limit into a large effect.

### Step 3: Internal Endpoint Exposure

1. Enumerate operational endpoints: `/metrics`, `/health`, `/actuator/**`,
   `/debug/pprof`, `/status`, `/graphql` introspection, queue dashboards (Bull
   Board, Flower, Sidekiq Web), admin panels, database UIs (Adminer,
   pgAdmin), tracing UIs, and internal RPC ports.
2. For each, determine binding and exposure from the snapshot: bind address,
   Kubernetes `Service` type, ingress rules, security groups, and whether an
   authentication middleware is applied.
3. **`/health` and `/metrics` deserve individual judgement**: a liveness probe
   returning `{"status":"ok"}` is fine to expose; a health endpoint that reports
   dependency hostnames, versions, and connection strings is an information
   leak; a Prometheus endpoint exposes route inventories, tenant names in label
   values, and traffic patterns.
4. **Defense in depth**: "it is only reachable inside the cluster" is a network
   assertion that one misconfigured ingress overturns. Authentication on
   internal routes is still expected; record its absence as at least a MEDIUM
   finding when the endpoint exposes state.
5. **Forgotten surfaces**: old API versions still routed, staging hostnames in
   production configuration, feature-flag admin endpoints, `.env`/`.git`/backup
   files reachable through the static file handler.

### Step 4: Service-to-Service and Machine Authentication

1. **Between services**: is there any authentication at all, or does the mesh
   assume network position is identity? Expected: mTLS, or OAuth client
   credentials / signed service tokens, with each service validating the caller
   — not merely the caller asserting a header like `X-Service-Name`.
2. **Trusted headers**: any handler that trusts `X-User-Id`, `X-Tenant-Id`,
   `X-Forwarded-For`, or `X-Real-IP` without the proxy chain being enforced.
   Spoofable identity headers are a full authorization bypass when they reach
   an internal service directly; spoofable IP headers defeat IP-based rate
   limits and allowlists.
3. **API keys**: check scoping (can a key do everything the user can?),
   expiration, rotation support (does the system accept an old and a new key
   during an overlap window?), revocation, storage (hashed at rest, like a
   password), presentation (shown once), and identifiable prefixes
   (`sk_live_…`) that let secret scanners and providers detect leaks.
4. **Machine credentials in transit**: keys in query strings (logged
   everywhere) rather than headers.
5. **Queue and cron consumers**: a worker that trusts any message on the queue
   is authenticated only by network access to the broker. Check broker
   authentication and message validation.

### Step 5: Webhooks — Inbound and Outbound

**Inbound** (a third party calls you):

1. **Signature verification** using the provider's scheme
   (`stripe.webhooks.constructEvent`, GitHub `X-Hub-Signature-256`, Slack's
   signing secret, an HMAC over the raw body). A receiver that parses and trusts
   the payload lets anyone mark an invoice paid — this is one of the highest-
   value findings this stage produces.
2. **Raw body preservation**: signature verification over a re-serialized JSON
   body is broken by definition; check that the framework does not consume the
   raw body first.
3. **Constant-time comparison** of the signature (cross-reference
   `/ray-crucible` `TIMING`).
4. **Timestamp/replay window** validated, and **idempotency by event id** so a
   replayed or retried event does not double-apply.
5. **Ordering**: events processed out of order (a `subscription.deleted` before
   a `subscription.created`) that leave state wrong.

**Outbound** (you call a customer's URL):

6. **SSRF** — the URL is user-supplied (`/ray-crucible` `SSRF`); note the
   cross-reference.
7. **Signing** your own deliveries so the receiver can verify, with a per-tenant
   secret.
8. **Retry policy** bounded, with backoff, and a dead-letter path — an unbounded
   retry loop against a slow customer endpoint is a self-inflicted outage.

### Step 6: GraphQL and Batch Interfaces

Only if the target exposes them:

1. **Depth and complexity limits**: without them, a nested query
   (`user { friends { friends { … } } }`) is an unauthenticated database
   amplifier.
2. **Introspection** disabled in production, and field suggestions ("did you
   mean…") disabled — suggestions reconstruct the schema even when
   introspection is off.
3. **Batching and aliasing**: a single request containing hundreds of aliased
   `login` mutations bypasses per-request rate limiting entirely. Check for a
   batch size limit and for limits keyed on operations rather than requests.
4. **Persisted queries** or an allowlist for public-facing APIs.
5. **Field-level authorization** — resolvers frequently bypass the REST
   middleware entirely (`/ray-turnstile` owns the authorization verdict; note
   the seam here).
6. **REST batch endpoints** (`POST /batch`, JSON:API bulk, gRPC streaming) have
   the same amplification property.

### Step 7: Security Logging

Record what must be logged, and check each against the code. Logging *hygiene*
(what must never be logged) is `/ray-seam`'s; this is coverage.

| Event | Must capture |
|---|---|
| Authentication success and failure | timestamp, principal, source IP, user agent, outcome |
| Logout and session invalidation | principal, session id (hashed) |
| MFA enrollment, use, and failure | principal, factor type |
| Password/credential change and reset | principal, initiator |
| Authorization denials (403) | principal, resource, action |
| Role, permission, and membership changes | actor, subject, before/after |
| API key or token issuance and revocation | actor, key id, scopes |
| Access to sensitive personal data | principal, record class, volume |
| Bulk export and report generation | principal, row count, filters |
| Impersonation start and end | operator, subject, duration |
| Administrative and configuration changes | actor, setting, before/after |
| Payment and balance operations | principal, amount, idempotency key |
| Webhook receipt and signature failures | provider, event id, outcome |

Then check the **properties** that make those logs usable:

- **Correlation ids** propagated across services, so an incident is
  reconstructable.
- **Centralization** off-host (CloudWatch, Loki, ELK, a SIEM) — logs only on a
  compromised host are logs an attacker can edit.
- **Integrity**: append-only or immutable storage for audit events; a
  `DELETE`-capable application role over the audit table defeats the control
  (cross-reference `/ray-vault`).
- **Retention** defined, and consistent with the privacy retention policy
  (`/ray-custodian`).
- **Clock sanity**: UTC timestamps with a consistent format.

### Step 8: Detection and Alerting

Logs nobody reads are not a control — the 2025 Top 10 renames the category to
say so. Check for alerting rules (Prometheus rules, CloudWatch alarms, Grafana
alerts, Sentry alerts, SIEM correlation rules) on at least:

1. Spike in authentication failures, globally and per account.
2. Spike in 403s from one principal (authorization probing).
3. Spike in 4xx/5xx overall, and error-budget burn.
4. Login from a new geography, ASN, or device for privileged accounts.
5. Unusual data volume: large exports, unusual `SELECT` volume, egress spikes.
6. New or unusual outbound destinations.
7. Privilege changes and new admin accounts.
8. Rate-limit rejections trending up (an attack in progress, or a broken client).
9. Spend anomalies on `PAID` endpoints.
10. Webhook signature failures.

For each, record whether a rule exists, whether it routes to a human channel,
and whether a runbook is referenced. An alert with no owner and no runbook is
recorded as `PARTIAL`.

### Step 9: Evidence Discipline

- **Anchor absences at the composition root**: the router/middleware chain, the
  gateway config, the alerting rules file, the logger setup. List where you
  looked. An absence finding with no anchor is unreviewable.
- **Check every layer before declaring a limiter absent**: WAF, CDN, ingress,
  gateway, framework middleware, and per-route decorators. Cite the layer you
  found, or all the layers you checked.
- **Prioritize by cost class, not by count.** A missing limiter on the endpoint
  that calls a paid model is worth more than twenty missing limiters on static
  reads. Say why in the finding.
- **Do not generate load.** No flooding, no load tests, no probing of any host.
  Everything here is read from configuration.
- **Severity defaults**: unverified webhook signature on a state-changing
  receiver HIGH; unauthenticated admin or debug endpoint exposed externally
  HIGH; no authentication between services MEDIUM–HIGH; no limiter on a `PAID`
  or `SIDE_EFFECT` endpoint MEDIUM–HIGH; per-instance limiter behind a load
  balancer MEDIUM; no audit logging of privilege changes MEDIUM; no alerting
  LOW–MEDIUM; GraphQL without depth limits MEDIUM. `ray-gauge` applies the caps,
  and its `internal_nested` rule will lower purely internal exposure — do not
  pre-inflate to compensate.

### Step 10: Compile and Write Findings

Create `workspace/findings/` if missing; one JSON object per file at
`workspace/findings/<uuid>.json`.

Compute before writing:

1. **`cwe`** — `CWE-770` (allocation without limits), `CWE-307` (no restriction
   of authentication attempts), `CWE-799` (improper control of interaction
   frequency), `CWE-345`/`CWE-347` (unverified data authenticity / improper
   signature verification), `CWE-306` (missing authentication for a critical
   function), `CWE-284` (improper access control), `CWE-778` (insufficient
   logging), `CWE-223` (omission of security-relevant information), `CWE-117`
   (improper output neutralization for logs), `CWE-215` (information exposure
   through debug information), `CWE-1385` (missing origin validation),
   `CWE-1188` (insecure default). Omit when none applies.
2. **`signature`** — first 16 hex chars of
   `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)` with the
   same normalization rule the other stages use (title lowercased and stripped
   to `[a-zA-Z0-9]`; empty → first 16 hex of `sha256(raw title)`;
   `primary_target` = first `code_paths` entry minus `:line`; empty → hash over
   the sorted `code_paths` join). Compute once, never recompute.
3. **`lineage_id`** — inherit from an archived finding with the same
   `signature` under `workspace/archive/findings_pass_*/` or
   `workspace/archive/loop*_findings/` (highest pass wins), else fresh UUIDv4.
4. **`discovery_commit`** — snapshot id verbatim when pinned; omitted in
   DEGRADED mode.

#### Findings Schema Format (per file)

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Payment webhook receiver processes events without verifying the provider signature",
  "description": "Which endpoint, which control is absent, every layer checked while establishing the absence, and what an attacker can do at volume or unauthenticated. For consumption findings, state the cost class and what one request costs.",
  "impact": "Concrete outcome (e.g., anyone who knows the URL can mark any invoice paid; an authenticated user can drive unbounded inference spend; a breach would leave no reconstructable trail).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["src/webhooks/stripe.ts:14", "src/app.ts:60"],
  "discovery_commit": "snapshot id verbatim; omit entirely in DEGRADED mode.",
  "cwe": "CWE-345 (optional)",
  "signature": "First 16 hex chars of the sha256 defined above.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The control to add, at the right layer, plus the regression test (e.g. 'reject a webhook whose signature header is absent or altered; assert 400 and no state change').",
  "endpoint": "Optional. The inventory entry this finding belongs to, e.g. 'POST /webhooks/stripe'.",
  "history": [
    {
      "stage": "sentry",
      "action": "created",
      "details": "Service exposure / detection finding recorded.",
      "pass_number": 1,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

### Step 11: Write the Control Ledger

1. Resolve `N` from `pass_number`, else `max` archive pass + 1, else `1`.
2. Copy any existing `workspace/ledgers/ray-sentry.json` to
   `workspace/archive/ledgers/ray-sentry_pass_${N}.json` (`mkdir -p` first).
3. Write `workspace/ledgers/ray-sentry.json` with `skill`, `pass_number`,
   `snapshot_id`, `generated_at`, an `endpoints` array (each with `route`,
   `method`, `auth`, `cost_class`, `limiter`, `documented`), and a `controls`
   array of `{id, control, state, evidence, finding_ids, note}` where `state` is
   `PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN`.

Control ids — each appears exactly once:

| ID | Control |
|---|---|
| `INV-01` | Endpoint inventory complete (including queues, crons, WebSockets) |
| `INV-02` | No undocumented or deprecated live endpoints |
| `RATE-01` | Edge/WAF rate limiting present |
| `RATE-02` | Per-principal / per-key application limiting present |
| `RATE-03` | Tighter limits on auth and `SIDE_EFFECT` endpoints |
| `RATE-04` | Limiter state shared across instances |
| `RATE-05` | `429` returned with `Retry-After` |
| `RATE-06` | Spend/quota ceilings on `PAID` endpoints |
| `RATE-07` | Business-flow abuse controls where a human is assumed |
| `RATE-08` | Amplifying endpoints bounded |
| `EXPO-01` | Operational endpoints not externally reachable |
| `EXPO-02` | Operational endpoints authenticated regardless of network position |
| `EXPO-03` | Health/metrics payloads free of sensitive detail |
| `EXPO-04` | No stale versions, staging hosts, or dotfiles served |
| `S2S-01` | Service-to-service authentication (mTLS or service tokens) |
| `S2S-02` | Identity headers not trusted from untrusted hops |
| `S2S-03` | Proxy chain (`X-Forwarded-For`) enforced before use |
| `S2S-04` | Broker/queue authentication and message validation |
| `KEY-01` | API keys scoped to least privilege |
| `KEY-02` | Key expiration and rotation with an overlap window |
| `KEY-03` | Immediate revocation possible |
| `KEY-04` | Keys stored hashed, shown once, prefixed for scanner detection |
| `KEY-05` | Keys not passed in query strings |
| `HOOK-01` | Inbound webhook signatures verified over the raw body |
| `HOOK-02` | Constant-time signature comparison |
| `HOOK-03` | Timestamp/replay window enforced |
| `HOOK-04` | Idempotency by event id |
| `HOOK-05` | Outbound deliveries signed with per-tenant secrets |
| `HOOK-06` | Outbound retries bounded with backoff and a dead-letter path |
| `GQL-01` | Query depth and complexity limits |
| `GQL-02` | Introspection and suggestions disabled in production |
| `GQL-03` | Batch/alias limits, or operation-keyed rate limiting |
| `GQL-04` | Persisted queries or an operation allowlist for public APIs |
| `LOG-01` | Authentication events logged |
| `LOG-02` | Authorization denials logged |
| `LOG-03` | Privilege and membership changes logged |
| `LOG-04` | Sensitive-data access and bulk exports logged |
| `LOG-05` | Administrative and configuration changes logged |
| `LOG-06` | Correlation ids propagated |
| `LOG-07` | Logs centralized off-host |
| `LOG-08` | Audit events tamper-resistant |
| `LOG-09` | Log retention defined |
| `ALERT-01` | Authentication-failure spike alert |
| `ALERT-02` | Authorization-denial spike alert |
| `ALERT-03` | Error-rate and availability alerts |
| `ALERT-04` | Anomalous-volume / exfiltration alert |
| `ALERT-05` | Privilege-change alert |
| `ALERT-06` | Rate-limit rejection trend alert |
| `ALERT-07` | Spend-anomaly alert on `PAID` endpoints |
| `ALERT-08` | Alerts route to a human channel with a runbook |

### Step 12: Complete

Report: findings by severity, controls by state, endpoints by cost class with
their limiter status, and every `UNKNOWN` with its blocker. Do not print finding
bodies or the ledger into chat.

## Boundary With Adjacent Skills

- **Login-specific throttling, MFA, API key *issuance* semantics** →
  `/ray-turnstile`. The general limiter and key *lifecycle* are here; overlap on
  login rate limiting is intentional.
- **SSRF in outbound webhook URLs, timing-unsafe comparison** →
  `/ray-crucible`. The signature *verification* control is here.
- **What must never be logged, error-response hygiene, body limits and
  timeouts** → `/ray-seam`. Coverage of what must always be logged is here.
- **Network topology, WAF placement, environment isolation, incident runbook
  ownership** → `/ray-citadel`.
- **Database audit logging (pgAudit) and privilege separation** → `/ray-vault`.
- **Personal-data access logging as a legal obligation** → `/ray-custodian`
  (`INC-01`); the technical control is here.
