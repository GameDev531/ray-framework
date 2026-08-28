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
nothing is there to read — which is why this stage works from an inventory
outward rather than from the code inward.

## Command Definition

- **Command:** `/ray-sentry`
- **Description:** Audits rate limiting and abuse controls, internal-endpoint
  exposure, service and key authentication, webhook verification, and security
  logging and alerting, writing findings plus a control ledger.
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
  `workspace/kb/THREAT_MODEL.md` and `workspace/kb/entities/*.md` (optional —
  the availability tiers there set the severity floor for consumption
  findings); this skill's `references/*.md`; target source (route definitions,
  gateway and proxy configuration, IaC, middleware, queue and worker code,
  logging and metrics configuration, alerting rules, GraphQL schema and server
  options, webhook receivers); `workspace/ledgers/ray-sentry.json` from the
  previous pass, if present.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-sentry.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-sentry_pass_${N}.json` before overwriting.
- **Preconditions**: target files readable. This stage performs **no** load
  testing, no request flooding, and no probing of any host — every verdict comes
  from configuration and code.
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges). The ledger is archived per pass and then
  deterministically overwritten.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/service_docket.md` | before Step 2, then per area through Step 5 | The endpoint cost-class taxonomy, the layered rate-limiting model, internal-endpoint exposure, service-to-service and machine authentication, API key lifecycle, inbound and outbound webhooks, GraphQL and batch interfaces, the security-logging event table, and the alerting rule set — each with expected and failing shapes |
| `references/findings_contract.md` | before writing the first finding, and again at Step 6 | Findings schema, the four computed fields, this domain's CWE set, evidence discipline, severity defaults, and the ledger format with its control ids |

Read the docket area by area as you sweep. The cost-class taxonomy in §1 is
worth internalizing early: it is what stops this stage from reporting twenty
equally-weighted "missing rate limit" findings when only two of them matter.

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

CODE-READING stage, so the findings-only skip does not apply. Whether an
endpoint is reachable from the internet is a deployment property: judge it from
IaC, ingress definitions, service manifests, and bind addresses in the snapshot.
When the snapshot cannot settle it, write `NEEDS_RESEARCH` naming the artifact
that would — never probe a live host. This skill's `references/*.md` sit beside
`SKILL.md`, not under CODE_ROOT.

### Step 1: Build the Endpoint Inventory

Everything here is scored per endpoint, so the inventory comes first. It is also
the answer to API9:2023 (Improper Inventory Management), which no code pattern
reveals on its own.

For each entry record path and method, protocol (REST/GraphQL/gRPC/WebSocket/
queue consumer/cron), authentication requirement, expected caller, and its
**cost class** from `service_docket.md` §1 — `CHEAP`, `DB_HEAVY`, `PAID`,
`SIDE_EFFECT`, or `PRIVILEGED`. The cost class is what decides priority for
every later step.

Enumerate as well: routes with no authentication, routes present in code but
absent from any API documentation in the repository, deprecated versions still
live beside their replacements, and anything bound to `0.0.0.0` that the
architecture treats as internal.

### Step 2: Abuse Resistance

Score each endpoint against the layered model in `service_docket.md` §2. The
three properties that decide most findings:

- **Layer coverage.** Edge limiting protects against floods; per-principal
  application limiting is what actually protects `PAID` and `SIDE_EFFECT`
  endpoints, because an attacker with one account and many IPs sails through the
  edge. A single global limiter is not evidence that a specific endpoint is
  covered.
- **Counter storage.** An in-process counter is per-instance: behind N replicas
  the effective limit is N×, and a restart resets it. This is one of the most
  common real defects in this domain — check it whenever the app runs more than
  one replica.
- **Spend versus rate.** A request-rate limiter bounds requests per second, not
  spend per month. A `PAID` endpoint with no quota or cost ceiling is a finding
  regardless of its limiter.

§2 also covers business-flow abuse (API6:2023) — flows that assume a human, like
trial signup, referral bonuses, and coupon redemption, where a plain rate limit
is rarely the right control — and amplification, where one request causes many
outbound requests or messages.

### Step 3: Exposure and Machine Authentication

`service_docket.md` §3 covers operational endpoints (`/metrics`, `/actuator`,
`/debug`, queue dashboards, admin panels, database UIs): where they bind,
whether an ingress reaches them, and whether they authenticate regardless of
network position. Judge health and metrics payloads individually — a liveness
probe returning `ok` is fine; one reporting dependency hostnames and versions is
a leak.

§4 covers machine identity: mTLS or service tokens between services rather than
network position as identity; handlers that trust `X-User-Id`, `X-Tenant-Id`, or
`X-Forwarded-For` without the proxy chain being enforced; the API key lifecycle
(scope, expiry, rotation with an overlap window, revocation, hashed storage,
identifiable prefixes); and queue consumers that trust any message on the
broker.

### Step 4: Webhooks and Batch Interfaces

`service_docket.md` §5 covers webhooks in both directions. Inbound signature
verification is one of the highest-value findings this stage produces — a
receiver that parses and trusts the payload lets anyone mark an invoice paid.
Check that verification runs over the **raw body** (a framework that consumes it
first breaks verification by definition), uses a constant-time comparison,
enforces a timestamp window, and is idempotent by event id.

§6 covers GraphQL and batch interfaces: depth and complexity limits,
introspection and field suggestions in production, and — the one teams miss —
**aliasing and batching**, where a single request containing hundreds of aliased
mutations bypasses per-request rate limiting entirely.

### Step 5: Detection

`service_docket.md` §7 lists the security events that must be logged and what
each must capture, plus the properties that make logs usable: correlation ids,
centralization off-host, tamper resistance, and defined retention. §8 lists the
alerting rules that turn those logs into detection.

The 2025 Top 10 renamed this category to *Security Logging and Alerting
Failures* precisely because logs nobody reads are not a control. An alert with
no owner and no runbook is recorded `PARTIAL`, not `PRESENT`.

### Step 6: Write Findings and the Ledger

Follow `references/findings_contract.md`. Two rules carry this domain: **anchor
absences at the composition root** — the router chain, the gateway config, the
alerting rules file — and list every layer you checked; and **prioritize by cost
class, not by count**, saying in the finding why this endpoint's absence matters
more than another's.

### Step 7: Complete

Report findings by severity, controls by state, endpoints by cost class with
their limiter status, and every `UNKNOWN` with its blocker. Do not print finding
bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Login throttling, MFA, API key issuance semantics | `/ray-turnstile` |
| SSRF in outbound webhook URLs, timing-unsafe comparison | `/ray-crucible` |
| What must never be logged, error hygiene, body limits and timeouts | `/ray-seam` |
| Network topology, WAF placement, environment isolation, runbook ownership | `/ray-citadel` |
| Database audit logging (pgAudit) and privilege separation | `/ray-vault` |
| Personal-data access logging as a legal obligation | `/ray-custodian` |

Login rate limiting overlaps `/ray-turnstile` by design: it is an authentication
control there and a service-protection control here. Log *coverage* is here; log
*hygiene* is `/ray-seam`'s. `ray-condenser` merges.
