# Findings Contract — ray-sentry

How this stage writes its output. Read it before writing the first finding of a
pass, and again when assembling the ledger.

Most findings here are **absences**, which makes the anchoring rules unusually
important: there is no bad line of code to point at, so the finding has to
establish where the control should have been and prove you looked.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults](#2-severity-defaults)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. CWE Set For This Domain](#4-cwe-set-for-this-domain)
- [5. Findings Schema](#5-findings-schema)
- [6. Control Ledger](#6-control-ledger)

______________________________________________________________________

## 1. Evidence Discipline

**Anchor absences at the composition root** — the router or middleware chain,
the gateway configuration, the alerting rules file, the logger setup — and list
in the description every place you looked. A finding whose anchor is "nowhere"
cannot be reviewed and will be dismissed by `/ray-magistrate`.

**Check every layer before declaring a limiter absent.** WAF, CDN, ingress,
gateway, framework middleware, per-route decorator. Cite the layer where you
found it, or name all the layers you checked and found empty.

**Prioritize by cost class, not by count.** A missing limiter on the endpoint
that calls a paid model is worth more than twenty missing limiters on static
reads, and the finding should say so — name the cost class and what one request
costs. A stage that reports every endpoint equally trains its reader to skim.

**Generate no load.** No flooding, no load tests, no probing of any host, no
sending of a test webhook. Everything here is read from configuration and code.

**Deployment claims need deployment evidence.** Whether an endpoint is reachable
from the internet comes from IaC, ingress rules, service manifests, and bind
addresses. When the snapshot cannot settle it, write `NEEDS_RESEARCH` and name
the artifact that would.

**Respect the calibration you know is coming.** `ray-gauge`'s `internal_nested`
rule lowers purely internal exposure. Score honestly rather than pre-inflating
to compensate — inflation does not survive, it just costs a round trip.

**Status.** Default `PROVISIONALLY_VALID`; `NEEDS_RESEARCH` where the control
may live outside the snapshot.

______________________________________________________________________

## 2. Severity Defaults

| Situation | Default |
|---|---|
| Unverified webhook signature on a state-changing receiver | HIGH |
| Unauthenticated admin or debug endpoint reachable externally | HIGH |
| API key or credential accepted in a query string on a privileged route | MEDIUM–HIGH |
| No authentication between services | MEDIUM–HIGH |
| Identity headers (`X-User-Id`) trusted from an untrusted hop | HIGH |
| No limiter or quota on a `PAID` or `SIDE_EFFECT` endpoint | MEDIUM–HIGH |
| Per-instance limiter behind a load balancer | MEDIUM |
| GraphQL without depth or complexity limits | MEDIUM |
| Batching/aliasing bypassing per-request limits on an auth endpoint | MEDIUM–HIGH |
| No audit logging of privilege changes or bulk exports | MEDIUM |
| Audit records deletable by the application role | MEDIUM |
| No alerting on authentication or authorization anomalies | LOW–MEDIUM |
| Health/metrics payload leaking versions and hostnames | LOW |
| Undocumented but authenticated endpoint | LOW |

Reserve CRITICAL for an unauthenticated path to bulk data or full compromise,
described concretely.

______________________________________________________________________

## 3. The Four Computed Fields

**`cwe`** (optional) — from §4. Decide it first; it feeds the signature.

**`signature`** — first 16 hex characters of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:

- `normalized_title` = `title` lowercased with every non-`[a-zA-Z0-9]`
  character stripped; empty result → first 16 hex of
  `sha256(<raw title as UTF-8>)`.
- `cwe_part` = the `cwe` value or the empty string.
- `primary_target` = the first `code_paths` entry minus any trailing `:line`;
  if empty or a non-source LOCATOR, hash
  `normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(",")`.

Order `code_paths` with the **endpoint or receiver anchor first**, then the
composition root, and keep that order stable across passes. Compute once at
creation; never recompute.

Note the LOCATOR rule from Block A step 3: an endpoint reference containing
`://`, or a bare route like `POST /webhooks/stripe`, is a non-source locator —
do not attach a fabricated `:line` to it. Where you have a real handler file,
use that as the anchor and put the route in the `endpoint` field instead.

**`lineage_id`** — inherit from an archived finding with the same `signature`
under `workspace/archive/findings_pass_*/` or
`workspace/archive/loop*_findings/` (highest pass wins); otherwise a fresh
UUIDv4. `ray-prospector/SKILL.md` Step 5a's basename-rename fallback applies.
STATE-RELATIVE paths.

**`discovery_commit`** — `active_snapshot.snapshot_id` verbatim when pinned;
**omit the key entirely** in DEGRADED mode.

______________________________________________________________________

## 4. CWE Set For This Domain

| CWE | Use for |
|---|---|
| `CWE-770` | Allocation of resources without limits or throttling |
| `CWE-799` | Improper control of interaction frequency |
| `CWE-307` | Improper restriction of excessive authentication attempts |
| `CWE-345` | Insufficient verification of data authenticity (unverified webhook) |
| `CWE-347` | Improper verification of a cryptographic signature |
| `CWE-306` | Missing authentication for a critical function |
| `CWE-284` | Improper access control (exposed internal endpoints) |
| `CWE-778` | Insufficient logging |
| `CWE-223` | Omission of security-relevant information |
| `CWE-117` | Improper output neutralization for logs |
| `CWE-532` | Sensitive information in a log file (keys in query strings reaching logs) |
| `CWE-215` | Information exposure through debug information |
| `CWE-1188` | Insecure default initialization |
| `CWE-290` | Authentication bypass by spoofing (trusted identity headers) |
| `CWE-441` | Unintended proxy or intermediary |
| `CWE-294` | Authentication bypass by capture-replay (no replay window) |

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Payment webhook receiver processes events without verifying the provider signature",
  "description": "Which endpoint, which control is absent, every layer you checked while establishing the absence, and what an attacker can do at volume or unauthenticated. For consumption findings, state the cost class and what one request costs.",
  "impact": "Concrete outcome (e.g., anyone who knows the URL can mark any invoice paid; an authenticated user can drive unbounded inference spend; a breach would leave no reconstructable trail).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["src/webhooks/stripe.ts:14", "src/app.ts:60"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-345",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The control to add, at the right layer, plus the regression test (e.g. 'reject a webhook whose signature header is absent or altered; assert 400 and no state change').",
  "endpoint": "Optional. The inventory entry this belongs to, e.g. 'POST /webhooks/stripe'.",
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

"At the right layer" in `mitigation` is doing real work: a limiter added in
application memory when the deployment runs six replicas is a fix that does not
fix anything. Say where it belongs and why.

______________________________________________________________________

## 6. Control Ledger

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`; if missing or
   invalid, use `max` of the `findings_pass_N` / `loopN_findings` folders in
   `workspace/archive/` + 1, defaulting to `1`.
2. If `workspace/ledgers/ray-sentry.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-sentry_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-sentry.json`.

```json
{
  "skill": "ray-sentry",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "generated_at": "<iso8601>",
  "endpoints": [
    {
      "route": "POST /api/summarize",
      "method": "POST",
      "auth": "session",
      "cost_class": "PAID",
      "limiter": "edge only",
      "documented": false
    }
  ],
  "controls": [
    {
      "id": "RATE-06",
      "control": "Spend/quota ceilings on PAID endpoints",
      "state": "PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN",
      "evidence": "src/app.ts:60",
      "finding_ids": [],
      "note": "No per-tenant monthly cap; edge limiter bounds rate only."
    }
  ]
}
```

Every control id from `service_docket.md` §9 appears exactly once. The
`endpoints` array is the artifact that answers API9:2023 and makes the next
pass cheap — keep it complete, including the endpoints that are fine.
