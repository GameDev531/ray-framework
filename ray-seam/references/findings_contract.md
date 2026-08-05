# Findings Contract — ray-seam

How this stage writes its output. Read it before writing the first finding of a
pass, and again when assembling the ledger.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults](#2-severity-defaults)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. CWE Set For This Domain](#4-cwe-set-for-this-domain)
- [5. Findings Schema](#5-findings-schema)
- [6. Control Ledger](#6-control-ledger)

______________________________________________________________________

## 1. Evidence Discipline

**Anchor at the server-side line that trusts the client**, not at the client
line that sends the value. The client is not the defect; the trust is. When both
are useful, `code_paths[0]` is the server anchor and the client site follows.

**Trace the whole chain before declaring validation absent.** A global
validation middleware, a framework default (Rails strong parameters, ASP.NET
model binding attributes, DRF serializers), a gateway schema, or a base
serializer may already cover the handler. State what you checked — that sentence
is what separates a finding from a guess, and `/ray-arbiter` will look for
exactly the thing you skipped.

**Do not report defense-in-depth as if it were exploitable.** A missing
`rel="noopener"` where the browser default already applies, or a timing nuance
with no attacker path, belongs at LOW with the limitation stated plainly.
Inflating it costs the pipeline a validation round and costs you credibility on
the findings that matter.

**Say what happens under failure, not just under success.** For fail-open
findings, the finding is only actionable if it names the trigger — usually
"enough load to cause a timeout" or "the dependency being briefly unavailable".

**Read before you claim.** Where a built bundle is not in the snapshot, audit
the build configuration and source and say that is what you did. Never describe
the contents of a bundle you did not open.

**Status.** Default `PROVISIONALLY_VALID`. Use `NEEDS_RESEARCH` when the control
plausibly lives outside the snapshot (headers set at a CDN, validation performed
by an API gateway) and name what would resolve it.

______________________________________________________________________

## 2. Severity Defaults

Discovery-stage defaults; `ray-gauge` applies the final caps.

| Situation | Default |
|---|---|
| Service-role or private API key in a client bundle | HIGH |
| Authenticated response cached publicly or by a shared cache | HIGH |
| Client-supplied price, total, or discount accepted without recomputation | HIGH |
| Fail-open authorization, signature verification, or rate limiting | HIGH |
| Mass assignment reaching a privilege, tenant, or balance field | HIGH |
| CORS reflecting `Origin` with credentials | MEDIUM–HIGH |
| Session or refresh token in `localStorage` | MEDIUM (HIGH where `/ray-crucible` confirms an XSS nearby) |
| Over-serialization exposing hashes, tokens, or other users' records | MEDIUM–HIGH |
| No outbound call timeouts on a request-path dependency | MEDIUM |
| `postMessage` receiver without an origin check | MEDIUM |
| Credentials or personal data written to logs | MEDIUM |
| Stack traces or debug pages in production | LOW–MEDIUM |
| Missing body-size limits, unbounded pagination | LOW–MEDIUM |
| Error text acting as an existence oracle | LOW |

Never mark CRITICAL without a described unauthenticated path to system or
bulk-data compromise.

______________________________________________________________________

## 3. The Four Computed Fields

**`cwe`** (optional) — from §4. Omit when nothing applies. Decide it first; it
feeds the signature.

**`signature`** — first 16 hex characters of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:

- `normalized_title` = `title` lowercased with every non-`[a-zA-Z0-9]`
  character stripped; empty result → first 16 hex of
  `sha256(<raw title as UTF-8>)`.
- `cwe_part` = the `cwe` value or the empty string.
- `primary_target` = the first `code_paths` entry minus any trailing `:line`;
  if empty or a non-source LOCATOR, hash
  `normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(",")`.

Order `code_paths` with the **server anchor first** and keep that order stable
across passes, or the signature drifts and the finding is re-reported as new.
Compute once at creation; never recompute.

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
| `CWE-602` | Client-side enforcement of server-side security (the archetype here) |
| `CWE-20` | Improper input validation |
| `CWE-915` | Improperly controlled modification of object attributes (mass assignment) |
| `CWE-213` | Exposure due to incompatible policies (over-serialization) |
| `CWE-209` | Information exposure through an error message |
| `CWE-636` | Not failing securely ("failing open") |
| `CWE-755` | Improper handling of exceptional conditions |
| `CWE-522` | Insufficiently protected credentials (tokens in web storage) |
| `CWE-798` | Hard-coded credentials (secrets in a bundle) |
| `CWE-942` | Permissive cross-domain policy with untrusted domains |
| `CWE-1385` | Missing origin validation in `postMessage` |
| `CWE-532` | Insertion of sensitive information into a log file |
| `CWE-117` | Improper output neutralization for logs |
| `CWE-770` | Allocation of resources without limits or throttling |
| `CWE-1333` | Inefficient regular expression complexity |
| `CWE-524`/`CWE-525` | Sensitive information in a cache |
| `CWE-444` | Inconsistent interpretation of HTTP requests (cache poisoning family) |
| `CWE-345` | Insufficient verification of data authenticity |

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

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
  "code_paths": ["server anchor first: src/api/orders.ts:57", "then the client site: web/src/checkout.tsx:120"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-602",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The corrective change plus the regression test that keeps it, e.g. 'POST /orders with a tampered total must return the server-computed total; assert the stored order price equals the catalogue price'.",
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

______________________________________________________________________

## 6. Control Ledger

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`; if missing or
   invalid, use `max` of the `findings_pass_N` / `loopN_findings` folders in
   `workspace/archive/` + 1, defaulting to `1`.
2. If `workspace/ledgers/ray-seam.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-seam_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-seam.json`.

```json
{
  "skill": "ray-seam",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "generated_at": "<iso8601>",
  "client_supplied_values": [
    {
      "value": "order.total",
      "consumed_at": "src/api/orders.ts:57",
      "revalidated": false,
      "note": "Stored directly; no catalogue lookup."
    }
  ],
  "controls": [
    {
      "id": "TRUST-01",
      "control": "Prices, totals, and discounts recomputed server-side",
      "state": "PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN",
      "evidence": "src/api/orders.ts:57",
      "finding_ids": [],
      "note": ""
    }
  ]
}
```

Every control id from `seam_docket.md` §10 appears exactly once, including the
ones that passed and the ones you could not determine. `UNKNOWN` entries carry a
`note` saying what blocked determination. `client_supplied_values` records every
value from the Step-1 map, including the ones that **are** revalidated — that is
what stops the next pass from re-deriving the same map from scratch.
