# Findings Contract — ray-siege

How the siege writes its findings. Read before the first finding of a round, and
again at Step 5. It reuses the standard Ray finding schema and the four computed
fields, adds the siege-specific fields, and reuses `ray-detonator`'s
`repro_status` / `reattack_status` / `patch_status` enums verbatim so a siege
finding is a first-class Ray finding — `ray-condenser` can merge it with a static
twin, and the report stages can consume it unchanged.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults](#2-severity-defaults)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. Siege-Specific Fields and Reused Enums](#4-siege-specific-fields-and-reused-enums)
- [5. CWE Set](#5-cwe-set)
- [6. Findings Schema](#6-findings-schema)

______________________________________________________________________

## 1. Evidence Discipline

**Live proof or it is not a finding.** Every siege finding carries a real
break-in against the running app, proven with a canary (`live_exploitation.md`
§2). A suspicion you could not break through is an insight, not a finding. This
is the whole point of the stage — it exists to move beyond "here is a weakness"
to "here is the app compromised."

**Anchor both the sink and the request.** `code_paths[0]` is the source sink
(the vulnerable handler/query), read from `--repo_root`. `break_in_evidence`
carries the exact live request/script and the canary result. A reviewer must be
able to re-fire the attack from what you wrote.

**Non-destructive proof only.** The evidence is a canary read, a benign marker,
a boolean/time differential, or an accepted tampered value — never damage. A
finding whose "proof" required destruction is a protocol violation; re-prove it
harmlessly or drop it.

**One break-in, one finding**, even across depth escalation — the chain goes in
`impact`, not into extra findings. If two distinct sinks were each broken, that
is two findings.

**Re-attack updates the same finding** (never a new one). The variant results and
the verdict transition are appended to the finding's history; the finding's
identity (`id`, `signature`, `lineage_id`) is fixed at creation.

______________________________________________________________________

## 2. Severity Defaults

Set an honest discovery-stage severity; if a full pipeline also runs, `ray-gauge`
applies the final caps. A *proven* live break-in generally rates higher than the
same class found statically, because reachability and exploitability are no longer
in question — but do not inflate past what the canary actually showed.

| Proven primitive | Default |
|---|---|
| Unauthenticated RCE, auth bypass to admin, or cross-tenant bulk data read | CRITICAL |
| SQLi with data extraction, IDOR exposing another principal's data, stored XSS with session theft potential, SSRF reaching a (mock) credential | HIGH |
| Reflected/DOM XSS, price/quantity tampering accepted, mass assignment of a privilege field, path traversal to a canary file | HIGH (MEDIUM if user-interaction or narrow) |
| Missing rate limit proven by a bounded burst, verbose error/exposure, missing security header observed live | MEDIUM–LOW |
| Open redirect, missing hardening with no proven impact | LOW |

`privileges_required`, `attacker_position`, and `user_interaction` describe what
the *proven* attack actually required — the identity the break-in used, from
where, with what interaction. Record what you did, not a hypothetical.

______________________________________________________________________

## 3. The Four Computed Fields

Identical to every other Ray stage, so lineage and dedupe work across the static
and live sides.

**`cwe`** (optional) — from §5. Decide first; it feeds the signature.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:
- `normalized_title` = `title` lowercased, non-`[a-zA-Z0-9]` stripped; empty →
  first 16 hex of `sha256(<raw title as UTF-8>)`.
- `cwe_part` = the `cwe` value or the empty string.
- `primary_target` = first `code_paths` entry minus a trailing `:line`; if empty
  or a non-source LOCATOR, hash over `sorted(code_paths).join(",")` instead.

Order `code_paths` with the **source sink first**, stable across rounds. Compute
once at creation; never recompute — re-attack must not change it.

**`lineage_id`** — inherit from an archived finding with the same `signature`
under `workspace/archive/findings_pass_*/` (or `..._round_*`), highest wins; else
a fresh UUIDv4. This is what lets a siege finding fold onto its static twin.

**`discovery_commit`** — the siege-branch baseline commit the break-in was proven
against (the round baseline), copied verbatim. Because the working tree is
deliberately mutated each round (sentinel-exempt, Block A step 1a), this records
*which build* was broken — set it once, at creation, to the round's baseline.

______________________________________________________________________

## 4. Siege-Specific Fields and Reused Enums

Added on top of the standard schema:

| Field | Meaning |
|---|---|
| `round` | The round number in which this break-in was first proven. |
| `target_url` | The loopback URL attacked. Always a `127.0.0.1`/`::1`/`localhost` address (the authorization gate guarantees it). |
| `break_in_evidence` | Object: `{ "channel": "...", "request": "path to the re-runnable script under workspace/reproducers/siege/", "canary": "<canary id proved>", "observed": "the response/marker that proves it" }`. |
| `patch_commit` | The siege-branch commit that patched it (set by ray-bulwark). |
| `reattack_variants` | Array of `{ "description": "...", "broke_in": true|false }`, ≥3 required for a `failed_to_bypass` verdict. |

Reused `ray-detonator` enums — do not invent new values:

- **`repro_status`** (the initial live break-in): `reproduced` (broke in with
  canary proof) / `failed_to_reproduce` (attacked but could not break through,
  with evidence the entrypoint was reached) / `not_attempted`. A siege finding is
  only written when `reproduced`.
- **`reattack_status`** (after patch): `bypassed_patch` / `failed_to_bypass` /
  `inconclusive_baseline_changed`.
- **`patch_status`**: `MITIGATION_PROPOSED` (patched, not yet re-verified) →
  `VERIFIED_SECURE` (requires `failed_to_bypass` with ≥3 failed variants) /
  `VERIFICATION_FAILED` (a variant bypassed it — hole still open) /
  `VERIFICATION_INCOMPLETE` (baseline changed or <3 valid variants).

**Invariant INV-1 (reused):** never persist `VERIFIED_SECURE` alongside a
`reattack_status` that is not `failed_to_bypass`. A bypass atomically moves the
finding to `VERIFICATION_FAILED` and it re-enters the loop.

______________________________________________________________________

## 5. CWE Set

Whatever the proven class is; the mapped domain docket names it. Common ones:
`CWE-89` (SQLi), `CWE-78` (command injection), `CWE-79` (XSS), `CWE-918` (SSRF),
`CWE-639`/`CWE-863` (IDOR/authz), `CWE-306` (missing auth), `CWE-347` (bad token
verification), `CWE-434` (upload), `CWE-22` (traversal), `CWE-915` (mass
assignment), `CWE-602` (client-trust), `CWE-1336` (SSTI), `CWE-502`
(deserialization), `CWE-77` (injection general), `CWE-770` (missing rate limit,
proven by bounded burst). Omit if none applies.

______________________________________________________________________

## 6. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "IDOR on GET /api/invoices/:id — any user reads any invoice",
  "description": "The sink (handler + query that trusts the id), the exact live request that broke in, the identity used, and the canary data returned. State what the server should have checked.",
  "impact": "What the proven break-in yields (and, under --depth escalate, the chain reached in the local sandbox).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "VALID",
  "code_paths": ["src/routes/invoices.ts:42", "src/db/invoices.ts:17"],
  "discovery_commit": "abc1234 (round baseline commit)",
  "cwe": "CWE-639",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The minimal fix (scope the query to the session principal) plus the regression test that proves it: a request from tenant A for tenant B's id must return 404.",
  "round": 1,
  "target_url": "http://127.0.0.1:8137",
  "break_in_evidence": {
    "channel": "authorization-bypass-200-with-cross-principal-data",
    "request": "workspace/reproducers/siege/idor_invoices_<uuid>.py",
    "canary": "invoices:ray-canary-31aa",
    "observed": "GET /api/invoices/31aa as canary user -> 200 with the canary invoice body"
  },
  "repro_status": "reproduced",
  "reattack_status": "failed_to_bypass",
  "reattack_variants": [
    {"description": "id as array ?id[]=31aa", "broke_in": false},
    {"description": "PATCH instead of GET", "broke_in": false},
    {"description": "tenant-B principal, same id", "broke_in": false}
  ],
  "patch_status": "VERIFIED_SECURE",
  "patch_commit": "def5678",
  "history": [
    {"stage": "siege-reaver", "action": "broke_in", "details": "IDOR proven with canary invoice 31aa", "round": 1, "timestamp": "<iso8601>"},
    {"stage": "siege-bulwark", "action": "patched", "details": "scoped query to session tenant; commit def5678", "round": 1, "timestamp": "<iso8601>"},
    {"stage": "siege-reaver", "action": "reattack_failed_to_bypass", "details": "3 variants, none broke in", "round": 1, "timestamp": "<iso8601>"}
  ]
}
```

Use `"status": "VALID"` — a live-proven break-in is not provisional. The
`history` stages are namespaced `siege-reaver` / `siege-bulwark` so a mixed
static+live pass keeps the provenance of who did what.
