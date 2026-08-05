# Findings Contract — ray-custodian

How this stage writes its output. Read it before writing the first finding of a
pass, and again when assembling the ledger.

Everything here is deliberately mechanical, because two downstream stages depend
on it: `ray-condenser` clusters on `signature`, and `ray-arbiter` re-reads the
`code_paths` anchors to try to disprove the finding. A finding that is vague
about where it lives cannot be validated and will be dismissed.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults](#2-severity-defaults)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. CWE Set For This Domain](#4-cwe-set-for-this-domain)
- [5. Findings Schema](#5-findings-schema)
- [6. Control Ledger](#6-control-ledger)

______________________________________________________________________

## 1. Evidence Discipline

These rules are what keep this stage from producing a wall of "add helmet"
noise that the validation stages then have to grind through.

**Anchor every finding at a line you actually read.** `code_paths` must point at
a real `file:line` under CODE_ROOT. Never invent a line number, and never cite a
file you did not open.

**Absence-of-control findings need a composition-root anchor.** If a control is
missing everywhere, anchor at the file where it *would* be installed — the
middleware chain, the server config, the model definition — and say plainly in
the description that you searched for it and where. A finding whose anchor is
"nowhere" is unreviewable.

**Search the whole chain before declaring absence.** Headers set at the CDN,
cookies hardened by a framework default, retention enforced by a bucket
lifecycle rule: each defeats a naive "not in the code" conclusion. Walk the five
layers in `web_surface_baseline.md` §0 first. If the control could plausibly
live in infrastructure outside this repository, write the finding with
`"status": "NEEDS_RESEARCH"` and state what would confirm or refute it. Fail
conservative; never issue a clean verdict you cannot support.

**One control, one finding.** Do not bundle "no HSTS, no CSP, no nosniff" into
one finding — the pipeline scores, reproduces, and tracks regressions per
finding. Equally, do not fragment: one absent control affecting twelve routes is
one finding with twelve `code_paths`.

**Regime attribution.** When the obligation is legal rather than technical, name
the article (`LGPD art. 18 IV`, `GDPR art. 33`) and keep the claim narrow —
describe the obligation and the gap, never predict an enforcement outcome or a
fine.

**Status.** Default to `PROVISIONALLY_VALID`. Use `NEEDS_RESEARCH` only when the
control's state genuinely cannot be determined from the snapshot, and say what
evidence would resolve it.

______________________________________________________________________

## 2. Severity Defaults

This is a discovery stage; `ray-gauge` applies the final caps. Score honestly
rather than pre-inflating to compensate for a cap you expect.

| Situation | Default |
|---|---|
| Session cookie without `HttpOnly` or without `Secure` | HIGH |
| No HTTPS enforcement / session material over plaintext | HIGH |
| Authenticated response cached publicly | HIGH |
| Rights or export endpoint reachable without an ownership check | HIGH |
| Sensitive, children's, government-ID, or financial data demonstrably reachable by an unauthorized party | HIGH |
| CSP absent or `unsafe-inline` on a page rendering user-controlled content | MEDIUM (HIGH if `/ray-crucible` confirms an XSS sink nearby) |
| `SameSite` absent on a session cookie in a cookie-authenticated app | MEDIUM |
| Non-essential tracker firing before consent | MEDIUM |
| No retention mechanism for stored personal data | MEDIUM |
| Missing `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP | LOW–MEDIUM |
| Server version disclosure | LOW |

Never mark a missing hardening header CRITICAL. Reserve CRITICAL for a
concrete, described path to bulk personal-data access — and even then, prefer
HIGH unless the path is unauthenticated.

______________________________________________________________________

## 3. The Four Computed Fields

Compute these before writing each file.

**`cwe`** (optional) — from §4 below. Omit the key when nothing applies. It is an
input to the signature, so decide it first.

**`signature`** — first 16 hex characters of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)` where:

- `normalized_title` = the `title`, lowercased, with every non-`[a-zA-Z0-9]`
  character stripped. If that leaves it empty (a title made entirely of
  non-ASCII characters), use the first 16 hex chars of
  `sha256(<raw title as UTF-8 bytes>)` instead, so two distinct titles do not
  both collapse to the empty string.
- `cwe_part` = the `cwe` value, or the empty string.
- `primary_target` = the first `code_paths` entry with any trailing `:line`
  stripped. If `code_paths` is empty, or the first entry is a non-source
  LOCATOR (a URL, a symbol), use the empty string — and in that case hash
  `normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(",")`
  instead.

Order `code_paths` deterministically, primary anchor first, and keep that order
stable across passes — otherwise the signature drifts and the finding is
re-reported as new. Compute the signature **once** at creation and never
recompute, edit, or invent it.

**`lineage_id`** — scan `workspace/archive/findings_pass_*/` and
`workspace/archive/loop*_findings/` (STATE-RELATIVE paths) for an archived
finding whose `signature` equals this one's; inherit its `lineage_id`, taking
the highest pass number if several match. Otherwise a fresh UUIDv4. The
basename-rename fallback for genuinely renamed files is specified in
`ray-prospector/SKILL.md` Step 5a and applies here unchanged.

**`discovery_commit`** — `active_snapshot.snapshot_id`, copied verbatim,
required and non-empty whenever the snapshot is pinned. **Omit the key
entirely** — not `""`, not `null` — in DEGRADED/legacy mode, because downstream
stages read an absent value as NOT_MATCHED, which is the conservative branch.

`signature` and `lineage_id` are always computed, in every mode; only
`discovery_commit` is mode-dependent.

______________________________________________________________________

## 4. CWE Set For This Domain

| CWE | Use for |
|---|---|
| `CWE-319` | Cleartext transmission (no HTTPS enforcement, mixed content) |
| `CWE-311` | Missing encryption of sensitive data |
| `CWE-1004` | Sensitive cookie without `HttpOnly` |
| `CWE-614` | Sensitive cookie without `Secure` |
| `CWE-1275` | `SameSite` misconfiguration |
| `CWE-1021` | Improper restriction of a framed UI (clickjacking) |
| `CWE-693` | Protection mechanism failure (missing CSP, missing hardening header) |
| `CWE-359` | Exposure of private personal information |
| `CWE-200` | Exposure of sensitive information to an unauthorized actor |
| `CWE-532` | Insertion of sensitive information into a log file |
| `CWE-598` | Use of `GET` with sensitive data in a query string |
| `CWE-524`/`CWE-525` | Sensitive information in a cache |
| `CWE-639` | Authorization bypass through a user-controlled key (rights endpoints) |
| `CWE-212` | Improper removal of sensitive information (incomplete erasure, weak anonymization) |
| `CWE-1230` | Exposure through metadata |

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, with no text
before or after the JSON.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Session cookie set without HttpOnly in [module]",
  "description": "Root-cause analysis: which personal data or session material is exposed, which control is absent or weak, exactly where you searched for it, and which layer would normally enforce it. Name the regime article when the obligation is legal.",
  "impact": "Concrete outcome (e.g., session theft via any XSS; bulk export of subject records by an unauthenticated caller; indefinite retention enlarging breach blast radius).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["src/server/session.ts:41"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit the key entirely in DEGRADED mode.",
  "cwe": "CWE-1004",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4, or inherited from an archived ancestor.",
  "mitigation": "The corrective change concretely — the directive, flag, or code shape — plus the regression test that keeps it applied (e.g. 'assert Set-Cookie on /login contains HttpOnly; Secure; SameSite=Lax').",
  "privacy_control_id": "Optional. The ledger control id that raised this, e.g. 'COOKIE-01'.",
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

The `mitigation` field carries more weight here than in most stages. A privacy
control that is fixed once and not tested decays quietly; naming the assertion
that would catch the regression is what turns a finding into a durable control.

______________________________________________________________________

## 6. Control Ledger

The ledger records every control that was checked, not just the ones that
failed. Without it, "no findings" and "did not look" are indistinguishable.

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`. If missing or
   invalid, scan `workspace/archive/` for `findings_pass_N` / `loopN_findings`
   folders and use `max_found + 1`, defaulting to `1`.
2. If `workspace/ledgers/ray-custodian.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-custodian_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-custodian.json`.

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
      "note": "Redirect covers the apex only; the www vhost serves plaintext."
    }
  ]
}
```

Every control id appears exactly once: the privacy ids from
`privacy_docket.md` §10 and the exposure ids from
`web_surface_baseline.md` §6. `UNKNOWN` entries must carry a `note` saying what
blocked determination — that note is the difference between a documented
decision and a gap.
