# Findings Contract — ray-warden

How `ray-warden` records what it investigated and did. A blue-team analyst's
output is a **case record** — the incident, the verdict, the confidence, and the
auditable chain of actions — not a source-code vulnerability. So `ray-warden`
writes a case object that stays compatible with the standard Ray finding schema
(same identity/lineage fields, so a pipeline can consume it) while carrying the
response-specific fields an incident needs. Read before the first case, and again
at the scoring step.

## Table of Contents

- [1. Case vs. Finding](#1-case-vs-finding)
- [2. Evidence & Verdict Discipline](#2-evidence--verdict-discipline)
- [3. Severity ↔ Confidence — they are not the same axis](#3-severity--confidence--they-are-not-the-same-axis)
- [4. The Four Computed Fields](#4-the-four-computed-fields)
- [5. Case-Specific Fields and Enums](#5-case-specific-fields-and-enums)
- [6. The Case Schema](#6-the-case-schema)

______________________________________________________________________

## 1. Case vs. Finding

A **case** is opened per incident (a correlated set of alerts about the same
entities in the same window — `analyst_playbooks.md` §1). Multiple raw alerts fold
into one case; the analyst never opens a second case for the same incident. A case
carries a `verdict` and a `confidence`, and it accretes `actions` over its life.

It is written to `workspace/warden/cases/<uuid>.json`. Every action the case
drove is *also* appended to the immutable `workspace/warden/audit.jsonl`
(`autonomy_tiers.md` §3) — the case is the analyst's picture; the audit log is
the tamper-evident ledger. The two must agree.

______________________________________________________________________

## 2. Evidence & Verdict Discipline

**Corroboration or it is not a verdict.** A `malicious` or `benign` verdict is
reached only from converging first-party signals (`analyst_playbooks.md` §7),
never from a single stale indicator and never because an investigated artifact
asserts its own nature. Absent corroboration the verdict is `uncertain` — an
honest `uncertain` is worth more than a confident guess.

**Point at the evidence.** Every load-bearing signal references a stored artifact
under `workspace/warden/evidence/<case>/` (the log excerpt, the enrichment
result, the redacted header) so a human can re-derive the verdict. Raw secrets and
full tokens are referenced by id, never stored in the clear.

**Actions match tiers, always.** Every entry in `actions` carries its tier and,
if it was taken, its rollback and (for T2/T3) the approving human. An `executed`
T3 with no `approved_by`, or an `autonomous: true` T3, is a contract violation —
it must never be written.

______________________________________________________________________

## 3. Severity ↔ Confidence — they are not the same axis

Keep them separate; conflating them is the classic SOC error.

- **`severity`** = how bad it is *if the verdict is true* (impact + urgency).
- **`confidence`** = how sure the analyst is the verdict is true (`§7` rubric).

A CRITICAL-severity incident at 0.55 confidence is **not** actioned autonomously —
it is escalated fast to a human because the stakes are high, but the analyst does
not *contain* on a coin-flip. A LOW-severity incident at 0.95 confidence may be
handled autonomously (if allowlisted T2) precisely because it is both minor and
certain. The autonomy gate (`autonomy_tiers.md` §1 + `analyst_playbooks.md` §7)
reads **confidence**; the escalation urgency reads **severity**.

| Severity | Meaning |
|---|---|
| CRITICAL | Active compromise of a crown-jewel asset / mass impact / ongoing exfiltration. |
| HIGH | Confirmed compromise of a single significant account/host, contained blast radius. |
| MEDIUM | Suspicious activity with real but limited potential impact. |
| LOW | Minor/expected anomaly, hardening opportunity, or likely benign needing a note. |

______________________________________________________________________

## 4. The Four Computed Fields

Kept identical to every other Ray stage so a case can be deduped/linked like any
finding.

**`cwe`** (optional) — the weakness the incident exploited, if known (e.g.
`CWE-287` weak auth for a credential-compromise case). Feeds the signature.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`, where
`primary_target` is the primary entity locator (`user:jamie@corp`,
`host:10.0.0.4`). Lets recurring incidents on the same entity link across time.

**`lineage_id`** — inherit from an archived case with the same `signature` (a
repeat compromise of the same account is the same lineage); else a fresh UUIDv4.

**`discovery_commit`** — not a code commit here; use the ISO-8601 timestamp the
case was opened (the incident's discovery time). An incident is a moment, not a
build.

______________________________________________________________________

## 5. Case-Specific Fields and Enums

| Field | Meaning |
|---|---|
| `alert_class` | The playbook class: `auth` / `phishing` / `endpoint` / `exfiltration` / `ioc` / `unclassified`. |
| `entities` | The normalized entities (`analyst_playbooks.md` §1): principals, assets, indicators. |
| `verdict` | `malicious` / `benign` / `uncertain`. |
| `confidence` | 0.0–1.0 and its band (`high`/`moderate`/`low`), per the rubric. |
| `key_signal` | The single most load-bearing piece of evidence, in one line. |
| `correlated_alerts` | The raw alert ids folded into this case. |
| `actions` | Array of action objects (below) — the response, tiered and audited. |
| `case_status` | See enum below. |

**`actions[]`** each: `{ "action": "...", "target": "...", "tier": "T1|T2|T3",
"decision": "proposed|executed|rolled_back|denied", "autonomous": true|false,
"rollback": "...", "approved_by": "...|null", "ts": "<iso8601>",
"audit_ref": "line in audit.jsonl" }`.

**`case_status`** enum: `open` (investigating) → `contained` (a reversible action
is holding, verdict may still firm up) → `escalated` (handed to a human, awaiting
decision) → `resolved` (verdict final, response complete/approved) → `closed_benign`
(corroborated false positive) → `closed_duplicate` (folded into another case).

**Invariant INV-W1:** `case_status: resolved` with any `actions[].tier == "T3"`
requires that action's `decision` to be `executed` with a non-null `approved_by`,
or `denied`. A resolved case never contains an un-adjudicated T3 action.

**Invariant INV-W2:** no `actions[]` entry has `autonomous: true` unless its
`tier` is `T1`, or it is `T2` **and** the run recorded an allowlist match **and**
`breaker_state == "closed"` at the time. Anything else is `proposed`.

______________________________________________________________________

## 6. The Case Schema

One JSON object per file at `workspace/warden/cases/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this case; must match the filename.",
  "title": "Likely OAuth token theft — jamie@corp session used from two continents",
  "description": "Impossible-travel sign-in on jamie@corp: token minted in Frankfurt 14:02Z, same token used from São Paulo 14:06Z; the São Paulo session created an inbox forwarding rule. MFA was satisfied at mint only. Off-baseline device and geo.",
  "impact": "If the token is stolen, the attacker reads the user's mail and has established persistence via the forwarding rule; account is a member of the finance group.",
  "severity": "HIGH",
  "privileges_required": "NONE",
  "attacker_position": "EXTERNAL",
  "user_interaction": "NONE",
  "status": "VALID",
  "code_paths": ["user:jamie@corp"],
  "discovery_commit": "2026-08-08T14:08:33Z (case opened)",
  "cwe": "CWE-287",
  "signature": "16 hex chars, per §4.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "Reversible containment applied (session revoked); recommend token rotation and forwarding-rule removal (proposed to human as the rule change is user-data-affecting).",
  "alert_class": "auth",
  "entities": {
    "principals": ["jamie@corp"],
    "assets": ["idp:corp-tenant"],
    "indicators": ["ip:198.51.100.7", "ip:203.0.113.55"]
  },
  "verdict": "malicious",
  "confidence": 0.88,
  "confidence_band": "high",
  "key_signal": "Same OAuth token used from two locations 4,700 km apart within 4 minutes — physically impossible.",
  "correlated_alerts": ["siem:auth-4821", "siem:mailrule-1190"],
  "actions": [
    {"action": "disable_session", "target": "idp:session:9f2c", "tier": "T2",
     "decision": "executed", "autonomous": true,
     "rollback": "re-enable session 9f2c via IdP admin API",
     "approved_by": null, "ts": "2026-08-08T14:09:01Z", "audit_ref": "audit.jsonl#L2211"},
    {"action": "remove_forwarding_rule", "target": "mailbox:jamie@corp/rule:auto-fwd", "tier": "T3",
     "decision": "proposed", "autonomous": false,
     "rollback": "not auto-reversible (user-data change)",
     "approved_by": null, "ts": "2026-08-08T14:09:04Z", "audit_ref": "audit.jsonl#L2212"}
  ],
  "case_status": "contained",
  "history": [
    {"stage": "warden-vigil", "action": "opened", "details": "auth playbook matched impossible-travel + sensitive action", "timestamp": "<iso8601>"},
    {"stage": "warden-vigil", "action": "contained", "details": "allowlisted T2 session revoke, breaker closed, confidence 0.88", "timestamp": "<iso8601>"}
  ]
}
```

Use `"status": "VALID"` for a corroborated verdict; keep the case `open`/`escalated`
while `verdict` is `uncertain`. The `history` stage is namespaced `warden-vigil`
so a mixed pipeline keeps provenance of who did what.
