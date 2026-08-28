# Findings Contract — ray-steward

How `ray-steward` writes its findings. It reuses the standard Ray finding schema
and the four computed fields, adds the maintenance-specific fields, and stays
consistent with the pipeline. The distinctive thing here is that a finding scores
a **risk that grows over time**, not an exploit that works today — the schema and
severity guidance reflect that. Read before the first finding, and again at Step 3.

## Table of Contents

- [1. Evidence Discipline (existence vs. verification)](#1-evidence-discipline-existence-vs-verification)
- [2. Scoring Risk-Over-Time](#2-scoring-risk-over-time)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. Steward-Specific Fields and Enums](#4-steward-specific-fields-and-enums)
- [5. CWE Set](#5-cwe-set)
- [6. Findings Schema](#6-findings-schema)

______________________________________________________________________

## 1. Evidence Discipline (existence vs. verification)

**Existence is not verification.** The core discipline: a control that *exists*
(a backup script, an alert rule file, a migration) is not a control that *works*
(a verified restore, a firing alert, a tested rollback). State which you
established. "A backup job exists but there is no evidence a restore has ever
succeeded" is an accurate, high-value finding — do not round it up to "backups OK"
or down to "no backups".

**`unknown` is a valid, reportable posture.** When the evidence for a
high-consequence control is absent, the finding says so honestly rather than
guessing. An `unknown` on restore-verification or DR is a finding; an `unknown` on
a minor control is a note.

**Anchor at the artifact, or name the absence.** `code_paths[0]` points at the
relevant file (the CI config, the migration, the backup script). When the gap is
an *absence* (no DR plan at all), `code_paths` names the area/expected location and
the description makes the absence explicit.

______________________________________________________________________

## 2. Scoring Risk-Over-Time

Severity reflects **consequence × how the probability grows if nothing changes**,
not exploitability today. `ray-gauge` applies final caps.

| Gap | Default |
|---|---|
| Unverified restore / no DR for a system holding critical data; runtime already EOL (no more security patches) | HIGH (CRITICAL if a failure would be unrecoverable) |
| Runtime EOL within months; destructive/locking migration on a hot table; no cert-expiry monitoring; backup exists but never test-restored | HIGH–MEDIUM |
| Major-version lag with a hard upgrade path; no automated update tooling; missing alerts on key failure modes; no secret-rotation cadence | MEDIUM |
| Minor freshness lag; runbook gaps for rare incidents; observability retention short | LOW |
| Control present *and verified* | not a finding (record as `ok` in posture.json) |

Because the risk is temporal, the description should state the **time dimension**:
what changes, and by when (EOL date, the next incident, the day a restore is
actually needed). `attacker_position` is often not applicable — set it to the
honest value (`N/A`/`UNKNOWN`) for a pure resilience gap rather than forcing an
attacker framing.

______________________________________________________________________

## 3. The Four Computed Fields

**`cwe`** (optional) — from §5.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`, where
`primary_target` is `code_paths[0]` minus a trailing `:line`, or the
`maintenance_area` when the finding is an absence; if empty, hash
`sorted(code_paths)`.

**`lineage_id`** — inherit from an archived finding with the same `signature`
(the same recurring gap); else a fresh UUIDv4.

**`discovery_commit`** — the repo commit assessed. For a time-based finding, the
description also carries the *external* time dimension (e.g. the EOL date), which
the commit alone does not capture.

______________________________________________________________________

## 4. Steward-Specific Fields and Enums

| Field | Meaning |
|---|---|
| `maintenance_area` | `freshness` / `patch_cadence` / `backup_restore` / `migration_safety` / `dr_runbook` / `secret_rotation` / `observability`. |
| `posture` | `gap` (missing/broken) or `unknown` (no evidence). A finding is written for both; `ok` controls stay in `posture.json`, not findings. |
| `control` | The specific control assessed (e.g. "verified restore", "cert-expiry alert"). |
| `time_dimension` | The way risk grows: an EOL date, "on the next restore", "grows with每 unpatched month". Free text; the honest "why this matters later". |
| `evidence_ref` | The artifact examined (or "none found" for an absence). |

______________________________________________________________________

## 5. CWE Set

`CWE-1104` (unmaintained third-party component / EOL), `CWE-1329` (reliance on a
component past EOL), `CWE-778` (insufficient logging), `CWE-223`/`CWE-778`
(insufficient audit/observability), `CWE-757`/`CWE-1188` (insecure defaults left
in place), plus `CWE-404`/`CWE-459` (improper resource shutdown / incomplete
cleanup) where relevant to recovery. Many resilience gaps have no clean CWE —
omit it rather than forcing one; the `maintenance_area` carries the taxonomy.

______________________________________________________________________

## 6. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Backups exist but restore has never been verified",
  "description": "ops/backup.sh runs a nightly pg_dump to object storage, but there is no restore-test script, CI job, or documented drill — no evidence a restore has ever succeeded. RPO/RTO are undefined. The gap only surfaces during an actual incident, when it is too late to discover the dump is unusable.",
  "impact": "If the primary database is lost or corrupted, recovery may fail or take an unknown time; an untested backup is effectively no backup for the data it is meant to protect.",
  "severity": "HIGH",
  "privileges_required": "N/A",
  "attacker_position": "N/A",
  "user_interaction": "N/A",
  "status": "VALID",
  "code_paths": ["ops/backup.sh"],
  "discovery_commit": "abc1234",
  "cwe": null,
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "Add an automated restore test (restore the latest dump into a scratch database and assert row counts / a canary record) on a schedule; define and document RPO/RTO; run a recovery game-day. Then this becomes a verified control.",
  "maintenance_area": "backup_restore",
  "posture": "unknown",
  "control": "verified restore",
  "time_dimension": "risk is latent until the day a restore is actually needed, when it is unrecoverable",
  "evidence_ref": "ops/backup.sh (backup present); no restore-test evidence found",
  "history": [
    {"stage": "steward-maint", "action": "assessed", "details": "backup exists; restore verification unknown", "timestamp": "<iso8601>"}
  ]
}
```

Use `"status": "VALID"` — an assessed gap or an evidenced `unknown` is a real
finding. Set the attacker fields to `N/A`/`UNKNOWN` for pure resilience gaps
rather than inventing an attacker. The `history` stage is namespaced
`steward-maint` for provenance.
