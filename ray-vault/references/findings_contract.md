# Findings Contract — ray-vault

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

**Anchor at the artifact that decides the control** — the IaC resource, the
migration carrying the `GRANT`, the connection string, the backup job. Never at
a file you did not read.

**Distinguish "not in the repository" from "not configured".** This is the
characteristic false positive of this domain: managed databases are routinely
configured outside the codebase, so a missing `storage_encrypted` line may mean
the encryption is set in a console, not that it is off. When the snapshot cannot
settle a control, write `NEEDS_RESEARCH` and name the artifact that would — a
Terraform state, a console export, a runbook.

**Never connect to anything.** No live queries, no reading real backups, no
validating a credential to see whether it still works. Everything comes from
code, migrations, and infrastructure descriptors.

**Prefer the concrete privilege claim.** "The runtime role holds `GRANT ALL` on
the schema at `migrations/0001_init.sql:14`, so any injection reaches every
table including `audit_log`" is reviewable and actionable. "Least privilege is
not followed" is neither.

**Say what a control does and does not protect.** At-rest encryption defends
against stolen media and decommissioned disks; it does nothing against a
compromised application or a leaked credential, both of which read straight
through it. A finding that implies otherwise misdirects the fix.

**Rotation language.** Every committed-credential finding must state in
`mitigation` that the credential is compromised and must be rotated. Removing it
from history is housekeeping, and a reader who takes away the wrong lesson keeps
a live credential they believe is dead.

**Read the file's role before reporting it.** A local development
`docker-compose.yml` publishing 5432 to `127.0.0.1` is not a finding; a deployed
one publishing it to `0.0.0.0` is. Say which you concluded and why.

**Status.** Default `PROVISIONALLY_VALID`; `NEEDS_RESEARCH` where the control
plausibly lives outside the snapshot.

______________________________________________________________________

## 2. Severity Defaults

| Situation | Default |
|---|---|
| Datastore publicly reachable, or reachable with default/absent authentication | HIGH |
| Application connecting as superuser or the instance master user | HIGH |
| Committed database credential or connection string | HIGH |
| Unencrypted backups in a bucket without public-access block | HIGH |
| Production personal data in a non-production environment | HIGH |
| Object storage bucket with a wildcard principal or public ACL | HIGH |
| Backups deletable by the same credential the application holds | MEDIUM–HIGH |
| No TLS, or unverified TLS, to the datastore | MEDIUM–HIGH |
| `GRANT ALL` / destructive verbs held by a service that never uses them | MEDIUM |
| No field-level encryption for the most sensitive columns | MEDIUM |
| No restore testing evidence | MEDIUM |
| No database audit logging on sensitive tables | MEDIUM |
| Home-rolled field encryption (ECB, static IV, no MAC) | MEDIUM–HIGH |
| Slow-query logs carrying bound personal data | LOW–MEDIUM |
| No connection logging | LOW |

Reserve CRITICAL for a described, unauthenticated path to the full dataset.

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

Order `code_paths` with the **deciding artifact first** (the IaC resource or the
migration), then the supporting site (the connection string, the pool setup).
Keep the order stable across passes. Compute once at creation; never recompute.

Where several datastores exist, include the datastore name in the `title` so
signatures do not collide across stores with the same defect — "Redis reachable
from the internet" and "Postgres reachable from the internet" must be distinct
findings with distinct lineages.

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
| `CWE-250` | Execution with unnecessary privileges (superuser connection) |
| `CWE-732` | Incorrect permission assignment for a critical resource |
| `CWE-284` | Improper access control (network reachability) |
| `CWE-311` | Missing encryption of sensitive data |
| `CWE-319` | Cleartext transmission of sensitive information |
| `CWE-312` | Cleartext storage of sensitive information |
| `CWE-327` | Use of a broken or risky cryptographic algorithm |
| `CWE-329` | Generation of a predictable IV with CBC mode |
| `CWE-798` | Use of hard-coded credentials |
| `CWE-521` | Weak password requirements (default datastore passwords) |
| `CWE-530` | Exposure of information through backup files |
| `CWE-552` | Files or directories accessible to external parties |
| `CWE-1188` | Insecure default initialization |
| `CWE-778` | Insufficient logging (no database audit trail) |
| `CWE-359` | Exposure of private personal information |
| `CWE-212` | Improper removal of sensitive information (weak masking) |

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Application connects to primary Postgres as the instance superuser",
  "description": "Which store, which control is absent or weak, the artifact that establishes it, and what it means for blast radius: what an attacker reaches once they hold this position, and which other barrier (if any) still stands.",
  "impact": "Concrete outcome (e.g., any SQL injection reads and writes every table and can disable auditing; a leaked backup URL discloses the full customer table).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["infra/rds.tf:22", "src/db/pool.ts:9"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-250",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The corrective change concretely — the exact GRANT set, the security-group rule, the sslmode value, the bucket policy — plus how to verify it stays: a CI check, an IaC policy test, a restore drill.",
  "datastore": "Optional. The inventory entry this belongs to, e.g. 'primary-postgres'.",
  "history": [
    {
      "stage": "vault",
      "action": "created",
      "details": "Datastore exfiltration-prevention finding recorded.",
      "pass_number": 1,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

The "how to verify it stays" half of `mitigation` matters here more than
elsewhere, because these controls drift silently: a `GRANT` added during an
incident, a security group widened for a migration, a bucket policy loosened for
a one-off export. An IaC policy test is what makes the fix stick.

______________________________________________________________________

## 6. Control Ledger

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`; if missing or
   invalid, use `max` of the `findings_pass_N` / `loopN_findings` folders in
   `workspace/archive/` + 1, defaulting to `1`.
2. If `workspace/ledgers/ray-vault.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-vault_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-vault.json`.

```json
{
  "skill": "ray-vault",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "generated_at": "<iso8601>",
  "datastores": [
    {
      "name": "primary-postgres",
      "engine": "postgres 15",
      "holds_personal_data": true,
      "defined_at": "infra/rds.tf:8",
      "environments": ["production", "staging"]
    }
  ],
  "controls": [
    {
      "id": "primary-postgres/PRIV-01",
      "control": "Application does not connect as superuser/master",
      "state": "PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN",
      "evidence": "infra/rds.tf:22",
      "finding_ids": [],
      "note": ""
    }
  ]
}
```

Use the control ids from `datastore_hardening.md` §8, **once per datastore**.
With more than one store, prefix the id with the store name
(`primary-postgres/PRIV-01`, `sessions-redis/NET-03`) so the ledger stays
unambiguous and comparable across passes.

`NOT_APPLICABLE` is a real and common answer here — the RLS-adjacent privilege
ids on engines without row-level security, field-level encryption on a store
holding no sensitive columns, replica controls where there are no replicas.
State the reason; that is what makes it a documented decision rather than a gap.
