# Maintenance Docket — Areas, Controls, and the Evidence That Proves Them

The checklist for `ray-steward`. Read the section for the area you are assessing.
Each control names the **evidence** that proves it and the **honest limit** of
what static inspection can conclude — because the defining trap of maintenance
auditing is mistaking *existence* for *verification* (a backup script is not a
tested restore; an alert rule file is not a firing alert).

For every control, record posture as `ok` (evidence of the control working),
`gap` (evidence it is missing or broken), or `unknown` (no evidence either way).
An `unknown` on a high-consequence control is itself a finding — "no evidence a
restore has ever succeeded" is a real risk, not a pass.

## Table of Contents

- [1. Dependency Freshness & End-of-Life](#1-dependency-freshness--end-of-life)
- [2. Patch Cadence](#2-patch-cadence)
- [3. Backup & Verified Restore](#3-backup--verified-restore)
- [4. Database Migration Safety](#4-database-migration-safety)
- [5. Disaster Recovery & Runbooks](#5-disaster-recovery--runbooks)
- [6. Secret Rotation](#6-secret-rotation)
- [7. Observability & Alert Coverage](#7-observability--alert-coverage)

______________________________________________________________________

## 1. Dependency Freshness & End-of-Life

Consume `ray-manifest`'s output where present rather than re-deriving versions.
- **Runtime/language EOL** — the language runtime, framework, base image, and
  database version against their published EOL dates. An EOL runtime stops
  receiving security patches — the risk rises with time regardless of today's CVE
  list. *Evidence*: the declared version (`.nvmrc`, `go.mod` go directive,
  `runtime.txt`, `FROM` base image, DB engine version) vs. the known EOL date.
- **Major-version lag** — components several majors behind current, where the
  upgrade path itself is now a large, risky project (debt compounding).
- **Abandoned dependencies** — a dependency with no releases in years / archived
  upstream (from `ray-manifest`'s unmaintained flag).
*Limit*: static inspection sees declared versions; it cannot always see the
running version. Say which you assessed.

______________________________________________________________________

## 2. Patch Cadence

- **Automated update tooling** — is there a Dependabot/Renovate config or an
  equivalent, and are its PRs actually merged (not piling up ignored)?
  *Evidence*: `.github/dependabot.yml`/`renovate.json` + merged-PR history.
- **A patch SLA** — any documented cadence for applying security updates.
- **CI that would catch a regression** — updates are only safe to apply
  frequently if tests would catch a break; a project with no test gate has an
  implicit "never update" cadence. *Evidence*: CI config + a real test suite.
*Limit*: the presence of tooling ≠ a healthy cadence; check that it is used.

______________________________________________________________________

## 3. Backup & Verified Restore

The area with the widest gap between "looks fine" and "is fine".
- **Backups exist** — scheduled, automated, covering the stateful stores.
  *Evidence*: a backup job/schedule (cron, managed snapshot, CI job). (Encryption/
  privileges of the backup are `ray-vault`'s.)
- **Restore is *verified*** — the load-bearing control. Is there evidence a
  restore has ever **succeeded** — a documented/automated restore test, a game-day,
  a scripted `restore && verify`? A backup nobody has restored is a hope, not a
  control. *Evidence*: a restore-test script/job or a documented successful drill.
  Absent evidence → `unknown` and a finding: "backups exist; no evidence restore
  works."
- **RPO/RTO defined** — is the acceptable data-loss window and recovery time
  stated, and does the backup frequency actually meet the RPO? *Evidence*: an
  RPO/RTO statement + backup frequency.
- **Offsite / immutable copies** — protection against a backup that shares the
  blast radius of what it backs up (ransomware deleting both).

______________________________________________________________________

## 4. Database Migration Safety

- **Reversibility** — do migrations have a tested down/rollback path, or is
  forward the only direction? *Evidence*: down migrations present and exercised.
- **Non-destructive & lock-aware** — a migration that drops/renames a column in
  use, or takes a long exclusive lock on a large table, causes an outage or data
  loss. Look for destructive DDL without an expand/contract pattern, and
  full-table locks on hot tables. *Evidence*: the migration files themselves.
- **Tested against production-like data** — migrations run in CI/staging on a
  realistic dataset before prod, not first-run in production. *Evidence*: a
  staging/CI migration step.
- **Data backfills bounded** — large backfills batched, not one giant
  transaction. *Evidence*: the backfill scripts.

______________________________________________________________________

## 5. Disaster Recovery & Runbooks

- **A DR plan exists** — documented steps to recover from the loss of the primary
  region/provider/datastore, with the RTO it targets. *Evidence*: a DR doc.
- **Runbooks for the top incidents** — the common failures (DB down, cert
  expiry, disk full, key rotation) have written, current runbooks a on-call could
  follow at 3am. *Evidence*: runbook docs, and whether they are current (dated,
  referencing live systems).
- **Single points of failure** — a documented or evident SPOF with no failover
  (one DB with no replica, one region, one key holder).
- **On-call / escalation defined** — someone is actually paged, with an
  escalation path. *Evidence*: on-call/escalation config or docs.

______________________________________________________________________

## 6. Secret Rotation

- **Rotation exists and has a cadence** — credentials, API keys, and certificates
  are rotated on a schedule, not set-once-forever. *Evidence*: rotation
  automation/policy; cert auto-renewal (ACME) config.
- **Certificate expiry monitoring** — expiring TLS certs are alerted before they
  lapse (a classic avoidable outage). *Evidence*: an expiry check/alert.
- **A rotation runbook** — when a secret leaks, there is a known, fast procedure
  to rotate it everywhere it is used. *Evidence*: the runbook + a map of where
  each secret is consumed.
*Limit*: `ray-steward` audits the rotation *posture*; finding a specific leaked
secret is `ray-quarry`/`ray-terrain`.

______________________________________________________________________

## 7. Observability & Alert Coverage

- **The three signals wired** — logs, metrics, and traces exist for the critical
  paths, and are retained long enough to investigate an incident. *Evidence*:
  logging/metrics/tracing config.
- **Alerts on the failure modes that matter** — not just CPU, but the
  security-and-availability signals: auth-failure spikes, error-rate/latency SLO
  breaches, backup-job failure, cert expiry, disk/quota. An alert rule that exists
  but routes nowhere is a `gap`. *Evidence*: alert rules + a notification route.
- **Alert quality** — coverage without so much noise that real alerts are ignored
  (alert fatigue is a resilience risk). *Evidence*: alert volume/routing if
  visible.
- **Audit logging** — security-relevant actions are logged and retained (ties to
  `ray-sentry`'s audit-logging control; `ray-steward` checks it is *maintained*
  and retained, not just present).
