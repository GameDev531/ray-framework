---
name: ray-vault
description: >-
  Audits the datastore against exfiltration: database privileges and least-privilege roles, network reachability, encryption in transit, at rest, and at field level, credential sourcing and rotation, backup protection and restore testing, non-production data copies, and database-level audit logging.
  Use when the target persists data and you need database exfiltration-prevention findings written to workspace/findings/.
  Don't use for query-level injection (use ray-crucible), application authorization and tenancy (use ray-turnstile), or cloud topology and deploy pipelines (use ray-citadel).
---

# Vault (/ray-vault)

## System Goal

Datastore Exfiltration Auditor. Works backwards from the outcome nobody
survives — the whole database in someone else's hands — and checks each barrier
that should have stopped it: the privileges the application holds, the network
that can reach the port, the encryption that makes a stolen copy useless, the
credentials that open it, the backups that copy it, the non-production clones
that multiply it, and the audit trail that would have noticed.

Injection is how attackers get *in*. This stage is about how much they get once
they are in, and whether anyone ever knows.

## Command Definition

- **Command:** `/ray-vault`
- **Description:** Audits database privileges, exposure, encryption,
  credentials, backups, non-production copies, and audit logging, writing
  findings plus a control ledger.
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
  - `workspace/kb/THREAT_MODEL.md`, `workspace/kb/entities/*.md` (optional).
  - `ray-vault/references/datastore_hardening.md` — read before scoring.
  - Target source: migrations, schema and grant statements, ORM configuration,
    connection strings and pool setup, IaC for managed databases, caches, object
    storage and buckets, backup jobs and lifecycle rules, seed and fixture
    scripts, ETL/BI configuration.
  - `workspace/ledgers/ray-vault.json` from the previous pass, if present.
- **Writes**:
  - `workspace/findings/<uuid>.json` — standard Ray findings schema.
  - `workspace/ledgers/ray-vault.json` — datastore inventory and control ledger.
  - `workspace/archive/ledgers/ray-vault_pass_${N}.json` — copy of the previous
    ledger before overwrite.
- **Preconditions**:
  - Target files must be readable. This stage **never** connects to a database,
    never runs a query against a live system, and never reads a real backup. All
    verdicts come from code, migrations, and infrastructure descriptors; when
    those cannot settle a control, the finding is `NEEDS_RESEARCH`.
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

Skill-specific note: credential history (a connection string committed and later
removed) is found through the VCS carve-out in the LIVE repo root, not under
CODE_ROOT.

### Step 1: Build the Datastore Inventory

Enumerate every persistent store, not just "the database". Teams harden the
primary Postgres and leave a Redis on a public IP with no password.

For each store record: engine and version, purpose, whether it holds personal
data (join with `/ray-custodian`'s inventory when present), how the application
connects, where it is defined (IaC, docker-compose, managed service), and its
environments.

Cover: relational databases and their read replicas, document stores, key-value
caches (Redis, Memcached), search indexes (Elasticsearch, OpenSearch, Meili),
queues and streams (Kafka, RabbitMQ, SQS), object storage buckets, data
warehouses and BI extracts, vector stores, analytics databases, and any local
SQLite or on-disk file the application writes.

### Step 2: Privilege Separation

Score against `references/datastore_hardening.md` §1.

1. **What role does the application connect as?** Read connection strings and
   IaC. A connection as `postgres`, `root`, `sa`, `admin`, or the instance's
   master user is a finding on its own: a SQL injection anywhere then becomes
   read of every table, write of every table, and often file or command access.
2. **Are grants scoped?** Expected: a role per service, granted only the verbs
   it uses on only the tables it touches. Look for `GRANT ALL`, grants on
   `ALL TABLES IN SCHEMA`, ownership of the schema by the runtime role, and
   `DELETE`/`TRUNCATE`/`DROP` held by a service that never deletes.
3. **Separate roles for separate jobs**: migrations (DDL) versus runtime (DML),
   read-only reporting, background workers, and admin tooling. One role for
   everything means the application always runs with migration privileges.
4. **Analytics and BI**: do they connect to the primary or to a read replica,
   and with what privileges? A BI tool with a read-write production credential
   is a standing risk.
5. **Human access**: does the repository show engineers connecting to production
   directly (a `psql` script, a documented tunnel, credentials in a runbook)?
   Expected: bastion or session-manager access, approval, time-boxing, and
   auditing.
6. **`SECURITY DEFINER` functions, superuser extensions, and file-access
   functions** (`pg_read_file`, `COPY … FROM PROGRAM`, `LOAD_FILE`,
   `xp_cmdshell`) — check whether the runtime role can reach them.

### Step 3: Network Reachability

1. **Is the datastore reachable from the internet?** Read IaC for public IPs,
   `publicly_accessible = true`, `0.0.0.0/0` in security groups or firewall
   rules, port mappings in compose files, and Kubernetes `Service` types.
   Publicly reachable databases remain a leading cause of trivial breaches.
2. **Is the allowed source narrow?** Expected: only the application's security
   group or subnet reaches 5432/3306/6379/27017/9200. A CIDR spanning the whole
   VPC is `PARTIAL`.
3. **Default and absent authentication**: Redis with no `requirepass`,
   MongoDB or Elasticsearch with authentication disabled, a default password in
   a compose file that is also used in a deployed environment.
4. **Administrative interfaces** exposed alongside the store (Adminer, pgAdmin,
   Mongo Express, Kibana, RedisInsight) — also `/ray-sentry` `EXPO-01`.
5. **Object storage**: buckets without public-access block, permissive bucket
   policies or ACLs, wildcard principals, and pre-signed URLs with very long
   expiries or over-broad prefixes.

### Step 4: Encryption

1. **In transit**: TLS required on every connection. In Postgres,
   `sslmode=require` still permits an active MITM — `verify-full` is the
   expectation where a CA is available. Check `sslmode=disable`,
   MySQL `useSSL=false`, Redis without TLS, and internal replication traffic.
2. **At rest**: volume/disk encryption enabled (default on most managed
   services, but check the IaC rather than assuming), including replicas,
   snapshots, and backups. Note what it does and does not protect: it defends
   against stolen media, not against a compromised application.
3. **At field level**: for the highest-sensitivity columns (government ids,
   payment identifiers, health data, private documents) — AEAD encryption
   (AES-256-GCM or equivalent) performed by the application with keys held in a
   KMS, so a database dump alone does not disclose the values. Check for a
   home-rolled scheme: ECB mode, a static IV, encryption without
   authentication, or a key stored beside the ciphertext.
4. **Passwords are never encrypted** — they are hashed with a password KDF. If
   the code encrypts passwords reversibly, that is `/ray-turnstile` `CRED-01`
   territory; report and cross-reference.
5. **Key management**: keys from a KMS or secret manager, with rotation, and not
   the same key across environments. A key committed to the repository voids the
   entire control.
6. **Searchability trade-off**: where a field must be encrypted and searchable,
   check for a blind index or deterministic encryption — and note that
   deterministic encryption leaks equality; do not report a well-understood
   trade-off as a defect without saying what it costs.

### Step 5: Credentials

1. **Sourcing**: connection strings from a secret manager at runtime, via a
   workload identity (instance role, pod identity, OIDC), rather than from a
   committed file or a baked image layer.
2. **Committed credentials**: sweep source, config, notebooks, fixtures, CI
   definitions, Dockerfiles, Helm values, and VCS history. Every hit is a
   finding whose `mitigation` must say **rotate**, not merely remove.
3. **Rotation**: is rotation possible without downtime and is it automated
   (managed rotation, or an overlap window)? Absence means a leaked credential
   stays valid indefinitely.
4. **Per-environment credentials**: a shared credential across dev, staging, and
   production means a developer laptop compromise is a production compromise.
5. **CI/CD**: static long-lived database or cloud credentials in CI secrets
   where federated short-lived credentials (OIDC) are available.

### Step 6: Backups

A leaked backup is a leaked database, and backups are usually the least guarded
copy of the most complete data.

1. **Existence and scope**: is there a backup mechanism at all, and does it
   cover every store in the inventory (people forget Redis-persisted state,
   object storage, and search indexes)?
2. **Encryption** of backup artifacts, with a key not stored beside them.
3. **Storage**: a private bucket with public access blocked, restricted IAM,
   versioning, and ideally object lock/immutability — the control that survives
   ransomware. A backup bucket writable by the same credentials the application
   holds is a single-compromise loss.
4. **Retention and the 3-2-1 property**: multiple copies, more than one medium
   or account, at least one off-site or in a separate cloud account.
5. **Restore testing**: is there evidence — a script, a scheduled job, a
   documented drill — that a restore has ever been exercised? An untested backup
   is not a backup, and its absence is a legitimate MEDIUM finding.
6. **Backups and erasure**: erasure obligations must eventually reach backups
   (cross-reference `/ray-custodian` `RET-03`).
7. **Local dumps**: scripts that write `pg_dump` output to a developer machine,
   a shared drive, or a repository directory.

### Step 7: Non-Production Copies and Minimization

The most common "test" breach is a production copy in a loosely guarded
environment.

1. **Seeds and fixtures**: do any contain real personal data?
2. **Refresh scripts** that clone production into staging or development —
   check for an anonymization or masking step in the same pipeline, applied
   before the data lands, not after.
3. **Masking quality**: replacing names but keeping emails, or hashing an email
   into a value that is still joinable, is pseudonymization, not anonymization.
4. **Environment access**: staging with weaker authentication holding production
   data is a production-severity exposure at staging-grade protection.
5. **Data warehouse and BI extracts**: often the widest, least controlled copy.
6. **Local development**: `.sql` dumps, `.sqlite` files, or CSV extracts
   committed to the repository. Grep for them explicitly.
7. **Minimization at the source**: columns collected and stored that nothing
   reads (join with `/ray-custodian` `MIN-01`) — the cheapest reduction in
   breach impact available.

### Step 8: Detection At The Data Layer

1. **Database audit logging** for sensitive tables (pgAudit, MySQL audit plugin,
   SQL Server audit, MongoDB auditing, CloudTrail data events for object
   storage). Absent → an exfiltration leaves no trace at the layer where it
   happened.
2. **Unusual query patterns**: is there anything that would notice a full-table
   `SELECT` outside the application's normal shape, a new client connecting, or
   a spike in rows returned? Alerting is `/ray-sentry`'s; the data-layer signal
   is here.
3. **Egress volume monitoring** from the database subnet.
4. **Slow-query and error logs** stored where they do not themselves leak data
   (a slow-query log containing bound parameters is a personal-data store —
   cross-reference `/ray-seam` `LOG-01`).
5. **Log integrity**: can the application role delete or alter audit records?

### Step 9: Evidence Discipline

- **Anchor at the artifact that decides the control**: the IaC resource, the
  migration with the `GRANT`, the connection string, the backup job. Never at a
  file you did not read.
- **Distinguish "not in the repository" from "not configured".** Managed
  databases are often configured outside the codebase. When the snapshot cannot
  settle a control, write `NEEDS_RESEARCH` and name what would (a Terraform
  state, a console export, a runbook). Do not report a control absent because
  the repository is not where it lives.
- **Never connect to anything.** No live queries, no reading real backups, no
  credential validation.
- **Prefer the concrete privilege claim.** "The runtime role holds `GRANT ALL`
  on the schema (migrations/0001_init.sql:14), so any injection reaches every
  table including `audit_log`" is far stronger than "least privilege is not
  followed".
- **Severity defaults**: datastore publicly reachable, or reachable with default
  or absent authentication, HIGH; application connecting as superuser HIGH;
  unencrypted backups in a bucket without public-access block HIGH; production
  personal data in a non-production environment HIGH; committed credentials
  HIGH; no TLS to the datastore MEDIUM–HIGH; no field-level encryption for
  highly sensitive columns MEDIUM; no restore testing MEDIUM; no database audit
  logging MEDIUM. `ray-gauge` applies the caps.

### Step 10: Compile and Write Findings

Create `workspace/findings/` if missing; one JSON object per file at
`workspace/findings/<uuid>.json`.

Compute before writing:

1. **`cwe`** — `CWE-250` (execution with unnecessary privileges), `CWE-732`
   (incorrect permission assignment), `CWE-284` (improper access control),
   `CWE-311` (missing encryption of sensitive data), `CWE-319` (cleartext
   transmission), `CWE-312` (cleartext storage), `CWE-327` (broken or risky
   crypto), `CWE-798` (hardcoded credentials), `CWE-521` (weak password
   requirements — default datastore passwords), `CWE-530` (exposure through
   backup files), `CWE-1188` (insecure default), `CWE-778` (insufficient
   logging), `CWE-359` (exposure of private information). Omit when none
   applies.
2. **`signature`** — first 16 hex chars of
   `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`, with the
   suite's normalization rule (title lowercased, stripped to `[a-zA-Z0-9]`;
   empty → first 16 hex of `sha256(raw title)`; `primary_target` = first
   `code_paths` entry minus `:line`; empty → hash over the sorted `code_paths`
   join). Compute once, never recompute.
3. **`lineage_id`** — inherit from an archived finding with the same
   `signature` under `workspace/archive/findings_pass_*/` or
   `workspace/archive/loop*_findings/` (highest pass wins), else fresh UUIDv4.
4. **`discovery_commit`** — snapshot id verbatim when pinned; omitted in
   DEGRADED mode.

#### Findings Schema Format (per file)

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Application connects to Postgres as the instance superuser",
  "description": "Which store, which control is absent or weak, the artifact that establishes it, and what it means for blast radius: what an attacker reaches once they hold this position, and which other barrier (if any) still stands.",
  "impact": "Concrete outcome (e.g., any SQL injection reads and writes every table and can disable auditing; a leaked backup URL discloses the full customer table).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["infra/rds.tf:22", "src/db/pool.ts:9"],
  "discovery_commit": "snapshot id verbatim; omit entirely in DEGRADED mode.",
  "cwe": "CWE-250 (optional)",
  "signature": "First 16 hex chars of the sha256 defined above.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The corrective change, concretely (the exact GRANT set, the security-group rule, the sslmode value, the bucket policy), plus how to verify it (a check in CI, an IaC policy test, a restore drill).",
  "datastore": "Optional. The inventory entry this finding belongs to, e.g. 'primary-postgres'.",
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

### Step 11: Write the Control Ledger

1. Resolve `N` from `pass_number`, else `max` archive pass + 1, else `1`.
2. Copy any existing `workspace/ledgers/ray-vault.json` to
   `workspace/archive/ledgers/ray-vault_pass_${N}.json` (`mkdir -p` first).
3. Write `workspace/ledgers/ray-vault.json` with `skill`, `pass_number`,
   `snapshot_id`, `generated_at`, a `datastores` array (each with `name`,
   `engine`, `holds_personal_data`, `defined_at`, `environments`), and a
   `controls` array of `{id, control, state, evidence, finding_ids, note}` with
   `state` in `PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN`. Use the
   control ids from `references/datastore_hardening.md` §8; each appears exactly
   once **per datastore** (prefix the id with the datastore name when there are
   several, e.g. `primary-postgres/PRIV-01`).

### Step 12: Complete

Report: findings by severity, controls by state, the datastore inventory with
which stores hold personal data, and every `UNKNOWN` with its blocker. Do not
print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

- **SQL injection and query construction** → `/ray-crucible`. This stage assumes
  injection may happen and asks how far it gets.
- **Tenant isolation, RLS policy correctness, application authorization** →
  `/ray-turnstile`. RLS as a *privilege* concern (roles, `BYPASSRLS`,
  ownership) is here; RLS as a *tenancy* control is there.
- **Retention, erasure, anonymization as legal obligations, personal-data
  classification** → `/ray-custodian`. The technical enforcement is here.
- **Alerting on data-layer anomalies, audit-log coverage across the
  application** → `/ray-sentry`.
- **Environment separation, VPC design, IaC review process, CI credential
  federation** → `/ray-citadel`.
