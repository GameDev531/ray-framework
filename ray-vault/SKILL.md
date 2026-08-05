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

Injection is how attackers get *in*; `/ray-crucible` owns that. This stage is
about how much they get once they are in, and whether anyone ever knows.

## Command Definition

- **Command:** `/ray-vault`
- **Description:** Audits database privileges, exposure, encryption,
  credentials, backups, non-production copies, and audit logging, writing
  findings plus a control ledger.
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
  `workspace/kb/THREAT_MODEL.md` and `workspace/kb/entities/*.md` (optional);
  this skill's `references/*.md`; target source (migrations, schema and grant
  statements, ORM and pool configuration, connection strings, IaC for managed
  databases, caches, object storage, backup jobs and lifecycle rules, seed and
  fixture scripts, ETL/BI configuration); `workspace/ledgers/ray-vault.json`
  from the previous pass, if present.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-vault.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-vault_pass_${N}.json` before overwriting.
- **Preconditions**: target files readable. This stage **never** connects to a
  database, runs a query against a live system, or reads a real backup. Every
  verdict comes from code, migrations, and infrastructure descriptors; when
  those cannot settle a control, the finding is `NEEDS_RESEARCH`.
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges). The ledger is archived per pass and then
  deterministically overwritten.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/datastore_hardening.md` | before Step 2, then per area through Step 7 | Privilege separation with the expected `GRANT` shape and the failing shapes; network reachability with grep starters; encryption in transit, at rest, and at field level per engine; credential sourcing; backups; non-production copies; data-layer detection; and the control-ledger ids |
| `references/findings_contract.md` | before writing the first finding, and again at Step 8 | Findings schema, the four computed fields, this domain's CWE set, evidence discipline, severity defaults, and the ledger format |

The hardening reference is organized by area and per engine where the engine
changes the verdict — `sslmode=require` and `sslmode=verify-full` look
equivalent and are not, and that distinction is in §3, not in your memory.

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

CODE-READING stage, so the findings-only skip does not apply. Credential history
— a connection string committed and later removed — is found through the VCS
carve-out in the live repo root, not under CODE_ROOT. This skill's
`references/*.md` sit beside `SKILL.md`, not under CODE_ROOT.

### Step 1: Build the Datastore Inventory

Enumerate every persistent store, not just "the database". Teams harden the
primary Postgres and leave a Redis on a public IP with no password.

Cover relational databases and their read replicas, document stores, key-value
caches, search indexes, queues and streams, object storage buckets, data
warehouses and BI extracts, vector stores, analytics databases, and any local
SQLite or on-disk file the application writes.

For each, record engine and version, purpose, whether it holds personal data
(join with `/ray-custodian`'s inventory when present), how the application
connects, where it is defined, and its environments. Every later control is
scored **per datastore**.

### Step 2: Privilege Separation

The control that decides how much a SQL injection is worth. Work through
`datastore_hardening.md` §1: what role the application connects as, whether
grants are scoped to the verbs and tables actually used, whether migrations,
runtime, reporting, and workers have separate roles, whether the runtime role
owns the schema, and whether in-database escalation primitives
(`SECURITY DEFINER`, `COPY … FROM PROGRAM`, `xp_cmdshell`) are reachable.

§1 ends with the method for auditing this without connecting: compare the verbs
the application actually issues against the verbs the role is granted. Any grant
with no corresponding usage is excess privilege.

### Step 3: Network Reachability

`datastore_hardening.md` §2, with its grep starters. Public reachability, source
restriction, default or absent authentication (Redis without `requirepass`,
Elasticsearch with security disabled), exposed admin UIs, and object-storage
exposure — public-access block, wildcard principals, pre-signed URL scope.

One judgement call recurs here: a `docker-compose.yml` publishing port 5432 is
only a finding if that file describes a deployed environment. Read the file's
role before reporting, and say which you concluded.

### Step 4: Encryption

`datastore_hardening.md` §3, in three layers. **In transit**, note that
`sslmode=require` still permits an active MITM — `verify-full` is the
expectation where a CA is available. **At rest**, verify it in the IaC rather
than assuming the managed default, including for replicas and snapshots, and
state plainly what it does and does not protect. **At field level**, check the
AEAD construction, key custody in a KMS, key rotation, and whether a plaintext
"search copy" beside the ciphertext quietly voids the whole control.

Passwords are hashed, never encrypted. If the code encrypts them reversibly,
that is `/ray-turnstile` `CRED-01` — report and cross-reference.

### Step 5: Credentials

`datastore_hardening.md` §4: runtime sourcing from a secret manager via workload
identity, no committed credentials (including in VCS history), distinct
credentials per environment and per consumer, a rotation path, federated
short-lived credentials in CI, and secret scanning.

**Every committed-credential finding must say in `mitigation` that the
credential is compromised and must be rotated.** Removal from history is
housekeeping, not remediation.

### Step 6: Backups and Non-Production Copies

A leaked backup is a leaked database, and backups are usually the least guarded
copy of the most complete data. `datastore_hardening.md` §5 covers coverage,
encryption, storage restriction, immutability against ransomware, account
separation, retention, access logging, and — the one that is almost always
absent — **evidence that a restore has ever been exercised**.

§6 covers the other multiplier: production copies in non-production
environments, the quality of the masking applied (hashing an email into a value
that is still joinable is pseudonymization, not anonymization), and dumps
committed to the repository.

### Step 7: Data-Layer Detection

`datastore_hardening.md` §7: database audit logging on sensitive tables, audit
records the application role cannot delete, a query-anomaly signal, egress
volume monitoring, connection logging, and slow-query logs that do not
themselves become a personal-data store.

Alerting rules on these signals belong to `/ray-sentry`; the presence of the
signal at the data layer is scored here.

### Step 8: Write Findings and the Ledger

Follow `references/findings_contract.md`. The distinction that matters most in
this domain: **"not in the repository" is not "not configured".** Managed
databases are frequently configured outside the codebase; when the snapshot
cannot settle a control, write `NEEDS_RESEARCH` and name what would (a Terraform
state, a console export, a runbook). Reporting a control absent because the
repository is not where it lives is the characteristic false positive here.

Prefer the concrete privilege claim: "the runtime role holds `GRANT ALL` on the
schema (`migrations/0001_init.sql:14`), so any injection reaches every table
including `audit_log`" beats "least privilege is not followed".

### Step 9: Complete

Report findings by severity, controls by state, the datastore inventory with
which stores hold personal data, and every `UNKNOWN` with its blocker. Do not
print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| SQL injection and query construction | `/ray-crucible` |
| Tenant isolation, RLS policy correctness, application authorization | `/ray-turnstile` |
| Retention, erasure, anonymization as legal obligations | `/ray-custodian` |
| Alerting on data-layer anomalies, application audit-log coverage | `/ray-sentry` |
| Environment separation, VPC design, IaC review, CI credential federation | `/ray-citadel` |

RLS appears in two stages by design: as a *tenancy* control it is
`/ray-turnstile`'s; as a *privilege* concern — roles, `BYPASSRLS`, table
ownership — it is here. `ray-condenser` merges the overlap.
