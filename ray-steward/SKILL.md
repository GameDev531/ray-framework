---
name: ray-steward
description: >-
  Operational maintenance & resilience auditor: assesses what keeps a system secure over time — dependency freshness and end-of-life, patch cadence, backup existence AND verified restore, database-migration safety, disaster-recovery and runbook readiness, secret-rotation cadence, and observability/alert coverage.
  Use to find the slow-decay risks that a point-in-time security audit misses — the backup nobody has ever restored, the runtime a year past EOL, the migration that locks the table, the alert that was never wired.
  Don't use it for point-in-time vulnerabilities (that's the domain suite) or dependency CVEs (that's ray-manifest, whose output this consumes); it audits upkeep and resilience, not a single snapshot's bugs.
---

# Steward (/ray-steward)

## System Goal

Operational Maintenance & Resilience Auditor. Security is not a state you reach
once; it decays. A system that was sound at launch rots as its runtime reaches
end-of-life, its dependencies drift years behind, its one backup is never
test-restored, its migrations grow riskier, and the alert that would catch an
incident was never actually wired up. `ray-steward` audits that **trajectory** —
the upkeep and resilience posture that determines whether the system is still
secure and recoverable six months from now.

It is the forward-looking counterpart to the point-in-time stages. Where
`ray-manifest` says "this dependency has a CVE now", `ray-steward` says "this
runtime is EOL in two months and the upgrade path is untested"; where `ray-vault`
confirms a backup is encrypted, `ray-steward` asks the harder question — "has a
restore ever actually succeeded, and what is the RPO/RTO?". It is a drop-in
sibling of `ray-prospector`, writing the same finding JSON.

## Command Definition

- **Command:**
  `/ray-steward [--repo_root=<path>] [--areas=<list>] [--state_root=<path>]`
- **Description:** Assesses the maintenance and resilience posture across the
  areas below and writes one finding per gap that raises risk over time.
- **Arguments (all optional):**
  - `--repo_root`: the working tree and its ops config to assess. Absent →
    current directory.
  - `--areas`: restrict to a subset (`freshness,backup,migration,dr,secrets,observability`).
    Absent → all areas that apply to the project.
  - `--state_root`: parent of `workspace/`. Absent → `./workspace/...`.

## Input/Output Contract

- **Reads**: the working tree at `--repo_root` — dependency manifests, CI/CD
  config, migration files, backup/DR scripts and docs, runbooks, IaC and
  monitoring config, `SECURITY.md`/ops docs; `workspace/manifest/` output from
  `ray-manifest` if a prior run produced it (for freshness/EOL); this skill's
  `references/*.md`.
- **Writes**:
  - `workspace/findings/<uuid>.json` — one per maintenance/resilience gap
    (standard schema plus steward fields; see `references/findings_contract.md`).
  - `workspace/steward/posture.json` — the per-area posture assessment (evidence).
  - `workspace/steward_report.md` — the human report.
- **Preconditions**: a project tree with some operational surface. A project with
  no ops config yet is itself a finding (no backup, no DR, no monitoring).
- **Idempotency Guarantee**: findings are UUID files (`ray-condenser` semantics);
  reports overwrite in place; re-running re-assesses from scratch.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/maintenance_docket.md` | during assessment | The checklist per area (freshness/EOL, patch cadence, backup+verified restore, migration safety, DR/runbook, secret rotation, observability/alerting), each with the evidence that proves it and the honest limits of what static inspection can conclude |
| `references/findings_contract.md` | before the first finding | The maintenance-finding schema, the four computed fields, the steward-specific fields, the `maintenance_area` enum, and how to score a *risk-over-time* rather than an exploit |

`ray-steward` reasons over the repo and consumes other skills' artifacts; it ships
no engine of its own. Where `ray-manifest` has run, its `ray_sbom_generate` output
gives the freshness/EOL raw material; the MCP `ray_memory_*` tools are available if
the assessment should recall prior operational notes.

## Instructions

### Step 0: Locator Resolution (Block A)

```
LOCATOR RESOLUTION:
0. ROLE: ray-steward reads the working tree and ops config under --repo_root
   (read-only) and consumes prior workspace artifacts. NEVER stop merely because
   a code snapshot is unset.
1. REPO_ROOT = --repo_root if passed, else current directory. Read-only.
2. STATE_ROOT: from --state_root if passed, else ./workspace/...; all output is
   STATE-RELATIVE and NEVER written under REPO_ROOT.
3. Every shell command uses ABSOLUTE paths and sets its own working directory.
```

### Step 1: Assess each area

Work the `references/maintenance_docket.md` checklist for each in-scope area. For
each control, gather the **evidence** the docket names and record the posture:
`ok` / `gap` / `unknown` (evidence absent). Crucially, distinguish *existence*
from *verification* — a backup script existing is `ok` for "backup exists" but
`unknown` for "restore verified" until there is evidence of a successful test
restore. Consume `ray-manifest`'s output for the freshness/EOL area rather than
re-deriving it.

### Step 2: Score risk-over-time

Each gap is scored by how risk **grows if nothing changes** (`references/findings_contract.md`
§2): an EOL runtime and an unverified backup are high because their failure mode
is catastrophic and their probability rises with time, even though neither is an
exploit today. An `unknown` (missing evidence) is reported as such — "no evidence
a restore has ever succeeded" is a legitimate, honest finding, not a pass.

### Step 3: Write findings and report

Write one finding per gap per `references/findings_contract.md`, `code_paths`
anchored at the relevant artifact (the CI config, the migration file, the backup
script, or the area itself when the gap is an absence). Write
`workspace/steward_report.md` organized by area with the posture table; report to
the user the counts (areas assessed / gaps / unknowns) and where the report is.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Dependency **CVEs right now** (point-in-time) | `/ray-manifest` |
| A backup's **encryption/privileges** (does it exist, is it protected) | `/ray-vault` |
| Deployed-architecture **incident-readiness design** | `/ray-citadel` |
| IaC **misconfiguration** of the infra itself | `/ray-terrain` |
| Detecting/responding to a **live incident** | `/ray-warden` |

`ray-steward` owns the over-time posture: freshness trajectory, verified
recoverability, migration safety, and coverage of the controls that keep a system
maintainable and resilient. It leans on `ray-manifest` for the raw dependency
facts and on `ray-vault`/`ray-citadel` for the point-in-time datastore and
architecture posture, then asks the question they don't: will this still hold, and
can we recover when it doesn't?
