---
name: ray-citadel
description: >-
  Audits the deployed architecture for defense in depth at scale: network layering, stateless application design, environment isolation, secret management topology, deploy pipeline integrity, container and Kubernetes hardening, observability, and incident readiness.
  Use when the target ships infrastructure as code, container definitions, or CI/CD pipelines and you need architecture-level findings written to workspace/findings/.
  Don't use for building the threat model (use ray-perimeter), application code defects (use ray-crucible or ray-seam), or datastore-specific hardening (use ray-vault).
---

# Citadel (/ray-citadel)

## System Goal

Defense-in-Depth Architect's Auditor. Reviews the deployed shape of the system —
network layers, environments, secrets, pipeline, runtime, and incident
readiness — against the principle that **no single control should be the only
thing standing between a mistake and a disaster**.

`/ray-perimeter` builds the threat model: who the attackers are and where they
can reach. `/ray-citadel` audits whether the architecture that was actually
committed — the Terraform, the Helm charts, the Dockerfiles, the workflow files
— puts enough independent barriers between those attackers and the assets. It
reads infrastructure the way the other stages read application code, and emits
the same findings.

## Command Definition

- **Command:** `/ray-citadel`
- **Description:** Audits network layering, environment isolation, secret
  topology, deploy pipeline integrity, runtime hardening, and incident
  readiness, writing findings plus a control ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: the `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--scale <small|large>`: which controls are expected. `large` expects the
    full set; `small` marks the scale-only controls (flagged **[scale]** in the
    baseline) `NOT_APPLICABLE` with a stated reason rather than reporting them
    as gaps. Absent → infer from the threat model's availability tiers and
    whether the repository contains multi-instance orchestration, and record the
    inference with its evidence.
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json` (`pass_number`, `active_snapshot`);
  `workspace/kb/THREAT_MODEL.md` (trust boundaries, attacker profiles, and the
  availability tiers that decide `--scale` and severity);
  `workspace/kb/architecture.md` and `workspace/kb/entities/*.md` (optional);
  this skill's `references/*.md`; target artifacts (IaC — Terraform,
  CloudFormation, Pulumi, CDK, Bicep; Kubernetes manifests and Helm charts;
  compose files; Dockerfiles; CI/CD workflows; service meshes; proxy and CDN
  configuration; environment templates; runbooks);
  `workspace/ledgers/ray-citadel.json` from the previous pass, if present.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-citadel.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-citadel_pass_${N}.json` before overwriting.
- **Preconditions**: infrastructure artifacts present in the snapshot. If the
  repository contains no IaC, containers, or pipeline definitions, say so
  plainly: record every control `UNKNOWN` with that reason, write at most one
  finding noting that the architecture is not described in code, and stop. Do
  **not** invent an architecture from the application's shape.
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges). The ledger is archived per pass and then
  deterministically overwritten.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/architecture_baseline.md` | before Step 1, then per area through Step 6 | The reference layered topology and what to check about the arrows between layers; statelessness and scaling; environment isolation with its `PARTIAL` gradations; secret topology; pipeline integrity; container and Kubernetes hardening; observability and incident readiness; and the control-ledger ids, with **[scale]** marking the controls a small deployment does not need |
| `references/findings_contract.md` | before writing the first finding, and again at Step 7 | Findings schema, the four computed fields, this domain's CWE set, evidence discipline, severity defaults, and the ledger format |

The baseline's value is in the **arrows**, not the boxes: which layer may reach
which. Read §1 before drawing any conclusion about network layering.

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

Two skill-specific notes:

- **Never touch live infrastructure.** No `terraform apply`, no `plan` against
  real state, no `kubectl` against a cluster. If a policy linter over the
  committed IaC is available, run it in a private shadow copy per step 4.
- **Forge settings are usually not in the repository.** Branch protection,
  required reviews, and required checks live in the platform's settings. Read
  what IS committed (`CODEOWNERS`, workflow triggers, environment protection
  rules, rulesets-as-code) and record the rest `UNKNOWN`, naming what would
  settle it. Do not assert a repository is unprotected because you cannot see
  the setting.

### Step 1: Reconstruct the Deployed Topology

From the committed artifacts, draw the path a request takes and the path data
takes, and write both into the ledger. For each hop record what it is, where it
is defined, what may reach it, and what it may reach.

Then check the property that makes layering worth anything, per
`architecture_baseline.md` §1: **each layer accepts traffic only from the layer
in front of it.** A private subnet whose security group allows the whole VPC is
one flat network wearing three names.

The single highest-value check in this step is whether the origin is reachable
directly, bypassing the CDN/WAF — because that one gap makes every edge control
optional at once, including the rate limiting `/ray-sentry` scored as present.

### Step 2: Statelessness and Scaling Safety

`architecture_baseline.md` §2: session and file state externalized; security
state (rate-limit counters, nonces, idempotency keys, denylists) in a shared
store rather than instance memory; scheduled work executing once rather than
once per replica; autoscaling bounded with budget alarms; connection draining;
and the polarity of degradation — security decisions must fail closed while
non-security paths may degrade open.

### Step 3: Environment Isolation

`architecture_baseline.md` §3, which grades each control rather than treating it
as binary: separation boundary (separate accounts is `PRESENT`, separate VPCs in
one account is `PARTIAL`), credential crossing, data crossing, network crossing,
production access controls, break-glass, and environment parity.

Parity deserves emphasis: if production was built by hand rather than by the
same IaC, then nothing you verified in this pass is known to be true of it — say
that explicitly in the finding.

### Step 4: Secret Topology

`architecture_baseline.md` §4: a single secret-management authority; no
committed secrets (a Kubernetes `Secret` in the repository is base64, which is
encoding, not encryption — treat it as plaintext); runtime retrieval via
workload identity; OIDC federation from CI instead of long-lived cloud keys;
rotation; per-consumer scope; and the exposure paths teams miss — build args
persisting in image layers, plaintext values in Terraform state, secrets echoed
in CI logs.

### Step 5: Pipeline and Supply-Chain Integrity

The pipeline is a production system with write access to production; audit it
like one. `architecture_baseline.md` §5 covers the gates and — importantly —
whether they can actually fail the build (`|| true`, `continue-on-error: true`),
pipeline privilege, artifact and action pinning, deploy strategy, and runner
isolation.

The finding to hunt for specifically is a workflow that executes untrusted
pull-request code with secrets in scope (`pull_request_target` plus a checkout
of the fork's head). That is a direct repository-compromise path and rates HIGH.

### Step 6: Runtime Hardening and Readiness

`architecture_baseline.md` §6 for containers and Kubernetes: non-root, read-only
root filesystem, no privileged containers or mounted Docker socket, minimal
digest-pinned images, resource limits, and — the one that erases every "private"
boundary inside a cluster when missing — **default-deny network policies**, since
Kubernetes defaults to allow-all between pods.

§7 covers observability and incident readiness: centralized logs with
correlation ids, a protected cloud audit trail, and an incident runbook that
exists *before* it is needed, including the regulatory clocks (`/ray-custodian`
§7: ANPD 3 business days, GDPR 72 hours). It closes with the process controls —
threat modeling on sensitive features, and security invariants tested in CI,
which is what keeps every other finding in this suite from decaying.

### Step 7: Write Findings and the Ledger

Follow `references/findings_contract.md`. Two rules carry this domain: **anchor
every finding at a committed artifact** (the Terraform resource, the manifest,
the Dockerfile line, the workflow step), and **do not audit an architecture you
inferred** — if the topology is not described in the repository, that absence is
the finding, not a list of controls you imagine are missing.

Separate `NOT_APPLICABLE` from `ABSENT` honestly. A single-container side
project does not need a service mesh or blue-green deploys; use `--scale`, state
the reason, and do not manufacture gaps.

### Step 8: Complete

Report findings by severity and layer, controls by state, the reconstructed
topology in a sentence or two, the `--scale` verdict and its evidence, and every
`UNKNOWN` with its blocker. Do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Building the threat model (trust boundaries, attacker profiles, asset tiers) | `/ray-perimeter` |
| Datastore privileges, backups, encryption at rest, datastore reachability | `/ray-vault` |
| Rate-limiting rules, exposed operational endpoints, alerting rules | `/ray-sentry` |
| Application code, validation, error handling | `/ray-seam`, `/ray-crucible` |
| Dependency versions and lockfile hygiene | `/ray-crucible` `DEPS` |
| Security headers and TLS configuration | `/ray-custodian` |

This stage consumes the threat model; it does not rewrite it. The WAF's
existence and placement are here, its rules are `/ray-sentry`'s. Where TLS
terminates is here; what headers it sets is `/ray-custodian`'s.
