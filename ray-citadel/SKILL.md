---
name: ray-citadel
description: >-
  Audits the deployed architecture for defense in depth at scale: network layering, stateless application design, environment isolation, secret management topology, deploy pipeline integrity, container and image hardening, observability, and incident readiness.
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
committed — the Terraform, the Helm charts, the Dockerfiles, the workflow
files — puts enough independent barriers between those attackers and the assets.
It reads infrastructure the way the other stages read application code, and it
emits the same findings.

## Command Definition

- **Command:** `/ray-citadel`
- **Description:** Audits network layering, environment isolation, secret
  topology, deploy pipeline integrity, runtime hardening, and incident
  readiness, writing findings plus a control ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--scale <small|large>`: sets which controls are expected. `large` (the
    default when the threat model names `CRITICAL` availability assets or the
    repository contains multi-instance orchestration) expects the full set;
    `small` marks the scale-only controls `NOT_APPLICABLE` with a stated reason
    rather than reporting them as gaps. Absent → infer, and record the inference.
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**:
  - `workspace/.ray_state.json` — `pass_number`, `active_snapshot`. Optional.
  - `workspace/kb/THREAT_MODEL.md` — trust boundaries, attacker profiles, and
    the availability tiers that decide `--scale` and severity.
  - `workspace/kb/architecture.md` and `workspace/kb/entities/*.md` (optional).
  - `ray-citadel/references/architecture_baseline.md` — read before scoring.
  - Target artifacts: IaC (Terraform, CloudFormation, Pulumi, CDK, Bicep),
    Kubernetes manifests and Helm charts, `docker-compose.yml`, Dockerfiles,
    CI/CD workflows, service meshes, proxy and CDN configuration, environment
    templates, runbooks and operational documentation.
  - `workspace/ledgers/ray-citadel.json` from the previous pass, if present.
- **Writes**:
  - `workspace/findings/<uuid>.json` — standard Ray findings schema.
  - `workspace/ledgers/ray-citadel.json` — the architecture ledger for this pass.
  - `workspace/archive/ledgers/ray-citadel_pass_${N}.json` — copy of the
    previous ledger before overwrite.
- **Preconditions**:
  - Infrastructure artifacts must be present in the snapshot. If the repository
    contains no IaC, containers, or pipeline definitions, say so plainly: record
    every control as `UNKNOWN` with that reason, write at most one finding
    noting that the architecture is not described in code, and stop. Do not
    invent an architecture from the application's shape.
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

Skill-specific notes:

- Branch protection, required reviews, and required checks live in the forge's
  settings, not usually in the repository. Read what IS committed
  (`CODEOWNERS`, workflow `on:` triggers, environment protection rules,
  rulesets-as-code) and record the rest as `UNKNOWN` naming what would settle
  it. Do not assert a repository is unprotected because you cannot see the
  setting.
- Never run `terraform apply`, `plan` against real state, `kubectl` against a
  cluster, or any command that touches live infrastructure. If a static analysis
  tool is available (a policy linter over the committed IaC), run it in a
  private shadow copy per Block A step 4.

### Step 1: Reconstruct The Deployed Topology

From the committed artifacts, draw the actual path a request takes and the
actual path data takes, and write both into the ledger. The reference baseline
is:

```
Internet
  → CDN / WAF: TLS termination, DDoS absorption, coarse rate limiting, caching
  → Load balancer (public subnet)
  → Application (private subnet, stateless, multiple instances)
  → Cache (private) and queues (private) for asynchronous work
  → Database (private subnet, no route to the internet) + read replicas
```

For each hop record: what it is, where it is defined, what may reach it, and
what it may reach. Then check the property that makes layering worth anything:
**each layer accepts traffic only from the layer in front of it**. A private
subnet whose security group allows the whole VPC is one flat network wearing
three names.

Look specifically for:

- An origin reachable directly, bypassing the CDN/WAF (a public load balancer
  address or an origin hostname with no restriction to the CDN's ranges or a
  shared secret header). This one defeats every edge control at once.
- Application instances with public IPs.
- A NAT-less private subnet that someone "fixed" by making it public.
- Management ports (SSH/RDP) open to the world instead of via a session manager.
- A service mesh or ingress that terminates TLS and then speaks plaintext across
  a shared network.

### Step 2: Statelessness and Scaling Safety

1. **Session state**: in a signed cookie or a shared store, not in instance
   memory. Local session state forces sticky sessions, and misconfigured
   affinity is a classic source of one user seeing another's data.
2. **File state**: uploads and generated artifacts in object storage, not on the
   instance filesystem.
3. **Scheduled work**: a job that must run once actually runs once (a leader
   election, a distributed lock, or a scheduler outside the fleet) rather than
   once per replica.
4. **In-memory security state**: rate-limit counters, nonce caches,
   idempotency keys, and denylists held per instance are ineffective at more
   than one replica and are wiped by every deploy. Cross-reference
   `/ray-sentry` `RATE-04`.
5. **Autoscaling with a ceiling**, plus budget alarms — an abuse spike must not
   scale into an unbounded bill. Note where the scaling policy has no maximum.
6. **Graceful degradation**: what happens when a dependency is down — does the
   system fail closed on security decisions and open on non-security ones, or
   the reverse? The reverse is an A10:2025 defect (`/ray-seam` `ERR-03`).

### Step 3: Environment Isolation

1. **Separation strength**: separate cloud accounts or projects per environment
   is the expectation at scale; separate namespaces or tag-based separation in
   one account is `PARTIAL` (a single IAM mistake crosses it).
2. **No credential crossing**: staging must not hold production credentials, and
   no role in a lower environment should be assumable into production.
3. **No data crossing**: staging with production data is a production-severity
   exposure at staging-grade protection (`/ray-vault` `NPD-04`).
4. **Network separation**: no VPC peering or shared subnets that let a
   compromised dev workload reach production services.
5. **Production access**: a small named set of people, MFA and SSO required,
   time-boxed elevation, with an audit trail. Look for evidence in IaC (IAM
   policies, SSO group mappings, break-glass roles) and in runbooks.
6. **Consistency**: the same IaC producing every environment, so a control
   verified in staging is the control running in production. Hand-built
   production is a finding, because nothing you audit here is then true of it.

### Step 4: Secret Management Topology

1. **One authority**: a secret manager (Vault, Secrets Manager, Parameter Store,
   Doppler, sealed secrets), not a mix of environment files, CI variables, and
   Kubernetes `Secret` objects committed as YAML — Kubernetes `Secret` values
   are base64, not encrypted, so a committed one is a plaintext leak.
2. **Runtime retrieval via workload identity** (instance profile, IRSA, pod
   identity, workload identity federation) rather than a static key that must
   itself be distributed.
3. **CI/CD federation**: OIDC from the CI provider to the cloud, rather than
   long-lived access keys stored in CI secrets.
4. **Rotation**: automated where the provider supports it; otherwise documented
   and exercised.
5. **Scope**: one secret per consumer, so revocation is surgical.
6. **Exposure paths**: secrets in build args (they persist in image layers), in
   `docker history`, in Terraform state (state files hold plaintext values —
   check that state is in an encrypted, access-controlled backend and not
   committed), in CI logs, or in error messages.
7. **Encryption at rest for state and manifests**: encrypted Terraform backend,
   SOPS/sealed-secrets for anything committed.

### Step 5: Pipeline and Supply-Chain Integrity

1. **Gates before deploy**: lint, tests, dependency audit
   (`npm audit`/`pip-audit`/`govulncheck`), secret scan (gitleaks), and image
   scan (Trivy or equivalent). Record which exist; a pipeline with no security
   gate is a finding, and gates that run but never fail the build (`|| true`,
   `continue-on-error: true`) are `PARTIAL` — check for exactly that.
2. **Branch protection and review**: no direct pushes to the default branch,
   required review, `CODEOWNERS` covering security-relevant paths (IaC, auth,
   CI). Where the setting is not visible, `UNKNOWN` with the reason.
3. **IaC changes reviewed as code**: a security-group change must go through the
   same review as application code. A pipeline that applies infrastructure
   without review, or a role that lets any workflow apply, is a finding.
4. **Pipeline privilege**: the deploy role's permissions. A CI role with
   administrator rights means every workflow — including one added by a
   contributor in a pull request — is a path to full control.
5. **Untrusted-input triggers**: workflows that run on `pull_request_target`,
   or that check out and execute code from a fork with secrets available. This
   is a direct repository-compromise path; treat it as HIGH.
6. **Third-party actions and images pinned** by digest, not by a mutable tag,
   and sourced from trusted publishers.
7. **Artifact integrity**: immutable, versioned images; no `latest` in
   production; signing/attestation (Sigstore, provenance) where available.
8. **Deploy strategy**: canary or blue-green with automatic rollback, so a bad
   change — including a security regression — has a bounded blast radius.
9. **Self-hosted runners**: shared runners executing untrusted pull-request code
   are a persistent compromise vector; check isolation and ephemerality.

### Step 6: Runtime and Container Hardening

1. **Non-root user** in the Dockerfile (`USER`), and `runAsNonRoot` /
   `runAsUser` in the pod security context.
2. **Read-only root filesystem** where feasible, with explicit writable mounts.
3. **No privileged containers**, no unnecessary capabilities, `no-new-privileges`
   set, no `hostNetwork`/`hostPID`/`hostIPC`, no Docker socket mounted into a
   container (that is host root by another name).
4. **Minimal base images** (distroless/alpine/slim), pinned by digest, rebuilt
   on a schedule so patched bases actually ship.
5. **Resource limits** on every workload — an unbounded container is a
   noisy-neighbour and denial-of-service surface.
6. **Kubernetes specifics**: default-deny `NetworkPolicy` (the default is
   allow-all between pods, which erases every "private" boundary inside the
   cluster), least-privilege `ServiceAccount` (and `automountServiceAccountToken:
   false` where the workload does not call the API), Pod Security Standards, and
   admission control.
7. **Host access**: SSH via a session manager rather than open ports and shared
   keys; instance metadata protected (IMDSv2 required, hop limit set) so an SSRF
   cannot mint credentials.

### Step 7: Observability and Incident Readiness

1. **Centralized logs with correlation ids**, metrics (latency, error rate,
   saturation, 401/403 rates), and tracing across services. Detailed alerting
   coverage is `/ray-sentry`'s; the architectural property here is that the
   telemetry leaves the host and is queryable during an incident.
2. **Cloud audit trail** enabled and protected (CloudTrail/Cloud Audit Logs/
   Activity Log), delivered to an account the workload cannot write to.
3. **Incident runbook**, present before it is needed: who is paged, how to
   revoke credentials and rotate keys, how to isolate a compromised workload,
   how to restore from backup, and how to communicate — including the regulatory
   clocks (`/ray-custodian` §7: ANPD 3 business days, GDPR 72 hours).
4. **Recovery objectives**: stated RTO/RPO and a restore procedure that has been
   exercised (`/ray-vault` `BKP-07`).
5. **Threat modeling in the process**: evidence that security review happens for
   sensitive features (a template, a checklist, a `CODEOWNERS` entry for
   security-relevant paths). Absence is a LOW process finding with high leverage.
6. **Dependency update mechanism** configured and actually merging
   (Dependabot/Renovate present but with a year of open pull requests is
   `PARTIAL`).

### Step 8: Evidence Discipline

- **Anchor every finding at a committed artifact**: the Terraform resource, the
  manifest, the Dockerfile line, the workflow step. An architecture finding with
  no anchor cannot be validated, and `/ray-magistrate` will dismiss it.
- **Do not audit an architecture you inferred.** If the topology is not
  described in the repository, that is the finding — not a list of controls you
  imagine are missing.
- **Separate `NOT_APPLICABLE` from `ABSENT` honestly.** A single-container
  side project does not need a service mesh or blue-green deploys. Use
  `--scale`, state the reason, and do not manufacture gaps.
- **Respect `ray-gauge`'s calibration.** Internal-only exposure is capped by the
  `internal_nested` rule, and a supply-chain prerequisite is capped by
  `supply_chain_prerequisites`. Score honestly rather than pre-inflating.
- **Severity defaults**: origin reachable bypassing the WAF HIGH; production
  credentials present in a lower environment HIGH; CI workflow executing
  untrusted pull-request code with secrets HIGH; database or management port
  open to the internet HIGH (report and cross-reference `/ray-vault`);
  privileged container or mounted Docker socket HIGH; secrets in image layers or
  in committed Terraform state HIGH; no default-deny `NetworkPolicy` MEDIUM;
  containers as root MEDIUM; mutable image tags in production MEDIUM; no
  security gates in CI MEDIUM; no incident runbook LOW–MEDIUM.

### Step 9: Compile and Write Findings

Create `workspace/findings/` if missing; one JSON object per file at
`workspace/findings/<uuid>.json`.

Compute before writing:

1. **`cwe`** — `CWE-1188` (insecure default), `CWE-16` (configuration),
   `CWE-284` (improper access control), `CWE-269` (improper privilege
   management), `CWE-250` (unnecessary privileges), `CWE-798` (hardcoded
   credentials), `CWE-522` (insufficiently protected credentials), `CWE-494`
   (download of code without integrity check), `CWE-829` (inclusion of
   functionality from an untrusted control sphere), `CWE-1104` (use of
   unmaintained third-party components), `CWE-770` (allocation without limits),
   `CWE-778` (insufficient logging). Omit when none applies.
2. **`signature`** — first 16 hex chars of
   `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)` with the
   suite's normalization rule (title lowercased and stripped to `[a-zA-Z0-9]`;
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
  "title": "Application load balancer accepts traffic directly, bypassing the CDN and WAF",
  "description": "The topology as committed, which layer is missing or porous, the artifact that establishes it, and which other controls silently depend on the missing one.",
  "impact": "Concrete outcome (e.g., every edge rate limit and WAF rule is bypassable by addressing the origin; a leaked CI credential can apply arbitrary infrastructure changes).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["infra/alb.tf:31", "infra/cloudfront.tf:12"],
  "discovery_commit": "snapshot id verbatim; omit entirely in DEGRADED mode.",
  "cwe": "CWE-1188 (optional)",
  "signature": "First 16 hex chars of the sha256 defined above.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The corrective change in the same artifact, plus the guardrail that keeps it (an IaC policy test, a required check, a conftest/OPA rule).",
  "architecture_layer": "Optional: EDGE | NETWORK | RUNTIME | ENVIRONMENT | SECRETS | PIPELINE | OBSERVABILITY | PROCESS.",
  "history": [
    {
      "stage": "citadel",
      "action": "created",
      "details": "Architecture defense-in-depth finding recorded.",
      "pass_number": 1,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

### Step 10: Write the Architecture Ledger

1. Resolve `N` from `pass_number`, else `max` archive pass + 1, else `1`.
2. Copy any existing `workspace/ledgers/ray-citadel.json` to
   `workspace/archive/ledgers/ray-citadel_pass_${N}.json` (`mkdir -p` first).
3. Write `workspace/ledgers/ray-citadel.json` with `skill`, `pass_number`,
   `snapshot_id`, `generated_at`, `scale` (with `source: "argument" | "inferred"`
   and its evidence), a `topology` array (each hop with `layer`, `defined_at`,
   `reachable_from`, `may_reach`), and a `controls` array of
   `{id, control, state, evidence, finding_ids, note}` where `state` is
   `PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN`. Use the control ids
   from `references/architecture_baseline.md` §8; each appears exactly once.

### Step 11: Complete

Report: findings by severity and layer, controls by state, the reconstructed
topology in one or two sentences, the `--scale` verdict and why, and every
`UNKNOWN` with its blocker. Do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

- **Building the threat model itself (trust boundaries, attacker profiles,
  asset tiers)** → `/ray-perimeter`. This stage consumes that model; it does not
  rewrite it.
- **Database privileges, network reachability of the datastore specifically,
  backups, encryption at rest** → `/ray-vault`. Report the datastore's exposure
  there; report the network layering that should have prevented it here.
- **Rate limiting, exposed operational endpoints, alerting rules** →
  `/ray-sentry`. The WAF's existence and placement are here; its rules are
  there.
- **Application code, validation, error handling** → `/ray-seam`,
  `/ray-crucible`.
- **Dependency versions and lockfile hygiene** → `/ray-crucible` `DEPS`.
  Pipeline gates that would catch them are here.
- **TLS termination configuration and security headers** → `/ray-custodian`.
  Where TLS terminates and what happens after it is here.
