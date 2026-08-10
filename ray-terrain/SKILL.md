---
name: ray-terrain
description: >-
  Infrastructure-as-Code and cloud-posture auditor: scans Terraform, CloudFormation, Kubernetes/Helm, Dockerfiles, and compose for concrete misconfigurations — open-to-the-world ingress, wildcard IAM, public storage, unencrypted resources, privileged containers, and secrets in IaC — and (read-only, behind a gate) can check live cloud posture when a CLI is present.
  Use to audit the infrastructure definitions of a system before or alongside a source review, catching the production-security mistakes that live in config rather than code.
  Don't expect it to replace a full policy engine on deep HCL/YAML semantics — it catches high-signal misconfig and drives tfsec/checkov/trivy/kube-score when present; for the deployed-architecture reasoning, use ray-citadel.
---

# Terrain (/ray-terrain)

## System Goal

Infrastructure-as-Code & Cloud-Posture Auditor. A large share of real production
compromises are not code bugs — they are an S3 bucket set to public, a security
group open to `0.0.0.0/0`, an IAM policy that grants `Action: "*"`, a container
running `privileged`, a database marked publicly accessible, a secret pasted into
a Terraform file. `ray-terrain` audits the IaC that provisions the system for
exactly those misconfigurations, at the resource level, with a `file:line` anchor
on every finding.

It is a drop-in sibling of `ray-prospector` for the infrastructure surface: same
finding JSON, same pipeline. It focuses on **static IaC** (no cloud credentials
needed) and can, behind a read-only gate, corroborate against **live cloud
posture** when a provider CLI is available.

**Honesty about depth.** The bundled scanner is a *bounded, high-signal* engine:
it catches the unambiguous, almost-always-wrong patterns with high precision. Full
HCL/YAML graph semantics and cross-resource policy reasoning need a real policy
engine — `ray-terrain` drives `tfsec`/`checkov`/`trivy`/`kube-score` when they are
installed and says plainly when a deeper check requires one that is absent.

## Command Definition

- **Command:**
  `/ray-terrain [--repo_root=<path>] [--mode=<static|live>] [--state_root=<path>]`
- **Description:** Scans IaC sources under the repo for misconfiguration and
  writes one finding per issue; with `--mode=live` and a provider CLI present,
  additionally corroborates read-only against the live account.
- **Arguments (all optional):**
  - `--repo_root`: the working tree to scan. Absent → current directory.
  - `--mode`: `static` (default) — IaC files only, no credentials, nothing sent
    to any cloud; `live` — additionally run **read-only** posture queries against
    the account whose CLI/creds are present (never a change, never a write),
    behind the gate below.
  - `--state_root`: parent of `workspace/`. Absent → `./workspace/...`.

## Input/Output Contract

- **Reads**: IaC sources under `--repo_root` (Terraform `.tf`/`.tf.json`,
  CloudFormation, Kubernetes/Helm YAML, `Dockerfile`, `docker-compose*`); this
  skill's `references/*.md`; an installed policy engine's output when present; and,
  only in `--mode=live`, read-only cloud APIs via the provider CLI.
- **Writes**:
  - `workspace/findings/<uuid>.json` — one per misconfiguration (standard schema
    plus IaC fields; see `references/findings_contract.md`).
  - `workspace/terrain/iac_report.json` — the raw scanner output (evidence).
  - `workspace/terrain_report.md` — the human report.
- **Preconditions**: at least one IaC file. `--mode=live` additionally requires a
  provider CLI **and** a read-only credential; absent either, it stays static and
  says so.
- **Idempotency Guarantee**: findings are UUID files (`ray-condenser` semantics);
  reports overwrite in place; re-running re-scans from scratch.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/iac_docket.md` | during the scan | Per-format parsing, the misconfiguration checklist per provider (AWS/GCP/Azure/K8s), the live-posture read-only gate, and how to drive tfsec/checkov/trivy/kube-score when present |
| `references/findings_contract.md` | before the first finding | The IaC-finding schema, the four computed fields, the IaC-specific fields, the `misconfig_class` enum, and severity defaults |

The engine is the bundled helper `scripts/ray_iac.py` (stdlib-only): a bounded,
high-signal, `file:line` scanner across Terraform/CFN/K8s/Docker/compose. Where the
Ray MCP server is available, it is the `ray_iac_scan` tool (`{"path": "..."}`) — a
real tool call, not a narrated one.

## Instructions

### Step 0: Locator Resolution (Block A) + Live-Mode Gate

```
LOCATOR RESOLUTION:
0. ROLE: ray-terrain reads IaC sources under --repo_root (read-only). NEVER stop
   merely because a code snapshot is unset.
1. REPO_ROOT = --repo_root if passed, else current directory. Read-only.
2. STATE_ROOT: from --state_root if passed, else ./workspace/...; all output is
   STATE-RELATIVE and NEVER written under REPO_ROOT.
3. Every shell command uses ABSOLUTE paths and sets its own working directory.
```

**Live-mode gate** (only if `--mode=live`): live posture is **read-only, always**.
Run only describe/list/get-style queries against the account whose CLI is present;
**never** a create, update, delete, or any state change. If a query would mutate,
it is not run. Absent a provider CLI or a credential, stay static and report that.
There is no write path in `ray-terrain`.

### Step 1: Scan the IaC

Run `scripts/ray_iac.py <REPO_ROOT> --json` (or the `ray_iac_scan` MCP tool).
Inventory installed policy engines (`command -v tfsec checkov trivy kube-score`);
where present, run the richer engine too and normalize its output into the same
finding shape (`references/iac_docket.md`). Record which formats were found and
which deeper checks require an absent tool — a gap is reported, not hidden.

### Step 2: Corroborate live (only in `--mode=live`)

For each high-signal static finding on a resource that maps to a live one, confirm
read-only whether it is actually exposed now (e.g. the bucket really is public,
the security group really allows `0.0.0.0/0`). A static finding confirmed live is
higher confidence; a static finding the live account does not reflect (drift) is
itself worth reporting.

### Step 3: Write findings and report

Write one finding per misconfiguration per `references/findings_contract.md`,
`code_paths` anchored at the exact `file:line`. Merge duplicate reports of the same
resource from the bundled scanner and a policy engine into one finding. A secret
found in IaC is written **redacted** (the finding hands the blast radius to
`ray-turnstile`/`ray-vault`). Write `workspace/terrain_report.md` ranked by
severity; report counts (files scanned / findings by severity) to the user; do
not dump the whole report or any secret into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Deployed-architecture reasoning (layering, statelessness, blast-radius design) | `/ray-citadel` |
| The datastore's own privileges/reachability once provisioned | `/ray-vault` |
| Dependency/supply-chain risk (not infrastructure config) | `/ray-manifest` |
| A committed secret outside IaC (source, history) | `/ray-quarry` |
| Rate-limiting / exposed-endpoint review of a running service | `/ray-sentry` |

`ray-terrain` owns concrete IaC-resource misconfiguration; `ray-citadel` reasons
about the architecture those resources compose. A finding here (a public bucket,
an open SG) is a first-class Ray finding — condensed, scored, reported like any
other — and, when it names a live resource, can seed a `--mode=live` confirmation
or a `ray-siege` test of the thing it exposes.
