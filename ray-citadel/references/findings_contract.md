# Findings Contract — ray-citadel

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

**Anchor every finding at a committed artifact** — the Terraform resource, the
Kubernetes manifest, the Dockerfile line, the workflow step. An architecture
finding with no anchor cannot be validated, and `/ray-magistrate` will dismiss
it as unverifiable.

**Do not audit an architecture you inferred.** If the topology is not described
in the repository, *that* is the finding — one finding, saying the architecture
is not captured in code. A list of controls you imagine are missing from an
infrastructure you never saw is noise, and it is confidently wrong noise, which
is worse.

**Separate `NOT_APPLICABLE` from `ABSENT` honestly.** A single-container side
project does not need a service mesh, blue-green deploys, or a default-deny
network policy. That is what `--scale` is for. Manufacturing gaps to fill a
report is the fastest way to make a security review ignorable.

**Never touch live infrastructure.** No `terraform apply`, no `plan` against
real state, no `kubectl` against a cluster, no cloud API calls. Everything is
read from the committed artifacts.

**Forge settings are usually invisible.** Branch protection, required reviews,
and required status checks live in the platform's settings, not the repository.
Read what is committed — `CODEOWNERS`, workflow triggers, environment protection
rules, rulesets-as-code — and record the rest `UNKNOWN` with what would settle
it. Asserting that a repository is unprotected because you cannot see the
setting is a false positive that damages trust in the whole pass.

**Say which other controls depend on the missing one.** This is the stage where
that matters most: an origin reachable past the CDN does not just weaken one
control, it silently voids every edge rate limit `/ray-sentry` recorded as
`PRESENT`. Naming that dependency is often the most useful sentence in the
finding.

**Respect the calibration you know is coming.** `ray-gauge`'s `internal_nested`
rule caps purely internal exposure, and `supply_chain_prerequisites` caps
findings that require a build-position foothold. Score honestly; pre-inflating
does not survive.

**Status.** Default `PROVISIONALLY_VALID`; `NEEDS_RESEARCH` where the control
lives outside the snapshot.

______________________________________________________________________

## 2. Severity Defaults

| Situation | Default |
|---|---|
| Origin reachable directly, bypassing the CDN/WAF | HIGH |
| Database or management port open to the internet | HIGH (cross-reference `/ray-vault`) |
| Production credentials present in a lower environment | HIGH |
| CI workflow executing untrusted pull-request code with secrets in scope | HIGH |
| Privileged container, mounted Docker socket, or host namespaces | HIGH |
| Secrets in image layers, build args, or committed Terraform state | HIGH |
| CI deploy role with administrator rights | MEDIUM–HIGH |
| IMDSv2 not required (an SSRF mints cloud credentials) | MEDIUM–HIGH |
| No default-deny `NetworkPolicy` in a multi-tenant or multi-service cluster | MEDIUM |
| Containers running as root | MEDIUM |
| Mutable image tags (`latest`) in production | MEDIUM |
| No security gates in CI, or gates that cannot fail the build | MEDIUM |
| Production built by hand rather than by the same IaC | MEDIUM |
| Unbounded autoscaling with no budget alarm | MEDIUM |
| No incident runbook | LOW–MEDIUM |
| No post-incident review process | LOW |

Reserve CRITICAL for a described, unauthenticated path to full environment
compromise.

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

Order `code_paths` with the **deciding artifact first**, then the artifacts that
corroborate it, and keep that order stable across passes. Compute once at
creation; never recompute.

IaC files are renamed and reorganized more often than source files, so the
basename-rename fallback in `ray-prospector/SKILL.md` Step 5a earns its keep
here — apply it so a `main.tf` split into `network.tf` does not orphan every
lineage.

**`lineage_id`** — inherit from an archived finding with the same `signature`
under `workspace/archive/findings_pass_*/` or
`workspace/archive/loop*_findings/` (highest pass wins); otherwise a fresh
UUIDv4. STATE-RELATIVE paths.

**`discovery_commit`** — `active_snapshot.snapshot_id` verbatim when pinned;
**omit the key entirely** in DEGRADED mode.

______________________________________________________________________

## 4. CWE Set For This Domain

| CWE | Use for |
|---|---|
| `CWE-1188` | Insecure default initialization of a resource |
| `CWE-16` | Configuration weakness (general) |
| `CWE-284` | Improper access control (network and IAM) |
| `CWE-269` | Improper privilege management (over-privileged deploy role) |
| `CWE-250` | Execution with unnecessary privileges (root containers) |
| `CWE-798` | Use of hard-coded credentials |
| `CWE-522` | Insufficiently protected credentials (secrets in state or layers) |
| `CWE-494` | Download of code without an integrity check (unpinned actions/images) |
| `CWE-829` | Inclusion of functionality from an untrusted control sphere |
| `CWE-1104` | Use of unmaintained third-party components |
| `CWE-770` | Allocation of resources without limits (unbounded autoscaling) |
| `CWE-778` | Insufficient logging (no cloud audit trail) |
| `CWE-668` | Exposure of a resource to the wrong sphere |
| `CWE-923` | Improper restriction of communication to an intended endpoint |
| `CWE-693` | Protection mechanism failure (WAF bypass) |

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

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
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-693",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The corrective change in the same artifact, plus the guardrail that keeps it: an IaC policy test, a required check, a conftest/OPA rule.",
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

The guardrail half of `mitigation` is the point of this stage. Infrastructure
drifts back: a security group widened during an incident, a `latest` tag
reintroduced by a hotfix, a policy relaxed for a migration. A policy test in the
pipeline is what makes an architecture finding stay fixed, and naming it is what
turns a one-time correction into a durable control.

______________________________________________________________________

## 6. Control Ledger

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`; if missing or
   invalid, use `max` of the `findings_pass_N` / `loopN_findings` folders in
   `workspace/archive/` + 1, defaulting to `1`.
2. If `workspace/ledgers/ray-citadel.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-citadel_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-citadel.json`.

```json
{
  "skill": "ray-citadel",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "generated_at": "<iso8601>",
  "scale": {
    "value": "large",
    "source": "inferred",
    "evidence": ["k8s/deployment.yaml:12 (replicas: 6)", "THREAT_MODEL.md: CRITICAL availability tier"]
  },
  "topology": [
    {
      "layer": "EDGE",
      "component": "CloudFront distribution",
      "defined_at": "infra/cloudfront.tf:12",
      "reachable_from": ["internet"],
      "may_reach": ["alb"]
    },
    {
      "layer": "NETWORK",
      "component": "Application load balancer",
      "defined_at": "infra/alb.tf:31",
      "reachable_from": ["internet", "cloudfront"],
      "may_reach": ["app-asg"]
    }
  ],
  "controls": [
    {
      "id": "TOPO-01",
      "control": "All public traffic transits the CDN/WAF; origin not directly addressable",
      "state": "PRESENT | PARTIAL | ABSENT | NOT_APPLICABLE | UNKNOWN",
      "evidence": "infra/alb.tf:31",
      "finding_ids": [],
      "note": "ALB security group allows 0.0.0.0/0 on 443, not only CloudFront ranges."
    }
  ]
}
```

Every control id from `architecture_baseline.md` §8 appears exactly once. The
`topology` array is worth filling properly even when nothing is wrong: it is the
only machine-readable record of what the deployed shape was at this snapshot,
and the next pass diffs against it.

`reachable_from` is the field that carries the real finding. Two components can
have identical definitions and completely different exposure depending on who
may reach them — record it from the security groups and ingress rules, not from
the component's name or subnet label.
