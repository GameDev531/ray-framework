# Findings Contract — ray-terrain

How `ray-terrain` writes its findings. It reuses the standard Ray finding schema
and the four computed fields, adds the IaC-specific fields, and stays consistent
with the pipeline so an infrastructure finding is first-class. Read before the
first finding, and again at Step 3.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults for Misconfiguration](#2-severity-defaults-for-misconfiguration)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. IaC-Specific Fields and the misconfig_class Enum](#4-iac-specific-fields-and-the-misconfig_class-enum)
- [5. CWE Set](#5-cwe-set)
- [6. Findings Schema](#6-findings-schema)

______________________________________________________________________

## 1. Evidence Discipline

**Anchor at the `file:line`.** `code_paths[0]` is the exact IaC location
(`infra/main.tf.json:5`) where the misconfiguration lives and where the fix
applies. Every finding is a concrete, located fact — not "the infra looks loose".

**Static vs. live confidence.** A static finding says the *definition* is
misconfigured. If `--mode=live` confirmed the resource is actually exposed now,
raise confidence and record it; if the live account contradicts the IaC, that
**drift** is its own finding. Never assert a resource is live-exposed without a
read-only observation.

**Secrets are redacted.** A hardcoded secret in IaC is recorded with the rule,
the `file:line`, and a redacted evidence line — never the secret value, in the
finding or in chat. The blast radius (what it unlocks) is handed to
`ray-turnstile`/`ray-vault`.

**Deduplicate engine + scanner.** When both the bundled scanner and an installed
policy engine flag the same resource+issue, write **one** finding (prefer the
engine's rule id/reference), not two.

______________________________________________________________________

## 2. Severity Defaults for Misconfiguration

Set an honest discovery-stage severity; `ray-gauge` applies final caps.

| Misconfiguration | Default |
|---|---|
| Public storage of sensitive data; DB publicly accessible with weak/no auth; hardcoded live credential | CRITICAL |
| `0.0.0.0/0` ingress to a sensitive port; IAM `Action:"*"`; privileged container on a shared node | HIGH |
| Wildcard IAM resource; hostNetwork/hostPath; encryption disabled; open ingress to a non-sensitive port | MEDIUM |
| Dockerfile root/`:latest`/ADD-url; missing hardening with no proven exposure | LOW |
| A resource that is intentionally and correctly public (a static website bucket) | not a finding (note in report) |

`attacker_position` is typically `EXTERNAL` for network exposure and public
storage, `IN_CLUSTER`/`HOST_SYSTEM` for container-escape classes. Record what the
misconfiguration actually exposes.

______________________________________________________________________

## 3. The Four Computed Fields

**`cwe`** (optional) — from §5.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`, where
`primary_target` is `code_paths[0]` minus a trailing `:line` (the IaC file), so
the same resource links across runs; if empty, hash `sorted(code_paths)`.

**`lineage_id`** — inherit from an archived finding with the same `signature`;
else a fresh UUIDv4.

**`discovery_commit`** — the repo commit the IaC was scanned at (the definition
state the misconfig was found in).

______________________________________________________________________

## 4. IaC-Specific Fields and the misconfig_class Enum

| Field | Meaning |
|---|---|
| `misconfig_class` | `network_exposure` / `over_privilege` / `public_data` / `no_encryption` / `container_escape` / `root_container` / `secret_exposure` / `supply_chain` / `reproducibility`. |
| `iac_format` | `terraform` / `cloudformation` / `kubernetes` / `dockerfile` / `compose`. |
| `resource` | The resource identity when known (`aws_s3_bucket.data`, `Pod/app`). |
| `rule` | The rule id that fired (bundled scanner id, or the policy engine's). |
| `live_status` | `not_checked` (static only) / `confirmed_exposed` / `drift_iac_stricter` / `drift_live_stricter`. |

______________________________________________________________________

## 5. CWE Set

`CWE-284` (improper access control — open ingress), `CWE-732` (incorrect
permission assignment — wildcard IAM, public ACL), `CWE-1327`/`CWE-1188` (exposed
resource / insecure default — public DB), `CWE-250` (execution with unnecessary
privilege — privileged/root container), `CWE-668` (exposure to wrong sphere —
hostNetwork/hostPath), `CWE-311` (missing encryption), `CWE-798` (hardcoded
credentials), `CWE-494` (download without integrity check — ADD url), `CWE-1104`
(unmaintained/unpinned base image). Omit if none applies.

______________________________________________________________________

## 6. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "S3 bucket aws_s3_bucket.data is public-read",
  "description": "infra/main.tf.json:4 sets acl = \"public-read\" on aws_s3_bucket.data, making the bucket world-readable. Anything stored there is exposed to the internet.",
  "impact": "Any object in the bucket is readable by anyone; if it holds user data, backups, or artifacts, that is a direct data exposure.",
  "severity": "HIGH",
  "privileges_required": "NONE",
  "attacker_position": "EXTERNAL",
  "user_interaction": "NONE",
  "status": "VALID",
  "code_paths": ["infra/main.tf.json:4"],
  "discovery_commit": "abc1234",
  "cwe": "CWE-732",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "Set the bucket ACL to private and grant access via scoped bucket policies or signed URLs; enable the account-level public-access block. Confirm no legitimate consumer relied on public read.",
  "misconfig_class": "public_data",
  "iac_format": "terraform",
  "resource": "aws_s3_bucket.data",
  "rule": "s3-public-acl",
  "live_status": "not_checked",
  "history": [
    {"stage": "terrain-iac", "action": "flagged", "details": "public-read ACL at infra/main.tf.json:4", "timestamp": "<iso8601>"}
  ]
}
```

Use `"status": "VALID"` — a located misconfiguration is a fact. For a
`--mode=live` confirmation, set `live_status: confirmed_exposed` and raise
confidence in the description; for drift, use the matching `drift_*` value and
explain which side is stricter. A `secret_exposure` finding keeps its evidence
**redacted**. The `history` stage is namespaced `terrain-iac` for provenance.
