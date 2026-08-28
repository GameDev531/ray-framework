# IaC Docket — Formats, Checks, Live Posture, and Tool-Driving

The technique reference for `ray-terrain`. Read the section for the format or check
you are running. Every check has a bundled dependency-free path
(`scripts/ray_iac.py`) and an optional richer path via an installed policy engine;
inventory tools first (`command -v tfsec checkov trivy kube-score`), prefer the
richer path when present, and never skip a class for want of a tool — but be
honest that the bundled scanner is high-signal and bounded, not a full engine.

## Table of Contents

- [1. Formats & How They're Parsed](#1-formats--how-theyre-parsed)
- [2. The Misconfiguration Checklist](#2-the-misconfiguration-checklist)
- [3. Live Cloud Posture (read-only, gated)](#3-live-cloud-posture-read-only-gated)
- [4. Driving Policy Engines](#4-driving-policy-engines)
- [5. Container Image Hardening & Scanning](#5-container-image-hardening--scanning)

______________________________________________________________________

## 1. Formats & How They're Parsed

| Format | Files | Parsing |
|---|---|---|
| Terraform | `*.tf` (HCL), `*.tf.json` (JSON) | `.tf.json` is structural; raw HCL is line-scanned for high-signal patterns (deep HCL graph needs tfsec/checkov). |
| CloudFormation | `*.json`/`*.yaml` with `Resources:`/`AWSTemplateFormatVersion` | JSON structural; YAML line-scanned. |
| Kubernetes / Helm | `*.yaml`/`*.yml` with `apiVersion:`+`kind:` | Line-scanned (no stdlib YAML); JSON manifests structural. |
| Docker | `Dockerfile`, `*.dockerfile` | Line rules (USER, FROM tag, ADD-url) + a whole-file "never sets USER" check. |
| Compose | `docker-compose*`, `compose*` | Line-scanned. |

The scanner gates non-obvious files: a `.yaml`/`.json` is only treated as IaC if
it structurally looks like it (an IaC marker), so unrelated config is not flagged.
Detection is **line-oriented**, so every finding carries a `file:line` the fix
applies at. Keys may be quoted (`"privileged": true`) or bare (`privileged: true`)
— both match. Values that are variable references (`var.`, `${…}`, `!Ref`,
`secretKeyRef`, `valueFrom`) are **not** treated as hardcoded secrets.

______________________________________________________________________

## 2. The Misconfiguration Checklist

The high-signal classes the bundled scanner flags, and what each maps to:

| Rule | Class / CWE | Why it's almost always wrong |
|---|---|---|
| `0.0.0.0/0` (and `::/0`) ingress | network-exposure / CWE-284 | Opens the resource to the entire internet; scope the CIDR. |
| IAM `Action: "*"` | over-privilege / CWE-732 | Grants every action; grant only what's needed. |
| IAM `Resource: "*"` | over-privilege / CWE-732 | Applies to every resource; scope to ARNs. |
| Storage `acl: public-read[-write]` | public-data / CWE-732 | Bucket world-readable/writable; make private. |
| `publicly_accessible: true` (DB) | network-exposure / CWE-1327 | Database reachable from the internet; use a private subnet. |
| `privileged: true` (container) | container-escape / CWE-250 | Full host access; drop it, add only needed caps. |
| `allowPrivilegeEscalation: true` | container-escape / CWE-250 | Lets a process gain more privilege; set false. |
| `hostNetwork: true` / `hostPath:` | isolation-break / CWE-668 | Shares host namespaces/filesystem; avoid. |
| `encrypted: false` | no-encryption / CWE-311 | Encryption at rest disabled; enable it. |
| `runAsNonRoot: false` | root-container / CWE-250 | Container runs as root; run as non-root. |
| Hardcoded secret in IaC | secret-exposure / CWE-798 | Credential in source; move to a secret manager (recorded **redacted**). |
| Dockerfile `USER root` / no USER | root-container / CWE-250 | Image runs as root by default. |
| Dockerfile `FROM …:latest` | reproducibility / CWE-1104 | Non-reproducible base; pin a digest/version. |
| Dockerfile `ADD https://…` | supply-chain / CWE-494 | Fetches unverified content; use COPY of a verified artifact. |

Richer engines add many more (cross-resource policy, provider-specific
benchmarks) — see §4. When a deeper class matters and no engine is installed, say
so; do not imply the bundled scan was exhaustive.

______________________________________________________________________

## 3. Live Cloud Posture (read-only, gated)

Only in `--mode=live`, and only **read-only**. The rule is absolute: run only
describe/list/get queries; never a create/update/delete or any state change. Use
the provider CLI that is present:
- **AWS**: `aws s3api get-bucket-acl`, `get-public-access-block`,
  `ec2 describe-security-groups`, `iam get-account-authorization-details`,
  `rds describe-db-instances` (check `PubliclyAccessible`).
- **GCP**: `gcloud storage buckets describe`, `compute firewall-rules list`,
  `projects get-iam-policy`.
- **Azure**: `az storage account show`, `network nsg rule list`, `role assignment list`.

Use live posture to **corroborate** a static finding (the bucket really is public
now → higher confidence) or to surface **drift** (IaC says private, live is public,
or vice versa — itself a finding). If a query would mutate anything, it is out of
scope: `ray-terrain` has no write path.

______________________________________________________________________

## 4. Driving Policy Engines

When installed, run and normalize into the same finding shape
(`{file, line, rule, severity, message}`):
- `tfsec <dir> --format json` / `trivy config <dir> --format json` — Terraform +
  broad IaC, rich rule sets.
- `checkov -d <dir> -o json` — multi-format (TF/CFN/K8s/Docker/Helm), large policy
  library.
- `kube-score score <manifests>` / `trivy k8s` — Kubernetes-specific.
Merge an engine's finding and the bundled scanner's finding for the **same
resource+issue** into one (dedupe by `file:line`+rule intent) so the report isn't
doubled. Prefer the engine's rule id and reference when both fire; keep the
bundled scanner as the always-available floor.

______________________________________________________________________

## 5. Container Image Hardening & Scanning

§2 checks the Dockerfile *as text* (the bundled scanner's `docker-*` rules —
`USER root`, `:latest`, `ADD <url>`). This section covers the **built image** as a
supply-chain artifact: its base, its layers, and its known CVEs. (Compiled with
the Apache-2.0 DevSecOps corpus in `CREDITS.md`.)

**The Dockerfile / image hardening checklist:**

| Check | Failing shape |
|---|---|
| Minimal base | A full `ubuntu`/`node` image where `-slim`, `distroless`, or `alpine` would do — every extra package is attack surface |
| Base pinned to a digest | `FROM node:20` (mutable tag) instead of `FROM node:20-slim@sha256:…` — an unpinned base is a silent supply-chain change |
| Non-root runtime | No `USER` directive (runs as root), or a root `ENTRYPOINT`; add a dedicated non-root user (also §2 `docker-no-user`) |
| No secrets in layers | A build `ARG`/`ENV`/`COPY` that bakes a token/key into a layer — it persists in image history even if later `RM`'d. Use BuildKit `--secret` mounts, never `ARG SECRET` |
| Drop capabilities / no privileged | K8s `securityContext` running privileged or with default caps — drop all, add only what's needed (crosses into §2 K8s checks) |
| Read-only root filesystem | Writable container FS where `readOnlyRootFilesystem: true` + a tmpfs would do |
| Multi-stage build | Build tools (compilers, `git`, package caches) shipped in the final image — split build and runtime stages so the runtime image carries only the artifact |
| `.dockerignore` present | No `.dockerignore`, so `.env`, `.git`, and local secrets get `COPY . .`'d into the image (cross-reference `ray-cloak`) |

**Driving the image scanner (when installed):**

- `trivy image <image:tag> --format json` — OS-package and language-dependency
  CVEs in the built image, plus secret and misconfig detection in layers.
- `grype <image>` / `docker scout cves <image>` — equivalent CVE surfaces.
- `dockle <image>` / `trivy image --scanners misconfig` — CIS-style image
  best-practice linting.

Normalize into the same finding shape and severity as §4. **Reachability still
decides** (as in `ray-manifest`): a CVE in an OS package the app never invokes is
lower than one on the runtime's hot path — trace it or say you did not. Image CVEs
are `ray-manifest`'s SCA discipline applied to the container layer; cross-reference
rather than double-count when both a lockfile and its image are scanned.
