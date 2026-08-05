# Architecture Baseline — Layers, Environments, Pipeline, Runtime

The reference architecture `/ray-citadel` scores a committed infrastructure
against, plus the failing shapes that keep appearing in real repositories and
the artifacts where each control is actually decided.

Scale matters. Controls marked **[scale]** are expected when the threat model
names `CRITICAL` or `STANDARD` availability assets, or the repository contains
multi-instance orchestration; on a small deployment they are recorded
`NOT_APPLICABLE` with a stated reason, not reported as gaps.

## Table of Contents

- [1. The Layered Topology](#1-the-layered-topology)
- [2. Statelessness and Scaling](#2-statelessness-and-scaling)
- [3. Environment Isolation](#3-environment-isolation)
- [4. Secret Topology](#4-secret-topology)
- [5. Pipeline Integrity](#5-pipeline-integrity)
- [6. Runtime Hardening](#6-runtime-hardening)
- [7. Observability and Incident Readiness](#7-observability-and-incident-readiness)
- [8. Control Ledger IDs](#8-control-ledger-ids)

______________________________________________________________________

## 1. The Layered Topology

```
Internet
  → CDN / WAF            TLS termination, DDoS absorption, coarse rate limiting, cache
  → Load balancer        public subnet, terminates or passes through TLS
  → Application          private subnet, stateless, N instances
  → Cache / queues       private subnet, reachable only from the application
  → Database (+replicas) private subnet, no route to the internet
```

The value of the diagram is not the boxes; it is the **arrows**. Each layer
accepts traffic only from the layer in front of it. Audit the arrows.

| Control | Expected | Failing shape | Where it is decided |
|---|---|---|---|
| Edge in front of everything **[scale]** | All public traffic transits the CDN/WAF | Origin directly addressable: a public ALB DNS name, an origin hostname with no restriction to the CDN's IP ranges or a shared secret header. Every edge control becomes optional | `aws_lb`, `cloudfront_distribution`, ingress annotations, DNS records |
| Application not public | Private subnet, no public IP | `associate_public_ip_address = true`, `map_public_ip_on_launch`, a `LoadBalancer` service per pod | Subnet and instance/service definitions |
| Datastore not public | Private subnet, no internet route | `publicly_accessible = true`, a database in a public subnet (also `/ray-vault` `NET-01`) | Database resources, route tables |
| Adjacent-layer-only rules | Security groups referencing the previous layer's group | `cidr_blocks = ["0.0.0.0/0"]` on an application or database port; a rule allowing the whole VPC CIDR | Security groups, NACLs, firewall rules |
| Egress control **[scale]** | Egress restricted; outbound through NAT with an allowlist where feasible | Unrestricted egress everywhere, which turns any SSRF or implant into a working exfiltration channel | Egress rules, NAT configuration |
| Management access | Session manager / bastion, no standing open ports | SSH or RDP open to `0.0.0.0/0`; a shared key committed | Security groups, key resources |
| Internal TLS **[scale]** | Encrypted between layers, or an explicitly justified boundary | TLS terminated at the edge and plaintext across a shared network to the application | Listener and target-group configuration, mesh policies |
| Instance metadata | IMDSv2 required, hop limit 1 | `http_tokens = "optional"` — an SSRF then mints cloud credentials with one GET (cross-reference `/ray-crucible` `SSRF`) | `metadata_options` blocks |
| DNS hygiene | No delegations to decommissioned services | Dangling CNAMEs (also `/ray-custodian` `EGRESS-05`) | Zone files, DNS resources |

______________________________________________________________________

## 2. Statelessness and Scaling

| Control | Expected | Failing shape |
|---|---|---|
| Session state | Signed cookie or a shared store (Redis) | In-process sessions forcing sticky sessions; misconfigured affinity has repeatedly served one user's response to another |
| File state | Object storage | Uploads on the instance filesystem: lost on scale-in, and inconsistent between replicas |
| Security state | Shared store for rate-limit counters, nonces, idempotency keys, denylists | Per-instance memory: the limit multiplies by replica count and resets on every deploy (`/ray-sentry` `RATE-04`) |
| Scheduled work | Single execution via leader election, a distributed lock, or an external scheduler | A cron inside every replica, so a nightly job runs N times — occasionally N charges, N emails, N deletions |
| Autoscaling **[scale]** | Bounded maximum plus a budget alarm | No ceiling: an abuse spike becomes an unbounded bill (an availability and financial incident, and the reason cost controls belong in a security review) |
| Deployment concurrency | Rolling with a surge limit; connection draining | Full-fleet replacement with no draining, dropping in-flight requests |
| Graceful degradation | Security decisions fail closed; non-security paths degrade open | An authorization service timeout that defaults to allow (`/ray-seam` `ERR-03`) |
| Backpressure **[scale]** | Queues bounded, consumers rate-limited, dead-letter queues configured | Unbounded queues turning a spike into an outage and a data-loss event |

______________________________________________________________________

## 3. Environment Isolation

| Control | Expected | `PARTIAL` | Failing shape |
|---|---|---|---|
| Separation boundary | Separate cloud accounts/projects per environment | Separate VPCs in one account | Everything in one account separated by name prefixes |
| Credential crossing | None; no lower-environment role assumable into production | Shared read-only credentials | Production credentials present in staging or in developer `.env` files |
| Data crossing | Synthetic or anonymized data in non-production | Masked subsets | A production restore into staging (`/ray-vault` `NPD-02`) |
| Network crossing | No peering between environments | Peering with narrow rules | A shared subnet or a flat network across environments |
| Production access | Few named humans, SSO + MFA, time-boxed elevation, audited | Standing access for a small group | Shared credentials; a long-lived admin key in a password manager |
| Break-glass | An explicit, alarmed, audited emergency role | — | An always-available administrator account nobody monitors |
| Environment parity | The same IaC produces every environment | Small documented deltas | Production built by hand — nothing verified elsewhere is known to be true of it |
| Config separation | Per-environment values, no production defaults in code | — | A production hostname or key as the default when an environment variable is unset |

______________________________________________________________________

## 4. Secret Topology

| Control | Expected | Failing shape |
|---|---|---|
| Single authority | One secret manager | Secrets spread across CI variables, `.env` files, Kubernetes `Secret` YAML, and Terraform variables |
| Committed secrets | None | A Kubernetes `Secret` in the repository — base64 is encoding, not encryption; treat it as plaintext |
| Retrieval | Workload identity (instance profile, IRSA, pod identity, workload identity federation) | A static access key distributed to fetch the other secrets, which just moves the problem |
| CI → cloud | OIDC federation, short-lived credentials | Long-lived cloud access keys in CI secrets |
| Rotation | Automated, or documented and exercised | None; a leaked value stays valid forever |
| Scope | One secret per consumer | One shared secret, so revocation is an outage everywhere |
| Build-time exposure | Secrets never passed as build args | `ARG API_KEY` persisting in image layers and `docker history` |
| State files | Encrypted remote backend, access-controlled, never committed | `terraform.tfstate` in the repository — it contains plaintext values of everything it manages |
| Committed encryption | SOPS/sealed-secrets/age for anything that must live in git | Plain YAML |
| Log exposure | Secrets masked in CI output and application logs | A workflow echoing an environment dump on failure |

______________________________________________________________________

## 5. Pipeline Integrity

The pipeline is a production system with write access to production. Audit it
like one.

| Control | Expected | Failing shape |
|---|---|---|
| Security gates | lint, tests, dependency audit, secret scan, image scan before deploy | No gates; or gates suffixed with `|| true` / `continue-on-error: true` so they can never fail the build |
| Branch protection | No direct pushes to the default branch; required review; required checks | Not visible in the repository → `UNKNOWN` with the reason, not an assertion |
| `CODEOWNERS` | Covers IaC, authentication, and CI paths | Absent, or covering only documentation |
| IaC review | Infrastructure changes reviewed like code | A pipeline that applies infrastructure on push with no approval gate |
| Pipeline privilege | Least privilege for the deploy role, per environment | A CI role with administrator rights: every workflow is a path to full control |
| Untrusted triggers | `pull_request` (no secrets) for fork contributions | `pull_request_target` combined with a checkout of the fork's head and secrets in scope — a direct repository-compromise path, and one of the highest-value findings in this stage |
| Third-party actions | Pinned by commit SHA | `uses: some/action@main` — a mutable reference executing in a privileged context |
| Base images | Pinned by digest, rebuilt on a schedule | `FROM node:latest`; a base pinned years ago and never rebuilt |
| Artifacts | Immutable, versioned, ideally signed with provenance | `:latest` deployed to production; nothing can say which commit is running |
| Deploy strategy **[scale]** | Canary or blue-green with automatic rollback | Big-bang deploys with a manual rollback nobody has practised |
| Runners | Ephemeral; untrusted code isolated | A persistent self-hosted runner executing fork pull requests, retaining state between jobs |
| Environment protection | Manual approval and restricted branches for production deploys | Any branch deployable to production |
| Dependency updates | Dependabot/Renovate configured and merging | Configured with a year of open pull requests — `PARTIAL`, and worth saying so |

______________________________________________________________________

## 6. Runtime Hardening

### Containers

| Control | Expected | Failing shape |
|---|---|---|
| User | `USER app` (non-root) in the Dockerfile; `runAsNonRoot: true` | Running as root — every container escape starts as root |
| Filesystem | `readOnlyRootFilesystem: true` with explicit writable mounts | Writable root, so an attacker persists |
| Privileges | `allowPrivilegeEscalation: false`, `no-new-privileges`, dropped capabilities | `privileged: true`; `CAP_SYS_ADMIN`; `--cap-add=ALL` |
| Host namespaces | None | `hostNetwork`, `hostPID`, `hostIPC` |
| Docker socket | Never mounted | `/var/run/docker.sock` mounted into a container — equivalent to host root |
| Base image | Minimal (distroless/slim/alpine), pinned by digest | A full OS image with a shell, a package manager, and a large CVE surface |
| Build content | No secrets, no `.git`, no development tooling in the final layer | A single-stage build shipping source, keys, and toolchains |
| Resources | CPU and memory requests and limits set | Unbounded containers: one workload starves the node |
| Health probes | Liveness and readiness distinct and meaningful | A readiness probe that returns 200 before dependencies are ready, sending traffic into failure |

### Kubernetes **[scale]**

| Control | Expected | Failing shape |
|---|---|---|
| Network policy | Default-deny ingress and egress per namespace | None — the default is allow-all between pods, which erases every "private" boundary inside the cluster |
| Service accounts | Least privilege; `automountServiceAccountToken: false` where unused | The `default` service account with broad RBAC, mounted everywhere |
| RBAC | Namespaced roles, no `cluster-admin` for workloads | Wildcard verbs and resources |
| Pod Security | Restricted profile enforced by admission | No admission control; anything deployable |
| Secrets | External secret operator or encrypted at rest with a customer-managed key | Plain `Secret` objects with default etcd encryption assumptions |
| Ingress | TLS, sane annotations, no wildcard host catching unintended traffic | A wildcard host routing unknown hostnames to a live service |
| Node access | Managed node groups; no standing SSH | Direct node access with shared keys |

______________________________________________________________________

## 7. Observability and Incident Readiness

| Control | Expected | Failing shape |
|---|---|---|
| Log centralization | Off-host, queryable, retained | Logs only on the instance — an attacker's first cleanup target |
| Correlation ids | Propagated across services and included in error responses | None; incidents are reconstructed by guesswork |
| Golden metrics | Latency, error rate, saturation, plus 401/403 rates | Infrastructure metrics only, so an attack looks like normal traffic |
| Cloud audit trail | Enabled in every account, delivered to an account the workload cannot write to | Disabled, or written to a bucket the same compromise can erase |
| Incident runbook | Committed before it is needed: who is paged, how to revoke and rotate, how to isolate, how to restore, how to communicate — including the ANPD 3-business-day and GDPR 72-hour clocks | None. The clock starts at discovery, not at the moment someone starts writing the plan |
| Recovery objectives | RTO/RPO stated; restore exercised | Untested backups (`/ray-vault` `BKP-07`) |
| On-call | Defined rotation with escalation | Alerts to an unmonitored channel |
| Post-incident review | A blameless template, with actions tracked | Nothing; the same incident recurs |
| Threat modeling | Evidence of security review for sensitive features (template, checklist, `CODEOWNERS`) | Security review happens only when someone remembers |
| Security testing in CI | The invariant tests this suite recommends — cross-tenant access, authorization, header assertions — run on every change | Security verified once, manually, in a review nobody repeats |

That last row is the one worth insisting on. Every finding this suite produces
can be converted into a test that fails on regression. Security that is not in
the pipeline evaporates.

______________________________________________________________________

## 8. Control Ledger IDs

| ID | Control |
|---|---|
| `TOPO-01` | All public traffic transits the CDN/WAF; origin not directly addressable |
| `TOPO-02` | Application instances not publicly addressable |
| `TOPO-03` | Datastores in private subnets with no internet route |
| `TOPO-04` | Security groups permit only adjacent-layer traffic |
| `TOPO-05` | Egress restricted |
| `TOPO-06` | Management access via session manager/bastion; no standing open ports |
| `TOPO-07` | Internal traffic encrypted |
| `TOPO-08` | IMDSv2 required with a hop limit |
| `TOPO-09` | No dangling DNS delegations |
| `STATE-01` | Session state externalized |
| `STATE-02` | File state in object storage |
| `STATE-03` | Security counters in a shared store |
| `STATE-04` | Scheduled work executes once |
| `STATE-05` | Autoscaling bounded with budget alarms |
| `STATE-06` | Deployments drain connections |
| `STATE-07` | Security decisions fail closed |
| `STATE-08` | Queues bounded with dead-letter handling |
| `ENV-01` | Environments separated by account/project |
| `ENV-02` | No credential crossing between environments |
| `ENV-03` | No production data in lower environments |
| `ENV-04` | No network peering between environments |
| `ENV-05` | Production access restricted, SSO+MFA, time-boxed, audited |
| `ENV-06` | Break-glass access explicit and alarmed |
| `ENV-07` | Environments produced by the same IaC |
| `ENV-08` | No production defaults baked into code |
| `SEC-01` | Single secret-management authority |
| `SEC-02` | No secrets committed (including Kubernetes `Secret` YAML) |
| `SEC-03` | Runtime retrieval via workload identity |
| `SEC-04` | CI authenticates to the cloud via OIDC federation |
| `SEC-05` | Rotation automated or documented and exercised |
| `SEC-06` | One secret per consumer |
| `SEC-07` | No secrets in build args or image layers |
| `SEC-08` | IaC state encrypted, access-controlled, not committed |
| `SEC-09` | Secrets masked in CI and application logs |
| `PIPE-01` | Security gates present before deploy |
| `PIPE-02` | Gates can fail the build |
| `PIPE-03` | Branch protection and required review |
| `PIPE-04` | `CODEOWNERS` covers security-relevant paths |
| `PIPE-05` | IaC changes reviewed before apply |
| `PIPE-06` | Deploy role least-privileged per environment |
| `PIPE-07` | No workflow executes untrusted code with secrets in scope |
| `PIPE-08` | Third-party actions pinned by SHA |
| `PIPE-09` | Base images pinned by digest and rebuilt on a schedule |
| `PIPE-10` | Immutable versioned artifacts; no `latest` in production |
| `PIPE-11` | Progressive deploy with automatic rollback |
| `PIPE-12` | Runners ephemeral and isolated |
| `PIPE-13` | Production deploys gated by environment protection |
| `PIPE-14` | Dependency updates configured and merging |
| `RUN-01` | Containers run as non-root |
| `RUN-02` | Read-only root filesystem where feasible |
| `RUN-03` | No privileged containers or unnecessary capabilities |
| `RUN-04` | No host namespaces or mounted Docker socket |
| `RUN-05` | Minimal, digest-pinned base images |
| `RUN-06` | Final images free of secrets, VCS metadata, and build tooling |
| `RUN-07` | Resource requests and limits set |
| `RUN-08` | Default-deny network policies |
| `RUN-09` | Least-privilege service accounts; token automount disabled where unused |
| `RUN-10` | Pod security admission enforced |
| `OBS-01` | Logs centralized off-host |
| `OBS-02` | Correlation ids propagated |
| `OBS-03` | Golden metrics including 401/403 rates |
| `OBS-04` | Cloud audit trail enabled and protected |
| `OBS-05` | Incident runbook committed, with regulatory clocks |
| `OBS-06` | RTO/RPO stated and restore exercised |
| `OBS-07` | On-call rotation with escalation |
| `OBS-08` | Post-incident review process |
| `PROC-01` | Threat modeling applied to sensitive features |
| `PROC-02` | Security invariants tested in CI |
