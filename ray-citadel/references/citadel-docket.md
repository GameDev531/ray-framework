# Citadel Docket — citadel

Vulnerable→safe patterns for `ray-citadel`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## Flat network / missing segmentation — CWE-923 · A05:2021
- **Broken:** any service can reach any other; the database is reachable from every
  pod; no network policy; internal admin planes on the same segment as public
  workloads.
- **Safe:** network policies / security groups scoping reachability to what each
  service needs; the datastore reachable only from its owning service.

## Weak service-to-service trust — CWE-306
- **Broken:** internal calls trusted because they are "internal" (no mTLS/token);
  a spoofable `X-Internal: true` header; shared static API keys between services.
- **Safe:** mutual TLS or signed service identity (SPIFFE/workload identity); per-caller
  authorization, not network-position trust.

## Secrets management at scale — CWE-798
- **Broken:** one secret shared across all services; secrets in env baked into images
  or in CI logs; no rotation; secrets in a config map in plaintext.
- **Safe:** a secrets manager with per-service scoped, rotatable credentials; short-lived
  tokens; no secret in an image layer.

## Lateral movement / blast radius — A01:2021
- **Broken:** a compromised low-value service holds credentials that reach high-value
  data; over-broad service accounts.
- **Safe:** least-privilege service accounts; a compromise is contained to that
  service's scope.

## Missing isolation of the control plane — CWE-668
- **Broken:** orchestrator/admin APIs (K8s API, CI, dashboards) reachable from workloads
  or the internet.
- **Safe:** control planes isolated and authenticated; workloads cannot reach them.

## What is NOT a finding here

- Perimeter-only trust that is genuinely backed by per-request authz at each service.
- A single-service target — this skill is for multi-service topologies (use the app
  domain skills instead).
- A documented, accepted trust boundary in the threat model.
