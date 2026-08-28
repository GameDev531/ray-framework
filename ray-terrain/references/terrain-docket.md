# Terrain Docket — terrain

Vulnerable→safe patterns for `ray-terrain`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## Over-permissive IAM — CWE-732 · A01:2021
- **Broken:** `Action: "*"` / `Resource: "*"`; a wildcard `Principal`; a role assumable
  by anyone; a K8s ClusterRole with `*` verbs.
- **Safe:** least-privilege actions and resources; scoped trust; named principals.

## Public exposure — CWE-284 · A05:2021
- **Broken:** an S3/GCS bucket or blob container public; a security group opening
  22/3389/DB ports to `0.0.0.0/0`; a database publicly reachable; a K8s Service
  `LoadBalancer` on an internal API.
- **Safe:** private by default; ingress scoped to needed CIDRs; storage private with
  explicit grants.

## Unhardened containers — CWE-250 · A05:2021
- **Broken:** container as root, `privileged: true`, `hostNetwork`/`hostPID`, no
  `readOnlyRootFilesystem`, all capabilities, `:latest` base image, secrets in
  `ENV`/build args.
- **Safe:** non-root user, dropped capabilities, read-only FS, pinned digest base image,
  secrets mounted at runtime not baked in.

## Missing encryption / logging — CWE-311 / CWE-778
- **Broken:** storage/volumes/queues unencrypted; no audit logging; no TLS on internal
  load balancers.
- **Safe:** encryption at rest enabled; audit trails on; TLS in transit.

## Terraform/state hygiene
- **Broken:** state or `.tfvars` with secrets committed; a remote state bucket world-
  readable.
- **Safe:** state in a locked, private, encrypted backend; secrets out of VCS.

## What is NOT a finding here

- A deliberately public asset (a static site bucket, a public API LB) that is public by
  design — confirm intent in the threat model.
- A `latest` tag in a local dev compose file not used in production.
- An over-broad permission in an example/module that the target does not instantiate.
