# Datastore Hardening — Controls, Grants, and Failing Shapes

The control set `/ray-vault` scores each datastore against. Engine-specific
detail is given where it changes the verdict; where it does not, the control is
stated once and applies to every store in the inventory.

## Table of Contents

- [1. Privilege Separation](#1-privilege-separation)
- [2. Network Reachability](#2-network-reachability)
- [3. Encryption](#3-encryption)
- [4. Credentials](#4-credentials)
- [5. Backups](#5-backups)
- [6. Non-Production Copies](#6-non-production-copies)
- [7. Data-Layer Detection](#7-data-layer-detection)
- [8. Control Ledger IDs](#8-control-ledger-ids)

______________________________________________________________________

## 1. Privilege Separation

The application should never hold more authority than the feature set requires.
This is the control that decides how much a SQL injection is worth.

### Expected shape (Postgres)

```sql
-- runtime role: DML only, on the tables it actually touches
CREATE ROLE app_api LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE appdb TO app_api;
GRANT USAGE ON SCHEMA public TO app_api;
GRANT SELECT, INSERT, UPDATE ON pedidos, clientes TO app_api;
-- no DELETE, no TRUNCATE, no DDL, no access to other tables

-- reporting role: read-only, ideally pointed at a replica
CREATE ROLE app_reports LOGIN PASSWORD '...';
GRANT SELECT ON pedidos TO app_reports;

-- migration role: DDL, used only by the migration job
CREATE ROLE app_migrate LOGIN PASSWORD '...';
-- owns the schema; the runtime role does not
```

### Failing shapes

| Shape | Consequence | Where to find it |
|---|---|---|
| Connecting as `postgres`, `root`, `sa`, `admin`, or the RDS master user | Any injection becomes total database control, including disabling auditing and reading server files | Connection strings, compose files, IaC `username` fields |
| `GRANT ALL PRIVILEGES` / `GRANT ALL ON ALL TABLES IN SCHEMA public` | Same blast radius with a different spelling | Migrations, `init.sql`, provisioning scripts |
| Runtime role **owns** the schema/tables | Owners can `DROP`, `ALTER`, and are exempt from RLS unless `FORCE ROW LEVEL SECURITY` is set (see `/ray-turnstile`'s tenancy reference, footgun 2) | Whoever runs migrations is the owner — compare migration and runtime credentials |
| One role for migrations and runtime | The application permanently holds DDL rights | A single `DATABASE_URL` used by both the app and the migration job |
| `DELETE`/`TRUNCATE` granted to a service that never deletes | Turns a read compromise into destruction, and defeats audit-table integrity | Grant statements versus actual query verbs in the code |
| BI/analytics connecting to the primary with write rights | A standing, widely shared, high-privilege credential | BI tool configuration, `.env` files, IaC |
| Engineers connecting to production directly | Unaudited, ad-hoc access; credentials spread to laptops | Runbooks, `Makefile` targets, documented tunnels |
| `SECURITY DEFINER` functions callable by the runtime role | Privilege escalation inside the database | Migrations creating functions |
| Reachable file/command primitives (`COPY … FROM PROGRAM`, `pg_read_file`, `LOAD_FILE`, `xp_cmdshell`, `sys.eval`) | Injection escalates to host access | Extension lists, role attributes, engine configuration |
| MongoDB `dbOwner`/`root`, Redis with no ACLs, Elasticsearch superuser | Same class in other engines | Engine-specific user configuration |

### How to audit without connecting

Compare two lists: the verbs the application actually issues (from the ORM and
raw queries) and the verbs the role is granted (from migrations and IaC). Any
grant with no corresponding usage is excess privilege. If grants are not in the
repository, record `UNKNOWN` and name the artifact that would settle it.

______________________________________________________________________

## 2. Network Reachability

| Control | Expected | Failing shape |
|---|---|---|
| Public reachability | Private subnet, no public IP | `publicly_accessible = true`, a public IP on the instance, `ports: "5432:5432"` in a deployed compose file |
| Source restriction | Only the application's security group / subnet | `0.0.0.0/0`, `::/0`, or a whole-VPC CIDR on the database port |
| Authentication | Required, strong, per-service | Redis without `requirepass`; MongoDB/Elasticsearch with authentication disabled; a default password reused in a deployed environment |
| Admin UIs | Not deployed, or behind SSO and a private network | Adminer/pgAdmin/Mongo Express/Kibana/RedisInsight exposed |
| Object storage | Public-access block on, no wildcard principals, no public ACLs | `"Principal": "*"`, `acl = "public-read"`, missing `aws_s3_bucket_public_access_block` |
| Pre-signed URLs | Short expiry, narrow object scope | Multi-day expiry, prefix-wide scope |
| Managed service endpoints | Private endpoint / VPC peering | Public endpoints with IP allowlists as the only barrier |

**Grep starters:** `publicly_accessible|0\.0\.0\.0/0|::/0|public-read|Principal.*\*|requirepass|security\.enabled|allowAnonymous|5432:|3306:|6379:|27017:|9200:`

**Note on compose files.** A `docker-compose.yml` publishing a database port is
only a finding if that file describes a deployed environment. A local
development compose file publishing 5432 to `127.0.0.1` is not. Read the file's
role before reporting, and say which you concluded.

______________________________________________________________________

## 3. Encryption

### In transit

| Engine | Expected | Failing shape |
|---|---|---|
| Postgres | `sslmode=verify-full` (or `verify-ca`) with a pinned root cert | `sslmode=disable`, `sslmode=allow`, `sslmode=prefer`; `require` alone accepts any certificate, so an active MITM still succeeds |
| MySQL | TLS required and verified | `useSSL=false`, `verifyServerCertificate=false` |
| MongoDB | `tls=true` with CA validation | `tlsAllowInvalidCertificates=true` |
| Redis | TLS or a strictly private network with authentication | Plaintext across a shared network |
| Elasticsearch | TLS on transport and HTTP layers | `xpack.security.enabled: false` |
| Replication | Encrypted | Plaintext replication between availability zones or regions |

### At rest

Volume encryption is on by default for most managed services, but verify it in
the IaC (`storage_encrypted`, `encryption_configuration`, `kms_key_id`) rather
than assuming — and verify it for **replicas, snapshots, and backups**, which
are separate resources.

State what it does and does not do in the finding: at-rest encryption protects
against stolen media and decommissioned disks. It does not protect against a
compromised application, a leaked credential, or an injection — those read
through the encryption layer transparently.

### At field level

For the highest-sensitivity columns, application-side AEAD encryption with keys
in a KMS means a database dump alone discloses nothing.

| Control | Expected | Failing shape |
|---|---|---|
| Algorithm | AES-256-GCM, XChaCha20-Poly1305, or an envelope scheme from a maintained library | ECB mode; CBC without a MAC; a static IV/nonce; a home-rolled construction |
| Key custody | KMS/HSM, per-environment, rotatable | Key in the repository, in the same database, or in the same environment variable file as the connection string |
| Key rotation | Versioned keys with re-encryption support | No key id stored with the ciphertext, making rotation impossible without a full re-encrypt outage |
| Searchability | Blind index or deterministic encryption where equality search is required, with the leakage acknowledged | Storing a plaintext "search copy" beside the ciphertext, which voids the control |
| Passwords | Hashed with a password KDF, never encrypted | Reversible encryption (see `/ray-turnstile` `CRED-01`) |

### Protocol-level crypto misuse (beyond mode selection)

Choosing AES-GCM is necessary, not sufficient. The failures that survive a
"we use AEAD" claim are in how the primitive is *used*. Audit each where the
application does its own cryptography rather than delegating to TLS/KMS:

| Misuse | Why it breaks | What to grep / check |
|---|---|---|
| **Nonce/IV reuse with GCM/CTR/ChaCha** | Reusing a nonce under the same key is catastrophic for GCM — it leaks the authentication key and XORs plaintexts. A counter that resets, a random 96-bit nonce generated at high volume (birthday bound), or a hard-coded IV | `iv =`/`nonce =` constants; a nonce derived from a low-entropy counter; random nonce without a usage cap |
| **Static/predictable IV with CBC** | Enables chosen-plaintext distinguishers and BEAST-style attacks | A fixed IV, or IV = key, or IV = zero |
| **MAC-then-encrypt / no MAC** | Unauthenticated encryption (CBC/CTR without a separate MAC) enables padding-oracle and bit-flipping attacks | CBC/CTR with no HMAC; encrypt-then-MAC is the safe order — flag MAC-then-encrypt and encrypt-and-MAC |
| **Padding oracle** | A distinguishable error/timing between "bad padding" and "bad MAC" on CBC decryption recovers plaintext | Decryption paths that return different errors/timing for padding vs. integrity failure |
| **ECDSA/DSA nonce (`k`) reuse or bias** | Reusing or biasing the per-signature `k` recovers the private key from two signatures | Home-rolled signing; a fixed or low-entropy `k`; not using RFC 6979 deterministic `k` |
| **RSA without OAEP / textbook RSA** | PKCS#1 v1.5 encryption padding oracles (Bleichenbacher); no padding at all is malleable | `RSA/ECB/NoPadding`, `PKCS1Padding` for encryption (vs OAEP) |
| **Weak/insufficient key or curve** | RSA < 2048, non-standard curves, DES/3DES/RC4/MD5/SHA-1 in a security role | Algorithm/keysize constants |
| **Non-constant-time comparison of MACs/tags** | Timing leak on tag/HMAC compare | `==`/`!=` on a MAC — see `/ray-crucible` `TIMING` |

### TLS/certificate validation depth (in transit)

`sslmode=require` and its equivalents encrypt but do **not** authenticate the
peer — an active MITM succeeds. Beyond the datastore transport rows in §3, check
any application-level TLS client (webhooks, service-to-service, outbound API
calls) for disabled or partial verification:

| Failing shape | Where |
|---|---|
| `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, `CURLOPT_SSL_VERIFYPEER=0`, a trust-all `X509TrustManager`/`HostnameVerifier` | HTTP/DB/gRPC client construction |
| Hostname verification disabled while cert verification is on | Custom `HostnameVerifier` returning true |
| Certificate pinning absent where the threat model needs it, or a pin that never rotates | Mobile/desktop clients, high-value service calls |

These overlap `/ray-turnstile` (signing/JWT) and `/ray-custodian` (transport
headers); report the crypto-usage defect where you found it and let
`/ray-condenser` merge.

______________________________________________________________________

## 4. Credentials

| Control | Expected | Failing shape |
|---|---|---|
| Sourcing | Secret manager at runtime via workload identity (instance role, pod identity, OIDC) | A committed `.env`, a baked image layer, a Kubernetes `Secret` in plain YAML in the repository |
| Committed secrets | None, in source or in history | Connection strings in code, notebooks, fixtures, CI files, Helm values. Removal is not remediation — the credential must be rotated |
| Per environment | Distinct credentials for dev, staging, production | One shared credential; a developer machine compromise becomes a production compromise |
| Rotation | Automated (managed rotation) or supported by an overlap window | No rotation path; a leaked credential is valid indefinitely |
| CI/CD | Short-lived federated credentials (OIDC) | Long-lived static cloud or database keys in CI secrets |
| Least privilege per consumer | A distinct credential per service and per job | One credential shared across services, so revocation means an outage everywhere |
| Scanning | Secret scanning in CI (gitleaks or equivalent) and a documented rotation runbook | No scanning; leaks found by third parties |

______________________________________________________________________

## 5. Backups

| Control | Expected | Failing shape |
|---|---|---|
| Coverage | Every store in the inventory, not just the primary database | Redis-persisted state, object storage, and search indexes forgotten |
| Encryption | Backup artifacts encrypted, key held separately | Plain dumps; the key stored in the same bucket |
| Storage | Private bucket, public access blocked, restricted IAM, versioning | A "temporary" bucket with a permissive policy; a dump left on a web-served path |
| Immutability | Object lock / WORM retention on at least one copy | Backups deletable by the same credential that runs the application — a ransomware actor deletes them first |
| Separation | A separate account or project from production | Backups in the same account, deleted by the same compromise |
| 3-2-1 | Three copies, two media/locations, one off-site | A single copy in the same region and account |
| Retention | Defined, and consistent with the privacy retention policy | Indefinite retention of personal data in backups while the live table is pruned |
| Restore testing | Evidence of a drill: a script, a scheduled restore job, a documented exercise | None — an untested backup is a hypothesis |
| Access logging | Reads of backup objects logged | No visibility into who downloaded a dump |
| Local dumps | Prohibited or tightly controlled | `pg_dump` to a laptop, a shared drive, or a repository directory; `.sql`/`.dump`/`.bak` files committed |

______________________________________________________________________

## 6. Non-Production Copies

The widest, least protected copies of production data usually live outside
production.

| Control | Expected | Failing shape |
|---|---|---|
| Seeds and fixtures | Synthetic data | Real names, emails, and documents committed as fixtures |
| Refresh pipeline | Anonymization applied **inside** the pipeline, before the data lands | A restore into staging followed by a "scrub script" that may or may not run |
| Masking quality | Irreversible: values replaced, not merely hashed or partially redacted | An email hashed to a value still joinable with another table; a CPF with only the middle digits masked, still uniquely identifying |
| Referential integrity | Masking preserves relationships without preserving identity | Masking that breaks the environment, so someone disables it |
| Environment protection | Staging holding production data protected like production | Staging with a shared password, no MFA, and public exposure |
| BI / warehouse | Governed, minimized, access-controlled | A full nightly copy readable by everyone with a BI login |
| Local development | Synthetic seed only | `.sqlite`, `.sql`, or CSV extracts of production in the repository or in developer home directories |
| Model training / analytics | Anonymized or under a stated basis | Production records used to train or evaluate models (cross-reference `/ray-custodian` `PURP-01`) |

______________________________________________________________________

## 7. Data-Layer Detection

| Control | Expected | Failing shape |
|---|---|---|
| Audit logging | pgAudit (or the engine's equivalent) on sensitive tables; CloudTrail data events on buckets | No audit logging: an exfiltration leaves no trace at the layer where it happened |
| Log destination | Off-host, append-only, in a different trust domain | Audit records in a table the application role can `DELETE` |
| Query anomaly signal | Something that would notice a full-table scan, a new client, or a large result set | Nothing; discovery comes from a third party months later |
| Egress monitoring | Volume from the database subnet is measured and alertable | Unmonitored |
| Slow-query and error logs | Retained without embedding personal data, or protected as if they contained it | Bound parameters with personal data in a widely readable log |
| Connection logging | New connections and their source recorded | Off, so a leaked credential's first use is invisible |

Alerting rules themselves belong to `/ray-sentry`; the presence of the signal at
the data layer is scored here.

______________________________________________________________________

## 8. Control Ledger IDs

Use these ids per datastore in `workspace/ledgers/ray-vault.json`. With more
than one store, prefix them (`primary-postgres/PRIV-01`).

| ID | Control |
|---|---|
| `PRIV-01` | Application does not connect as superuser/master |
| `PRIV-02` | Grants scoped to the verbs and tables actually used |
| `PRIV-03` | Separate roles for migrations, runtime, reporting, and workers |
| `PRIV-04` | Runtime role does not own the schema |
| `PRIV-05` | Destructive verbs withheld where unused |
| `PRIV-06` | Analytics/BI on a read-only replica |
| `PRIV-07` | Human production access via bastion, approved and audited |
| `PRIV-08` | No reachable in-database file/command primitives |
| `NET-01` | Datastore not reachable from the internet |
| `NET-02` | Source restriction narrowed to the application |
| `NET-03` | Authentication enabled and non-default |
| `NET-04` | No exposed database admin UIs |
| `NET-05` | Object storage public access blocked; no wildcard principals |
| `NET-06` | Pre-signed URLs short-lived and narrowly scoped |
| `ENC-01` | TLS required and verified on every connection |
| `ENC-02` | Encryption at rest on instances, replicas, and snapshots |
| `ENC-03` | Field-level encryption for the most sensitive columns |
| `ENC-04` | AEAD algorithm with unique nonces; no home-rolled crypto |
| `ENC-05` | Keys in a KMS, per environment, rotatable |
| `ENC-06` | No plaintext "search copy" defeating field encryption |
| `CRED-01` | Credentials sourced at runtime from a secret manager |
| `CRED-02` | No credentials in source or VCS history |
| `CRED-03` | Distinct credentials per environment and per consumer |
| `CRED-04` | Rotation automated or supported without downtime |
| `CRED-05` | CI/CD uses short-lived federated credentials |
| `CRED-06` | Secret scanning in CI |
| `BKP-01` | Backups exist and cover every store |
| `BKP-02` | Backup artifacts encrypted |
| `BKP-03` | Backup storage private, restricted, versioned |
| `BKP-04` | Immutability/object lock on at least one copy |
| `BKP-05` | Backups in a separate account or region |
| `BKP-06` | Retention defined and consistent with the privacy policy |
| `BKP-07` | Restore tested, with evidence |
| `BKP-08` | Backup access logged |
| `BKP-09` | No ad-hoc local dumps |
| `NPD-01` | Seeds and fixtures contain no real personal data |
| `NPD-02` | Production→non-production refresh anonymizes in-pipeline |
| `NPD-03` | Masking is irreversible |
| `NPD-04` | Non-production environments holding real data are protected accordingly |
| `NPD-05` | BI/warehouse copies minimized and access-controlled |
| `NPD-06` | No production data dumps in the repository |
| `DET-01` | Database audit logging on sensitive tables |
| `DET-02` | Audit records tamper-resistant and off-host |
| `DET-03` | Query-anomaly signal available |
| `DET-04` | Egress volume monitored |
| `DET-05` | Slow-query/error logs free of personal data or protected as such |
| `DET-06` | Connection logging enabled |
