# Service Docket — Abuse Resistance, Exposure, and Detection

Every control `/ray-sentry` checks, by area. Read one section at a time as you
sweep.

## Table of Contents

- [1. Endpoint Cost Classes](#1-endpoint-cost-classes)
- [2. Rate Limiting and Abuse Control](#2-rate-limiting-and-abuse-control)
- [3. Internal Endpoint Exposure](#3-internal-endpoint-exposure)
- [4. Machine Authentication and API Keys](#4-machine-authentication-and-api-keys)
- [5. Webhooks](#5-webhooks)
- [6. GraphQL and Batch Interfaces](#6-graphql-and-batch-interfaces)
- [7. Security Logging](#7-security-logging)
- [8. Detection and Alerting](#8-detection-and-alerting)
- [9. Control Ledger IDs](#9-control-ledger-ids)

______________________________________________________________________

## 1. Endpoint Cost Classes

Classify every endpoint. The class decides priority, severity, and which control
is actually the right one — this is what stops the stage from producing twenty
equally-weighted "missing rate limit" findings when two of them matter.

| Class | Examples | Why it matters |
|---|---|---|
| `CHEAP` | Static read, health check, cached lookup | Volume alone is the only risk; edge limiting is usually sufficient |
| `DB_HEAVY` | Search, report, export, aggregation, full-text query | One request can occupy the database for seconds; needs concurrency caps, not just rate caps |
| `PAID` | Model inference, SMS, email, geocoding, any third-party call billed per request | Each request spends money. Abuse produces an invoice, not just load — and a rate limiter does not bound a monthly total |
| `SIDE_EFFECT` | Signup, invite, password reset, order creation, webhook delivery | Abuse creates state and reaches third parties: spam sent from your domain, enumeration, reputation damage |
| `PRIVILEGED` | Admin actions, impersonation, key issuance, role changes | Abuse escalates rather than just consuming |

Also flag, per endpoint: no authentication required, undocumented, deprecated
but still routed, and bound to `0.0.0.0` while treated as internal.

______________________________________________________________________

## 2. Rate Limiting and Abuse Control

### The layered model

A single limiter at one layer is not coverage. Score each layer separately.

| Layer | What it is | What it stops | What it misses |
|---|---|---|---|
| Edge | CDN/WAF rules, `nginx limit_req` | Floods, crude scraping, volumetric DoS | An attacker with one account and a proxy pool |
| Application | Per authenticated principal, per API key, per tenant | Account-level abuse of `PAID` and `SIDE_EFFECT` endpoints | Distributed abuse across many free accounts |
| Endpoint class | Login far tighter than reads; `PAID` tied to a quota; `DB_HEAVY` with a concurrency cap | Targeted abuse of the expensive paths | Business-flow abuse (see below) |

**Edge bypass**: if the origin is directly addressable, every edge limit is
optional. Check for a public origin address or an origin hostname with no
restriction to the CDN — and cross-reference `/ray-citadel` `TOPO-01`.

### Properties that decide findings

| Control | Expected | Failing shape |
|---|---|---|
| `RATE-04` Counter storage | A shared store (Redis, the gateway) | An in-process map, the default `express-rate-limit` memory store, a Python dict. Behind N replicas the effective limit is N×, and a deploy resets it to zero. Very common, and invisible in single-instance testing |
| `RATE-05` Response | `429` with `Retry-After`, plus limit headers on public APIs | A `500`, or a silent drop — an availability bug of its own, and it teaches clients to retry harder |
| `RATE-06` Spend ceilings | A per-tenant or per-key cap on paid operations | A rate limiter only. Requests per second says nothing about dollars per month |
| `RATE-08` Amplification | Bounded fan-out | One request producing many outbound requests, notifications, or webhook deliveries — a small limit with a large effect |

### Business-flow abuse (API6:2023)

Flows that assume a human will perform them once: free-trial signup, referral
bonuses, coupon redemption, invite sending, review posting, ticket purchase,
scarce-inventory checkout.

A plain rate limit rarely covers these, because the abuse rate can be well
under any reasonable threshold while still being entirely automated. The
appropriate controls are flow-specific: verification, proof of work, device or
payment-instrument uniqueness, velocity limits across correlated accounts, or
manual review above a threshold. Report the absence with the flow named, not as
a generic rate-limit finding.

______________________________________________________________________

## 3. Internal Endpoint Exposure

Enumerate: `/metrics`, `/health`, `/actuator/**`, `/debug/pprof`, `/status`,
GraphQL introspection, queue dashboards (Bull Board, Flower, Sidekiq Web), admin
panels, database UIs (Adminer, pgAdmin, Mongo Express), tracing UIs, and
internal RPC ports.

| Control | Expected | Failing shape |
|---|---|---|
| `EXPO-01` Reachability | Bound to localhost or an internal interface; no ingress rule; not in a public security group | A `LoadBalancer` service or ingress path reaching an operational endpoint |
| `EXPO-02` Authentication | Present regardless of network position | "It is only reachable inside the cluster" — a network assertion that one misconfigured ingress overturns. Absence is at least MEDIUM when the endpoint exposes state |
| `EXPO-03` Payload content | Minimal | A health endpoint reporting dependency hostnames, versions, and connection strings; a Prometheus endpoint exposing route inventories and tenant names in label values |
| `EXPO-04` Forgotten surfaces | None | Old API versions still routed, staging hostnames in production config, feature-flag admin endpoints, and `.env` / `.git` / backup files reachable through the static file handler |

Judge each payload individually. A liveness probe returning `{"status":"ok"}` is
fine to expose and should be recorded `PRESENT`, not reported.

______________________________________________________________________

## 4. Machine Authentication and API Keys

### Service to service

| Control | Expected | Failing shape |
|---|---|---|
| `S2S-01` Authentication | mTLS, or OAuth client credentials / signed service tokens, with each service validating the caller | Network position treated as identity: any workload that can reach the port is trusted |
| `S2S-02` Identity headers | Never trusted from an untrusted hop | A handler reading `X-User-Id` or `X-Tenant-Id` set by "the gateway" — a full authorization bypass if the service is reachable directly |
| `S2S-03` Proxy chain | `X-Forwarded-For` parsed with a known trusted-proxy count | Taking the leftmost value, which the client sets: defeats IP-based rate limits and allowlists |
| `S2S-04` Brokers | Queue and stream authentication, plus message validation by the consumer | A worker that trusts any message on the queue |

### API keys

| Control | Expected | Failing shape |
|---|---|---|
| `KEY-01` Scope | Least privilege per key | A key that can do everything its owner can |
| `KEY-02` Lifecycle | Expiration, and rotation with an overlap window where both keys are accepted | No rotation path, so rotation means downtime and therefore never happens |
| `KEY-03` Revocation | Immediate | Revocation that waits for a cache TTL |
| `KEY-04` Storage | Hashed at rest like a password, shown once, with an identifiable prefix (`sk_live_…`) so scanners and providers can detect leaks | Plaintext keys in the database; keys re-displayable in the UI |
| `KEY-05` Transport | Header only | Keys in query strings, which are logged by every proxy, CDN, and access log on the path |

______________________________________________________________________

## 5. Webhooks

### Inbound (a third party calls you)

| Control | Expected | Failing shape |
|---|---|---|
| `HOOK-01` Signature verification | The provider's scheme: `stripe.webhooks.constructEvent`, GitHub `X-Hub-Signature-256`, Slack's signing secret, an HMAC over the raw body | A receiver that parses the payload and trusts it. **Anyone who learns the URL can mark an invoice paid** — one of the highest-value findings this stage produces |
| `HOOK-01` Raw body | Verification runs over the exact bytes received | Verification over a re-serialized JSON body: broken by definition, and it usually still passes the provider's test event, so nobody notices |
| `HOOK-02` Comparison | Constant-time (cross-reference `/ray-crucible` `TIMING`) | `===` on the signature |
| `HOOK-03` Replay | Timestamp window enforced | A captured request replayable indefinitely |
| `HOOK-04` Idempotency | Keyed by event id | A retried or replayed event applying twice — providers retry by design, so this is a correctness bug that is also a security one |
| — | Ordering | State transitions tolerant of out-of-order delivery | A `subscription.deleted` arriving before `subscription.created` leaving state wrong |

### Outbound (you call a customer's URL)

| Control | Expected | Failing shape |
|---|---|---|
| — | URL validation | SSRF: the URL is customer-supplied (`/ray-crucible` `SSRF`) |
| `HOOK-05` Signing | Your deliveries signed, with a per-tenant secret | Unsigned deliveries, or one shared secret across tenants |
| `HOOK-06` Retries | Bounded, with backoff and a dead-letter path | An unbounded retry loop against a slow customer endpoint: a self-inflicted outage |

______________________________________________________________________

## 6. GraphQL and Batch Interfaces

Only where the target exposes them.

| Control | Expected | Failing shape |
|---|---|---|
| `GQL-01` Cost limits | Depth and complexity limits | A nested query (`user { friends { friends { … } } }`) as an unauthenticated database amplifier |
| `GQL-02` Schema exposure | Introspection **and** field suggestions disabled in production | Suggestions ("did you mean…") reconstruct the schema even with introspection off — teams disable one and not the other |
| `GQL-03` Batching and aliasing | Batch size limits, and rate limiting keyed on operations rather than requests | One request with hundreds of aliased `login` mutations bypassing per-request limits entirely |
| `GQL-04` Public APIs | Persisted queries or an operation allowlist | Arbitrary queries from anonymous callers |
| — | Field authorization | Enforced per resolver | Resolvers bypassing the REST middleware (`/ray-turnstile` owns the verdict) |

REST batch endpoints (`POST /batch`, JSON:API bulk, gRPC streaming) have the
same amplification property and deserve the same limits.

______________________________________________________________________

## 7. Security Logging

What must be logged, and what each event must capture. Hygiene — what must never
be logged — is `/ray-seam` §6.

| Event | Must capture | Ledger id |
|---|---|---|
| Authentication success and failure | timestamp, principal, source IP, user agent, outcome | `LOG-01` |
| Logout and session invalidation | principal, hashed session id | `LOG-01` |
| MFA enrollment, use, and failure | principal, factor type | `LOG-01` |
| Credential change and reset | principal, initiator | `LOG-01` |
| Authorization denials (403) | principal, resource, action | `LOG-02` |
| Role, permission, and membership changes | actor, subject, before/after | `LOG-03` |
| API key or token issuance and revocation | actor, key id, scopes | `LOG-03` |
| Access to sensitive personal data | principal, record class, volume | `LOG-04` |
| Bulk export and report generation | principal, row count, filters | `LOG-04` |
| Impersonation start and end | operator, subject, duration | `LOG-05` |
| Administrative and configuration changes | actor, setting, before/after | `LOG-05` |
| Payment and balance operations | principal, amount, idempotency key | `LOG-05` |
| Webhook receipt and signature failures | provider, event id, outcome | `LOG-02` |

Then the properties that make those logs usable at all:

| Control | Expected | Failing shape |
|---|---|---|
| `LOG-06` Correlation | Ids propagated across services and surfaced in error responses | An incident reconstructed by guesswork |
| `LOG-07` Centralization | Off-host, queryable (CloudWatch, Loki, ELK, a SIEM) | Logs only on the host an attacker just compromised |
| `LOG-08` Integrity | Append-only or immutable audit storage | An application role that can `DELETE` from the audit table (cross-reference `/ray-vault`) |
| `LOG-09` Retention | Defined, and consistent with the privacy retention policy | Undefined, or contradicting `/ray-custodian` `RET-03` |
| — | Clocks | UTC, consistent format | Mixed local times across services, making correlation unreliable |

______________________________________________________________________

## 8. Detection and Alerting

Logs nobody reads are not a control — the 2025 Top 10 renames the category to
say exactly that. Check for rules (Prometheus, CloudWatch alarms, Grafana,
Sentry, SIEM correlation) covering at least:

| # | Signal | Ledger id |
|---|---|---|
| 1 | Authentication-failure spike, globally and per account | `ALERT-01` |
| 2 | 403 spike from one principal (authorization probing) | `ALERT-02` |
| 3 | Error-rate and availability degradation | `ALERT-03` |
| 4 | Anomalous data volume: large exports, unusual query volume, egress spikes | `ALERT-04` |
| 5 | Login from a new geography, ASN, or device for privileged accounts | `ALERT-01` |
| 6 | Privilege changes and new admin accounts | `ALERT-05` |
| 7 | Rate-limit rejections trending up (an attack in progress, or a broken client) | `ALERT-06` |
| 8 | Spend anomalies on `PAID` endpoints | `ALERT-07` |
| 9 | Webhook signature failures | `ALERT-02` |
| 10 | New or unusual outbound destinations | `ALERT-04` |

For each, record whether the rule exists, whether it routes to a channel a human
actually watches, and whether a runbook is referenced (`ALERT-08`). An alert
with no owner and no runbook is `PARTIAL` — it will fire into an empty room.

______________________________________________________________________

## 9. Control Ledger IDs

Each appears exactly once in `workspace/ledgers/ray-sentry.json`.

| ID | Control |
|---|---|
| `INV-01` | Endpoint inventory complete (including queues, crons, WebSockets) |
| `INV-02` | No undocumented or deprecated live endpoints |
| `RATE-01` | Edge/WAF rate limiting present |
| `RATE-02` | Per-principal / per-key application limiting present |
| `RATE-03` | Tighter limits on auth and `SIDE_EFFECT` endpoints |
| `RATE-04` | Limiter state shared across instances |
| `RATE-05` | `429` returned with `Retry-After` |
| `RATE-06` | Spend/quota ceilings on `PAID` endpoints |
| `RATE-07` | Business-flow abuse controls where a human is assumed |
| `RATE-08` | Amplifying endpoints bounded |
| `EXPO-01` | Operational endpoints not externally reachable |
| `EXPO-02` | Operational endpoints authenticated regardless of network position |
| `EXPO-03` | Health/metrics payloads free of sensitive detail |
| `EXPO-04` | No stale versions, staging hosts, or dotfiles served |
| `S2S-01` | Service-to-service authentication (mTLS or service tokens) |
| `S2S-02` | Identity headers not trusted from untrusted hops |
| `S2S-03` | Proxy chain enforced before using `X-Forwarded-For` |
| `S2S-04` | Broker authentication and message validation |
| `KEY-01` | API keys scoped to least privilege |
| `KEY-02` | Key expiration and rotation with an overlap window |
| `KEY-03` | Immediate revocation possible |
| `KEY-04` | Keys stored hashed, shown once, prefixed for scanner detection |
| `KEY-05` | Keys not passed in query strings |
| `HOOK-01` | Inbound webhook signatures verified over the raw body |
| `HOOK-02` | Constant-time signature comparison |
| `HOOK-03` | Timestamp/replay window enforced |
| `HOOK-04` | Idempotency by event id |
| `HOOK-05` | Outbound deliveries signed with per-tenant secrets |
| `HOOK-06` | Outbound retries bounded with backoff and a dead-letter path |
| `GQL-01` | Query depth and complexity limits |
| `GQL-02` | Introspection and suggestions disabled in production |
| `GQL-03` | Batch/alias limits, or operation-keyed rate limiting |
| `GQL-04` | Persisted queries or an operation allowlist for public APIs |
| `LOG-01` | Authentication events logged |
| `LOG-02` | Authorization denials and webhook failures logged |
| `LOG-03` | Privilege, membership, and key changes logged |
| `LOG-04` | Sensitive-data access and bulk exports logged |
| `LOG-05` | Administrative, impersonation, and financial actions logged |
| `LOG-06` | Correlation ids propagated |
| `LOG-07` | Logs centralized off-host |
| `LOG-08` | Audit events tamper-resistant |
| `LOG-09` | Log retention defined |
| `ALERT-01` | Authentication-anomaly alerts |
| `ALERT-02` | Authorization-denial and signature-failure alerts |
| `ALERT-03` | Error-rate and availability alerts |
| `ALERT-04` | Anomalous-volume / exfiltration alerts |
| `ALERT-05` | Privilege-change alerts |
| `ALERT-06` | Rate-limit rejection trend alerts |
| `ALERT-07` | Spend-anomaly alerts on `PAID` endpoints |
| `ALERT-08` | Alerts route to a watched channel with a runbook |
