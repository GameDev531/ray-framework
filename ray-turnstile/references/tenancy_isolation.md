# Tenancy Isolation — Models, Enforcement, Footguns

Cross-tenant data access is the worst outcome a multi-tenant application can
produce, and it is almost always caused by a single missing predicate rather
than by a missing subsystem. This reference gives `/ray-turnstile` the isolation
models, the per-model audit procedure, the Postgres RLS footgun list, and the
regression test that makes the control durable.

## Table of Contents

- [0. The Three Authorization Layers](#0-the-three-authorization-layers)
- [1. Isolation Models](#1-isolation-models)
- [2. Auditing Shared-Schema Isolation](#2-auditing-shared-schema-isolation)
- [3. Row-Level Security Footguns](#3-row-level-security-footguns)
- [4. Isolation Beyond The Primary Database](#4-isolation-beyond-the-primary-database)
- [5. The Regression Test](#5-the-regression-test)
- [6. Control Ledger IDs](#6-control-ledger-ids)

______________________________________________________________________

## 0. The Three Authorization Layers

Authorization fails at three levels that are independent of each other. A
codebase can enforce one perfectly and none of the others, which is why a single
"is authorization implemented?" question produces useless answers.

### Object level (IDOR / BOLA — API1:2023)

Every handler that reads an identifier from request input — path, query, body,
or header — must scope the lookup to the principal.

| | Shape |
|---|---|
| Expected | `WHERE id = $1 AND tenant_id = $2`, or a policy check between the fetch and the response |
| Failing | Fetch by id, then return. The "authorization" is that the UI never shows other ids |
| Trap | UUIDs are **not** a substitute for the check. Unguessable ids still leak through referrers, logs, exports, and shared links. When a comment claims otherwise, say so explicitly in the finding |
| Trap | Writes and deletes are audited separately from reads. A scoped `GET` beside an unscoped `DELETE` is common and worse |

### Function level (BFLA — API5:2023)

Privileged operations reachable by an unprivileged principal.

- Admin routers mounted without a guard.
- Role checks present in the UI but not on the API.
- Method-specific gaps: `GET` guarded, `PATCH` not.
- GraphQL mutations that bypass the REST middleware entirely.
- A guard applied to `/admin/*` but not to the same handler mounted elsewhere.

### Property level (BOPLA — API3:2023)

Both directions of the same mistake.

**Inbound (mass assignment).** `User.update(req.body)`,
`Object.assign(user, req.body)`, `**request.data`,
`assign_attributes(params)`, `patchValue(...)`. Verify there is an explicit
field allowlist and that none of these are settable from input:

```
role, is_admin, permissions, scopes
tenant_id, org_id, account_id, owner_id, user_id
plan, subscription, seats, quota, credits, balance
verified, email_verified, status, state
price, amount, discount, total
created_at, id
```

**Outbound (over-serialization).** A serializer that dumps the model: password
hashes, reset tokens, internal notes, soft-deleted rows, other users' ids.
The tell is a response carrying far more than the screen displays.

### Where all three are commonly skipped

The middleware protects the HTTP path and nothing else. Sweep these separately,
every time: background jobs, queue consumers, scheduled tasks, export and report
generators, webhook handlers, GraphQL resolvers, batch and bulk endpoints,
admin CLI commands, and internal tooling (Django admin, ActiveAdmin, Retool
configurations, a `scripts/` directory).

______________________________________________________________________

## 1. Isolation Models

| Model | Shape | Primary failure mode | How to recognize it in the repo |
|---|---|---|---|
| `shared_schema` | One database, one schema, a `tenant_id` (or `org_id`, `account_id`, `workspace_id`, `company_id`) column on tenant-owned tables | A query that forgets the predicate | A migration adding `tenant_id` to many tables; a base model or scope carrying it |
| `schema_per_tenant` | One database, `SET search_path` per tenant | The `search_path` leaking across pooled connections; migrations drifting between schemas | `CREATE SCHEMA` per signup; `search_path` manipulation in a connection hook |
| `db_per_tenant` | One database (or cluster) per tenant | Connection routing picking the wrong tenant; credential sprawl; a shared "control plane" database that is itself shared-schema | A tenant→DSN registry, dynamic connection factories |
| `single_tenant` | One deployment per customer | Not a tenancy problem, but check that the "admin"/"support" plane spanning deployments is itself authorized | One config file per environment, no tenant column anywhere |

**Hybrids are the norm.** A `db_per_tenant` product usually still has a shared
control-plane database holding users, invites, billing, and audit logs — that
plane is shared-schema and must be audited as such. Record the hybrid in the
ledger rather than forcing one label.

**Inference procedure when `--tenancy auto`:**

1. Grep migrations and models for `tenant_id|org_id|organization_id|account_id|
   workspace_id|company_id|customer_id`. Many tables carrying one → shared
   schema.
2. Grep for `CREATE SCHEMA`, `search_path`, `SET SCHEMA` → schema per tenant.
3. Grep for dynamic connection strings, a tenant→database map, or a connection
   factory keyed by tenant → database per tenant.
4. None of the above, and a single hard-coded customer identity in config →
   single tenant.

Record the inference, the evidence paths, and the confidence in the ledger.
If the evidence is contradictory, record `UNKNOWN` and audit against the
**most permissive** possibility (shared schema) — failing conservative here
means over-checking, which is cheap; failing the other way means missing the
worst class of bug.

______________________________________________________________________

## 2. Auditing Shared-Schema Isolation

This is a population sweep, not a spot check. Do it in this order.

### 2.1 Enumerate tenant-owned tables

From migrations and models, list every table with a tenant column, plus every
table that is *transitively* tenant-owned (a `line_items` table with no
`tenant_id` but a foreign key to `invoices`). Transitive tables are where
isolation quietly breaks: the join that was supposed to carry the constraint
gets replaced by a direct lookup during a refactor.

### 2.2 Enumerate every read and write against those tables

Cover all of these, because the middleware only protects the first:

- ORM calls (`findOne`, `findByPk`, `get`, `filter`, `where`, `find_by`)
- query-builder calls (Knex, jOOQ, SQLAlchemy Core, Ecto)
- raw SQL (`db.query`, `execute`, `.raw(`, stored procedures, views)
- GraphQL resolvers and dataloaders
- background jobs, cron tasks, queue consumers
- report/export/analytics code paths
- admin panels and internal tooling (Django admin, ActiveAdmin, Retool
  configs, a `scripts/` directory)
- database views and materialized views (a view without the predicate exports
  the leak to every query that selects from it)

### 2.3 Classify each site

| Classification | Shape |
|---|---|
| SCOPED | The tenant predicate is present, and the tenant value comes from the authenticated principal |
| SCOPED-BY-DEFAULT | A framework default scope, base repository, or RLS policy applies — verify it actually attaches on this path, including for raw SQL and for jobs that run outside the request context |
| UNSCOPED | No predicate; the row is fetched by primary key or by a non-tenant filter |
| SPOOFABLE | A predicate exists, but the tenant value comes from request input (`req.body.tenant_id`, `X-Tenant-Id`, a query parameter, a JWT claim the client can influence) — this is worse than unscoped, because it looks correct in review |

`SPOOFABLE` deserves its own finding text: state exactly where the tenant value
originates and how a caller controls it.

### 2.4 Report

One finding per UNSCOPED/SPOOFABLE site, each carrying the shared root cause in
its description so `ray-condenser` can cluster them. Put the total scoped vs.
unscoped counts in the ledger's `identity_surface.unscoped_query_sites`.

### 2.5 The cross-tenant write

Do not stop at reads. Check that:

- create paths set `tenant_id` from the principal, never from input;
- update paths cannot move a row between tenants (`UPDATE … SET tenant_id = …`);
- foreign keys cannot reference another tenant's row (attaching tenant B's file
  to tenant A's invoice — a validation gap that leaks data on the next render);
- bulk endpoints validate every element of the array, not just the first.

______________________________________________________________________

## 3. Row-Level Security Footguns

RLS is the strongest available control for shared-schema isolation because it
moves enforcement below the application, where a forgotten predicate cannot
reach. It also fails silently when misconfigured, which makes it a high-value
audit target.

The expected shape:

```sql
ALTER TABLE pedidos ENABLE ROW LEVEL SECURITY;
ALTER TABLE pedidos FORCE ROW LEVEL SECURITY;      -- see footgun 2

CREATE POLICY tenant_isolation ON pedidos
  USING      (tenant_id = current_setting('app.tenant_id')::uuid)   -- reads
  WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);  -- writes
```

```js
// per-request, inside the transaction that will run the queries
await client.query('BEGIN');
await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]); // true = transaction-scoped
// ... queries ...
await client.query('COMMIT');
```

| # | Footgun | Why it silently defeats RLS | What to grep |
|---|---|---|---|
| 1 | The app connects as a **superuser** or a role with `BYPASSRLS` | Policies are not applied at all | Connection strings using `postgres`/`root`; `ALTER ROLE … BYPASSRLS`; a migration user reused at runtime |
| 2 | The app role **owns the table** and `FORCE ROW LEVEL SECURITY` is not set | Table owners are exempt from their own policies by default — the most common production failure | `ENABLE ROW LEVEL SECURITY` present with no matching `FORCE`; owner of the migration = runtime role |
| 3 | `USING` without `WITH CHECK` | Reads are filtered but a tenant can INSERT or UPDATE rows into another tenant | `CREATE POLICY` blocks lacking `WITH CHECK` on writable tables |
| 4 | Policies only for `SELECT` | `FOR SELECT` policies leave `INSERT`/`UPDATE`/`DELETE` unconstrained | `FOR SELECT` with no sibling policies, and no `FOR ALL` |
| 5 | Session-scoped context through a transaction pooler | `SET app.tenant_id` (session scope) with PgBouncer in transaction/statement mode leaks the previous tenant's context to the next request's connection — and only manifests under concurrency, i.e. in production | `SET ` / `SET SESSION` for tenant context; PgBouncer `pool_mode = transaction`; any `set_config(..., false)` |
| 6 | Context set outside the transaction that uses it | The connection can be returned to the pool between the set and the query | `set_config` outside a `BEGIN`; a middleware that sets context on a connection it does not hold |
| 7 | Context derived from user input without validation | `set_config('app.tenant_id', req.header('x-tenant'))` is a full bypass with a header | Any tenant context sourced from headers, query strings, or unverified claims |
| 8 | `current_setting` without a default | Raises when unset — which is arguably the *safe* failure; but a policy written as `current_setting('app.tenant_id', true)` (missing_ok) returning NULL can make the predicate NULL and filter everything, or, combined with `OR`, filter nothing | `current_setting(..., true)` inside policies |
| 9 | New tables added without RLS | The migration that adds a table is where isolation is forgotten | Compare the list of tenant tables against tables with `ENABLE ROW LEVEL SECURITY` |
| 10 | `SECURITY DEFINER` functions and views | Run as their owner and can read across tenants; a view without `security_barrier` can leak rows through a cheap, side-effecting function in the caller's `WHERE` | `SECURITY DEFINER`; `CREATE VIEW` over tenant tables |
| 11 | RLS on the primary but not on read replicas or analytics copies | The replica becomes the bypass | Replica DSNs and BI connections |
| 12 | ORM connection reuse across requests | A long-lived connection carrying a stale tenant context (common with singleton clients and serverless connection reuse) | Global client instances used inside request handlers |

**MySQL/other engines.** MySQL has no RLS; isolation is application-enforced or
view-based. Say so in the ledger (`NOT_APPLICABLE` for the RLS controls, with a
note) and weight the Step-2 sweep accordingly — without a database-level net,
every unscoped query is a live defect rather than a defense-in-depth gap.

______________________________________________________________________

## 4. Isolation Beyond The Primary Database

The database is the part teams remember. These are the parts they do not:

| Surface | Failing shape | Test |
|---|---|---|
| Cache (Redis/Memcached) | Keys like `user:123:profile` or `report:monthly` with no tenant component | Grep key builders for a tenant segment; check cache invalidation is also tenant-scoped |
| Object storage | A shared bucket with predictable paths (`/uploads/1234.pdf`), or signed URLs with an over-broad prefix | Check the key template and the signing scope |
| Search index | One index for all tenants with no filter applied at query time, or a filter applied in the client rather than the query | Check the query builder for a tenant filter and whether it can be omitted |
| Queues and jobs | A job payload carrying only a record id; the worker then loads it with no tenant context | Check that workers re-establish tenant context, and that the payload's tenant is validated against the record |
| Rate-limit / quota counters | Shared counters letting one tenant exhaust another's quota | Check the counter key |
| Webhooks | Events for tenant A delivered to a URL configured by tenant B; a shared signing secret across tenants | Check per-tenant secrets and delivery targets |
| Exports and reports | A report generator run with an admin connection that ignores scoping | Audit the report path separately; it is frequently written outside the ORM |
| Logs and error trackers | Tenant A's payloads visible to tenant B's support users in a shared tool | Out of scope for isolation, but note it for `/ray-custodian` |
| Feature flags / config | A flag evaluation that leaks another tenant's configuration or customer list | Check the evaluation payload |
| ML/embedding stores | Vector collections shared across tenants with filtering applied post-retrieval | The filter must be part of the query, not applied after |

______________________________________________________________________

## 5. The Regression Test

Every isolation finding should carry this in `mitigation`, adapted to the stack.
It is the cheapest durable control in the entire suite:

```
GIVEN a principal authenticated as tenant A
WHEN it requests a resource owned by tenant B
  (by id, in a list filter, in a bulk operation, via the export endpoint,
   via a queued job, and via GraphQL)
THEN the response is 404 (preferred, no existence oracle) or 403
AND no row of tenant B appears in the response body
AND the attempt is recorded in the audit log
```

Extended cases worth naming when relevant:

- **Write direction**: tenant A cannot create or update a row bearing tenant B's
  id, and cannot re-parent a row into tenant B.
- **Nested resources**: `/tenants/A/projects/<B's project id>` must 404 even
  though the tenant segment is correct.
- **Enumeration**: a sequential-id resource must not distinguish "exists but
  forbidden" from "does not exist".
- **Post-deletion**: after tenant A's user is removed, their token must stop
  working immediately, not at expiry.

Record in the ledger whether such tests already exist in the repository
(`TEST-01`). Their absence is a MEDIUM finding on its own in any application
that stores multi-tenant data.

______________________________________________________________________

## 6. Control Ledger IDs

| ID | Control |
|---|---|
| `TEN-01` | Isolation model identified with evidence |
| `TEN-02` | All tenant-owned tables enumerated, including transitive ones |
| `TEN-03` | Every read against tenant tables is scoped |
| `TEN-04` | Every write sets/validates tenant from the principal, never from input |
| `TEN-05` | Tenant value never sourced from client-controlled input |
| `TEN-06` | Rows cannot be re-parented between tenants |
| `TEN-07` | Foreign keys cannot cross tenants |
| `RLS-01` | RLS enabled on every tenant-owned table |
| `RLS-02` | `FORCE ROW LEVEL SECURITY` set where the app role owns the table |
| `RLS-03` | App role is not superuser and lacks `BYPASSRLS` |
| `RLS-04` | Policies cover read and write (`USING` + `WITH CHECK`, all commands) |
| `RLS-05` | Tenant context set transaction-scoped and pooler-safe |
| `RLS-06` | `SECURITY DEFINER` functions and views reviewed for cross-tenant reads |
| `RLS-07` | Replicas and analytics copies enforce the same policies |
| `AUTHZ-01` | Enforcement model identified (middleware/policy/ad-hoc) |
| `AUTHZ-02` | Object-level authorization on every id taken from request input |
| `AUTHZ-03` | Function-level authorization on privileged routes (all methods, all protocols) |
| `AUTHZ-04` | Property-level authorization: field allowlists on write, field filtering on read |
| `AUTHZ-05` | No authorization enforced solely in the frontend |
| `AUTHZ-06` | Jobs, exports, webhooks, and admin tooling enforce the same rules |
| `ISO-01` | Cache keys tenant-scoped |
| `ISO-02` | Object-storage paths and signed URLs tenant-scoped |
| `ISO-03` | Search/vector queries filter by tenant in the query itself |
| `ISO-04` | Queue workers re-establish and validate tenant context |
| `ISO-05` | Quota and rate-limit counters are per tenant |
| `ISO-06` | Webhook targets and signing secrets are per tenant |
| `TEST-01` | A cross-tenant access regression test exists in the repository |
