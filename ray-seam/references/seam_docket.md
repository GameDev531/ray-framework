# Seam Docket — Client/Server Trust Boundary Controls

Every control `/ray-seam` checks, by area. Each carries the expected shape, the
failing shape, and where it hides — read one section at a time as you sweep.

The unifying question, asked of each value that crosses the boundary: *who
decides this, and who is allowed to know it?*

## Table of Contents

- [1. Server-Side Validation](#1-server-side-validation)
- [2. Mass Assignment and Over-Serialization](#2-mass-assignment-and-over-serialization)
- [3. Error Handling and Fail-Open Paths](#3-error-handling-and-fail-open-paths)
- [4. Client Storage and Bundles](#4-client-storage-and-bundles)
- [5. CORS and Cross-Origin Messaging](#5-cors-and-cross-origin-messaging)
- [6. Logging Hygiene](#6-logging-hygiene)
- [7. Resource Limits](#7-resource-limits)
- [8. Caching and Response Correctness](#8-caching-and-response-correctness)
- [9. Client-Supplied Values In Server Decisions](#9-client-supplied-values-in-server-decisions)
- [10. Control Ledger IDs](#10-control-ledger-ids)

______________________________________________________________________

## 1. Server-Side Validation

| Control | Expected | Failing shape |
|---|---|---|
| `VAL-01` Schema at every entrypoint | A declarative schema (zod, yup, joi, pydantic, class-validator, JSON Schema, Rails strong parameters, ASP.NET model validation) applied to body, query, params, and any header that feeds logic | A handler reading `req.body.x` with no schema anywhere in its path |
| `VAL-02` Strictness | Unknown keys rejected: `.strict()`, `additionalProperties: false`, `extra="forbid"` | A permissive schema passing extra fields through to whatever consumes the object — the enabling half of mass assignment |
| `VAL-03` Bounds | Numbers ranged, strings length-capped, enums closed, arrays size-capped, dates sane | An unbounded array or string: a storage-abuse and denial-of-service vector before it is anything else |
| `VAL-04` Not client-only | The server enforces independently of the form | `required`, `maxlength`, and a regex on the input element, with no server counterpart. Report the missing **server** check, not the client one |
| — | Correct order | Validation applied after the value was already used, or after a side effect has fired |

**Where it hides.** Newer routes added after the validation convention was
established; GraphQL resolvers and WebSocket handlers, which usually sit outside
the HTTP middleware; webhook receivers; admin endpoints; and file-upload
metadata, which is often parsed before any schema runs.

______________________________________________________________________

## 2. Mass Assignment and Over-Serialization

Both directions of the same mistake: the client deciding which fields matter.

### Inbound (`ASSIGN-01`, `ASSIGN-02`)

Grep: `Model.update(req.body)`, `Object.assign(entity, req.body)`,
`**request.data`, `assign_attributes(params)`, `setattr` loops,
`patchValue(...)`, `.save(req.body)`.

Confirm an explicit field allowlist exists, and that none of these are settable
from input:

```
role, is_admin, permissions, scopes
tenant_id, org_id, account_id, owner_id, user_id
plan, subscription, seats, quota, credits, balance
verified, email_verified, status, state
price, amount, discount, total
created_at, id
```

When the field crosses into authorization, `/ray-turnstile` also owns it —
report and let `ray-condenser` merge.

### Outbound (`ASSIGN-03`)

A serializer that dumps the model. Look for password hashes, reset tokens,
internal notes, soft-deleted rows, other users' identifiers, and fields the UI
never displays. The reliable tell is a response carrying far more than the
screen shows — open the network tab equivalent in the code: what does the
endpoint actually return versus what does the component actually read?

**GraphQL** deserves a separate look: field-level authorization is frequently
absent, and introspection plus field suggestions ("did you mean…") reconstruct
the schema even when introspection is disabled. Cost limits are `/ray-sentry`'s;
field exposure is here.

______________________________________________________________________

## 3. Error Handling and Fail-Open Paths

### Information leakage (`ERR-01`, `ERR-02`, `ERR-04`)

| Control | Expected | Failing shape |
|---|---|---|
| Production error responses | A generic message plus a correlation id; detail logged internally | `err.stack`, `traceback.format_exc()`, `printStackTrace`, framework debug pages, `DEBUG = True`, an unenforced `NODE_ENV` |
| Message content | Uniform across cases | "user not found" versus "wrong password"; "tenant B does not exist" versus "forbidden"; a validation error echoing the database constraint name |
| Debug surfaces | Absent from production builds | `/debug` routes, profilers, publicly served source maps |

### Fail-open (`ERR-03`) — the highest-value sweep in this section

This is why OWASP added *Mishandling of Exceptional Conditions* as A10:2025, and
it is invisible to anyone reading the happy path. For each security-relevant
call, trace what happens when it **throws or times out**:

- A `catch` that logs and then continues past the check.
- A permission check inside a `try` whose `catch` returns `true` or `null`
  (and `null` treated as "no restriction").
- A timeout on an authorization or feature-flag service that defaults to allow.
- A signature verification wrapped in a `try` that swallows the failure.
- A rate-limit store that is unreachable, so the limiter is skipped.
- A token-introspection call that fails and falls back to a cached or default
  identity.

The correct polarity: **security decisions fail closed; non-security paths may
degrade open.** A finding here should say which polarity the code has and what
an attacker does to trigger it — often just enough load to cause a timeout.

______________________________________________________________________

## 4. Client Storage and Bundles

| Control | Expected | Failing shape |
|---|---|---|
| `STORE-01` Web storage | No credentials in `localStorage`/`sessionStorage` | A session or refresh token there: readable by any script the page runs, so any XSS becomes account takeover. The recommended shape is an `HttpOnly` cookie, or an in-memory token with a cookie-based refresh — say so in `mitigation`, because the refresh flow must change with it |
| `STORE-02` Logout | Client caches cleared | Personal data cached client-side surviving logout on a shared device (also `/ray-custodian` `STORE-01`) |
| `BUNDLE-01` Build variables | Only publishable values exposed | Any `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`, `NUXT_PUBLIC_*` carrying a private API key, a database URL, a signing secret, or a service-role key. **A service-role key in a frontend bundle is a HIGH finding with a one-line exploit** |
| `BUNDLE-02` Source maps | Not served in production | Server-side code and comments recoverable from the browser |
| — | Hidden UI as a control | A component gated on `isAdmin` with no server-side counterpart. The server check is `/ray-turnstile`'s finding; note the cross-reference |
| — | Client-side "encryption" | Obfuscation of values the server must trust, presented as a security control |

Enumerate **every** exposed build variable and classify each rather than
sampling. Publishable keys (Stripe publishable, a public analytics id) are fine
and should be recorded as such, so the ones that are not stand out.

______________________________________________________________________

## 5. CORS and Cross-Origin Messaging

### CORS (`CORS-01`…`CORS-03`)

`Access-Control-Allow-Origin: *` with `Allow-Credentials: true` is rejected by
browsers — so the pattern that actually causes incidents is the workaround:
**reflecting the request `Origin` header**, which is equivalent to allowing every
origin, with credentials.

Grep: `origin: true`, `callback(null, true)`, `req.headers.origin` echoed into
the response, `Access-Control-Allow-Origin` built from a variable, and regex
origin matching — `/example\.com$/` also matches `evilexample.com`, and
`/^https:\/\/example\.com/` also matches `example.com.evil.net`.

Also check `Allow-Methods`, `Allow-Headers`, `Expose-Headers`, preflight cache
duration, and whether the `null` origin is allowed (sandboxed iframes and
`file://` pages send it).

### Cross-origin messaging (`MSG-01`, `MSG-02`)

- Every `addEventListener('message', …)` must check `event.origin` against an
  expected value **before** using `event.data`.
- Every `postMessage(data, targetOrigin)` must pass a specific `targetOrigin`,
  never `'*'`, when the payload is not public.
- Embedded third-party frames receiving data via query string or fragment.
- `target="_blank"` without `rel="noopener"`: modern browsers default to
  `noopener`, so this is LOW — report it only where the code explicitly
  re-enables opener access.

______________________________________________________________________

## 6. Logging Hygiene

What must **never** be written: passwords, tokens, session ids, API keys, full
card numbers, government ids, health data, full request bodies of authentication
routes, and the `Authorization` and `Cookie` headers.

| Control | Expected | Failing shape |
|---|---|---|
| `LOG-01` Redaction | Configured in the logger: pino `redact`, winston formats, structlog processors, Rails `filter_parameters`, Django `SENSITIVE_POST_PARAMETERS` | Absent in an application that logs request bodies |
| `LOG-02` Auth routes | Never logged in full | `logger.info(req.body)` on `/login` |
| `LOG-03` Error trackers | Scrubbing hook configured (`beforeSend`, `before_send`, `sendDefaultPii: false`) | Default-on PII forwarding: local variables in stack frames, request bodies, and cookies shipped to a third party |
| `LOG-04` Log injection | User input escaped for newlines before being written | Forged log entries; and, where a log viewer renders entries as HTML, XSS in the tooling |

Personal data in logs is also a retention obligation — cross-reference
`/ray-custodian` `RET-03`. Coverage (what must always be logged) is
`/ray-sentry`'s.

______________________________________________________________________

## 7. Resource Limits

| Control | Expected | Failing shape |
|---|---|---|
| `LIMIT-01` Body size | A limit on every parsing middleware: `express.json({ limit })`, `client_max_body_size`, multipart limits, GraphQL payload size | Unbounded bodies |
| `LIMIT-02` Timeouts (inbound) | Server request timeout and database statement timeout | A query with no statement timeout holding a connection indefinitely |
| `LIMIT-03` Timeouts (outbound) | Timeouts on every third-party call, plus retry budgets and a circuit breaker | **The most commonly missing control in this section.** A hung upstream with no timeout exhausts the connection pool and takes the service down — an outage caused by someone else's incident |
| — | Retry discipline | Retries with backoff and jitter | Immediate retries amplifying an incident into a storm |
| `LIMIT-04` Result sets | Pagination with a maximum `limit`; exports streamed or bounded | An export materializing an entire table; a `limit` parameter the client sets to 1000000 |
| `LIMIT-05` Regex | Linear-time engine (RE2) or a length cap before matching | Nested quantifiers over user input (shared with `/ray-crucible` `REDOS`) |
| — | Fan-out | Bounded parallelism per request | One request spawning unbounded concurrent work |
| — | Media | Dimension and pixel caps before decoding | A decompression bomb: a small file expanding to gigabytes in memory |

______________________________________________________________________

## 8. Caching and Response Correctness

| Control | Expected | Failing shape |
|---|---|---|
| `CACHE-01` Authenticated responses | `Cache-Control: private, no-store` | `public` or a long `max-age` on personalized content, at the app, the CDN, or a reverse proxy — this serves one user's data to another and is a HIGH finding |
| `CACHE-02` `Vary` | Declares every credential-bearing header the response varies by (`Authorization`, `Cookie`, a tenant header) | Absent, so a shared cache mixes users |
| `CACHE-03` Cache keys | Complete: every parameter that changes the body is keyed, and no attacker-settable unkeyed header influences it | Cache poisoning (an unkeyed `X-Forwarded-Host` shaping a cached response) and cache deception (`/account.css` served as account data and cached as a static asset) |
| `CACHE-04` Service workers | Do not cache authenticated responses | A cached personalized response outliving the session on a shared device |

______________________________________________________________________

## 9. Client-Supplied Values In Server Decisions

The core table. For each value the client sends that the server uses in a
decision, the server must recompute or revalidate it.

| Value from the client | Correct server behavior | Ledger id |
|---|---|---|
| Price, discount, tax, shipping, total | Recompute from product ids and the current price table. Never accept a submitted amount — the DevTools edit is a five-second attack | `TRUST-01` |
| Quantity, stock, seat count | Validate against inventory **inside the transaction** | `TRUST-02` |
| `user_id`, `tenant_id`, `role`, `plan` | Take from the authenticated session, never from the payload (overlaps `/ray-turnstile`) | `TRUST-03` |
| Timestamps, expiry, "already paid", state transitions | Server clock and server state only | `TRUST-04` |
| File metadata (size, type, checksum) | Recompute from the stored bytes | `TRUST-05` |
| Currency, locale, feature flags | Validate against an allowlist; never let them alter authorization or price | `TRUST-03` |
| Pagination cursors, sort fields | Validate against an allowlist; never interpolate into a query (`/ray-crucible` `SQLI`) | `VAL-03` |
| Callback and redirect URLs | Allowlist (`/ray-crucible` `REDIR`) | — |
| Webhook payload contents | Verify the signature before trusting anything (`/ray-sentry` `HOOK-01`) | — |

Each unverified entry is a finding anchored at the handler line that consumes
it. Record every value in the ledger's `client_supplied_values` array with
`revalidated` true, false, or unknown — the ones that are fine belong on record
too, or the next pass re-derives them.

______________________________________________________________________

## 10. Control Ledger IDs

Each appears exactly once in `workspace/ledgers/ray-seam.json`.

| ID | Control |
|---|---|
| `VAL-01` | Schema validation on every entrypoint (body, query, params) |
| `VAL-02` | Schemas reject unknown keys |
| `VAL-03` | Numeric, length, enum, and array bounds enforced |
| `VAL-04` | No validation that exists only on the client |
| `ASSIGN-01` | Write paths use an explicit field allowlist |
| `ASSIGN-02` | Privilege, price, and tenant fields not settable from input |
| `ASSIGN-03` | Serializers emit an explicit field set |
| `ERR-01` | Production errors generic, with a correlation id |
| `ERR-02` | No stack traces, debug pages, or source maps in production |
| `ERR-03` | No security-relevant fail-open paths |
| `ERR-04` | Error text is not an existence or state oracle |
| `STORE-01` | No credentials in `localStorage`/`sessionStorage` |
| `STORE-02` | Client caches cleared on logout |
| `BUNDLE-01` | No private secrets in client-exposed build variables |
| `BUNDLE-02` | No production source maps exposing server code |
| `CORS-01` | Explicit origin allowlist; `Origin` never reflected |
| `CORS-02` | Credentials allowed only where required |
| `CORS-03` | Methods, headers, and preflight cache scoped |
| `MSG-01` | `postMessage` receivers validate `event.origin` |
| `MSG-02` | `postMessage` senders pass a specific `targetOrigin` |
| `LOG-01` | Redaction configured for sensitive fields |
| `LOG-02` | Auth-route bodies and credential headers never logged |
| `LOG-03` | Error-tracker scrubbing configured |
| `LOG-04` | Log entries escape user-controlled newlines |
| `LIMIT-01` | Body size limits on all parsers |
| `LIMIT-02` | Request and database statement timeouts set |
| `LIMIT-03` | Outbound call timeouts and retry budgets set |
| `LIMIT-04` | Pagination and export result sets bounded |
| `LIMIT-05` | Regexes over user input linear-time or length-capped |
| `CACHE-01` | Authenticated responses marked `private, no-store` |
| `CACHE-02` | `Vary` declares every credential-bearing header |
| `CACHE-03` | Cache keys complete; no unkeyed attacker-controlled input |
| `CACHE-04` | Service workers do not cache authenticated responses |
| `TRUST-01` | Prices, totals, and discounts recomputed server-side |
| `TRUST-02` | Quantities and stock validated transactionally |
| `TRUST-03` | Identity, role, and flags taken from the session or an allowlist |
| `TRUST-04` | Timestamps and state transitions decided server-side |
| `TRUST-05` | File metadata recomputed from stored bytes |
