# Turnstile Docket — turnstile

Vulnerable→safe patterns for `ray-turnstile`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## IDOR / BOLA — CWE-639 · A01:2021 · API1:2023
- **Broken:** `GET /orders/{id}` (or id in body) fetched without checking the caller
  owns it; sequential/guessable ids; ownership checked in the UI but not the API.
- **Safe:** every object access re-derives the owner from the *session*, not the
  request, and asserts ownership/tenant on the server for every path.

## Broken function-level authz (BFLA) — CWE-285 · API5:2023
- **Broken:** admin/privileged routes gated only by "is authenticated", or by a
  client-sent role, or missing on an alternate verb/endpoint (`PUT` guarded, `PATCH`
  not).
- **Safe:** server-side role/permission check on every privileged action, consistent
  across all verbs and aliases.

## Mass assignment to privilege — CWE-915 · API3:2023
- **Broken:** binding request body straight to a model lets `role`/`is_admin`/
  `tenant_id`/`price` be set by the client.
- **Safe:** explicit allow-list of bindable fields; server sets privileged fields.

## Authentication weaknesses — CWE-287 · A07:2021
- **Broken:** plaintext/`md5`/`sha1` password storage; missing constant-time compare;
  no lockout/rate limit on login (→ ray-sentry); user-enumerable reset/login;
  predictable reset tokens; reset token not invalidated after use.
- **Safe:** `bcrypt`/`argon2`/`scrypt`, constant-time comparison, generic auth
  errors, high-entropy single-use expiring tokens.

## Session & JWT/OAuth — CWE-384 / CWE-347 · A07:2021 · API2:2023
- **Broken:** session id not rotated on privilege change; JWT `alg:none` or HS/RS
  confusion; signature not verified; `exp`/`aud`/`iss` unchecked; secret guessable;
  OAuth `state` missing (CSRF), open `redirect_uri`, code interceptable.
- **Safe:** rotate on login/elevation, pin the algorithm and verify the signature,
  validate all standard claims, enforce `state` and exact `redirect_uri` match.

## Tenant isolation — CWE-1230 · API1:2023
- **Broken:** a query missing its `tenant_id` filter; a cache/key shared across
  tenants; an id space global instead of per-tenant.
- **Safe:** tenant scoping enforced at the data-access layer for every query, proven
  not per-endpoint.

## MFA / step-up — CWE-306
- **Broken:** MFA enforced on login but not on token refresh or a sensitive action;
  a "remember device" that never re-checks.
- **Safe:** step-up on sensitive actions; MFA state bound to the session.

## What is NOT a finding here

- Admin-can-do-admin-things where the threat model trusts admins by design.
- A route that requires prior authentication to reach — note the requirement, don't
  rate it as a bypass, unless the auth check itself is defeatable.
- Rate limiting handled at the gateway/CDN (coordinate with ray-sentry).
