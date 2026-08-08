# Identity Docket — Credentials, Sessions, Tokens, Recovery

The control set `/ray-turnstile` scores authentication against. Each section
gives the expected implementation, the failing shapes to grep for, and the
severity default before `ray-gauge` applies its caps.

## Table of Contents

- [1. Password Storage](#1-password-storage)
- [2. Password Policy](#2-password-policy)
- [3. Sessions](#3-sessions)
- [4. Self-Contained Tokens (JWT)](#4-self-contained-tokens-jwt)
- [5. MFA and Anti-Automation](#5-mfa-and-anti-automation)
- [6. Account Recovery, Invites, and Enumeration](#6-account-recovery-invites-and-enumeration)
- [7. Federated Identity (OAuth 2.0 / OIDC / SAML)](#7-federated-identity-oauth-20--oidc--saml)
- [7b. Secrets And Critical-Operation Integrity](#7b-secrets-and-critical-operation-integrity)
- [8. Control Ledger IDs](#8-control-ledger-ids)

______________________________________________________________________

## 1. Password Storage

**Expected.** `argon2id` is the current default recommendation; `scrypt` and
`bcrypt` remain acceptable. OWASP's minimum Argon2id configuration is 19 MiB of
memory, 2 iterations, and 1 degree of parallelism; higher memory (64–128 MiB)
with 3+ iterations is the security-conscious setting where the latency budget
allows. For bcrypt, a work factor of at least 10 is the floor and 12+ is the
common production setting. PBKDF2 is acceptable only where FIPS compliance
forces it, and then with a high iteration count and HMAC-SHA-256 or stronger.

```js
// expected shape
const argon2 = require('argon2');
const hash = await argon2.hash(password, { type: argon2.argon2id });  // salt is generated per hash
const ok   = await argon2.verify(hash, submitted);                    // constant-time internally
```

| Failing shape | Why it matters | Severity |
|---|---|---|
| `md5(`, `sha1(`, `sha256(password)`, `hashlib.sha256`, `crypto.createHash` on a password | GPU-crackable at billions of guesses per second; a database dump is a full credential dump | HIGH |
| No salt, or a single global/static salt | Rainbow tables and cross-account cracking become viable | HIGH |
| A single unkeyed HMAC or a hand-rolled KDF | Not memory-hard, not iterated; the same failure with more ceremony | HIGH |
| Reversible encryption of passwords | Any key compromise yields plaintext for every user; also breaks the expectation that even operators cannot read passwords | HIGH |
| bcrypt with cost < 10, Argon2 with < 19 MiB memory | Weakens the only barrier a dump has to cross | MEDIUM |
| No rehash-on-login when parameters were raised | Old weak hashes persist forever | LOW–MEDIUM |
| `==` / `!=` comparison of a hash, MAC, or token | Timing oracle; use `crypto.timingSafeEqual`, `hmac.compare_digest`, `subtle.ConstantTimeCompare` | MEDIUM |
| bcrypt with no explicit length cap | bcrypt silently truncates at 72 bytes, so a long passphrase is weaker than the user believes, and pre-hashing without care introduces a null-byte truncation bug | LOW–MEDIUM |

**Also check:** that the password is never logged (grep the auth route for
logger calls that dump the request body), never returned by a serializer, and
never included in an error message or an exception's local variables sent to an
error tracker.

______________________________________________________________________

## 2. Password Policy

NIST SP 800-63B (revision 4, finalized July 2025) is the reference the modern
consensus follows:

| Requirement | Expected | Failing shape |
|---|---|---|
| Minimum length | 8 characters when the password is one factor in MFA; 15 when a password is the only authenticator | A 6-character minimum; a 4-digit PIN as the sole factor |
| Maximum length | Accept at least 64 characters | A 16-character cap; silent truncation |
| Character set | Accept all printing ASCII, spaces, and Unicode | Rejecting spaces or symbols; stripping characters before hashing |
| Composition rules | None | "Must contain 1 uppercase, 1 digit, 1 symbol" — pushes users to `Password1!` and adds no real entropy |
| Periodic rotation | None, absent evidence of compromise | Forced 90-day expiry — degrades password quality in practice |
| Breach screening | Check against a list of compromised and commonly used passwords | Absent. Use a k-anonymity range query (send the first 5 hex chars of the SHA-1, compare the suffixes locally) so the full password or full hash never leaves the system |
| Hints and knowledge-based answers | Not offered | "Security questions" — publicly discoverable answers, treated as a full credential |
| Paste and password managers | Allowed | `onpaste="return false"` on password fields |

______________________________________________________________________

## 3. Sessions

| Control | Expected | Failing shape | Severity |
|---|---|---|---|
| Identifier generation | CSPRNG, ≥128 bits (`crypto.randomBytes`, `secrets.token_urlsafe`) | `Math.random()`, `uuid.v1()` (time+MAC based), an incrementing id, a hash of the user id | HIGH |
| Regeneration on privilege change | New session id on login, on role elevation, on impersonation start/stop | The pre-login session id survives authentication → session fixation | MEDIUM–HIGH |
| Server-side invalidation | Logout deletes or denylists the session record | Logout only clears the client cookie; the token stays valid until expiry | MEDIUM–HIGH |
| Invalidation on password change / reset | All other sessions terminated | A stolen session survives the victim's password change — this is the control that ends an incident | HIGH |
| Idle timeout | Present and proportionate to the data | No idle timeout on an admin console | LOW–MEDIUM |
| Absolute timeout | Present | A session valid for a year | LOW–MEDIUM |
| Concurrent session visibility | The user can see and revoke active sessions | Absent | LOW |
| Session data integrity | Signed (and encrypted if it holds more than an opaque id) | A cookie containing `{"user":1,"role":"admin"}` with no signature — trivially forged | HIGH |
| Binding | Optionally bound to a client characteristic | Not a defect when absent; note it in `mitigation` only |

______________________________________________________________________

## 4. Self-Contained Tokens (JWT)

RFC 8725 (JSON Web Token Best Current Practices) is the checklist. Run every
line of it against the **verification** code — the signing code is rarely the
problem.

| # | Check | Failing shape | Severity |
|---|---|---|---|
| 1 | Algorithm pinned at verification | `jwt.verify(token, key)` with no `algorithms` option; a library that reads `alg` from the header and trusts it | HIGH |
| 2 | `alg: none` rejected | Any code path that accepts an unsigned token | CRITICAL-adjacent; report HIGH with a described forgery path |
| 3 | No HS/RS confusion | An RS256 verifier that also accepts HS256 lets an attacker sign with the **public** key as the HMAC secret | HIGH |
| 4 | Key strength | An HMAC secret shorter than 256 bits, or a dictionary word — offline crackable from a single captured token | HIGH |
| 5 | `exp` validated, and short | No expiry, or an access token valid for months | MEDIUM–HIGH |
| 6 | `nbf` / `iat` sanity, bounded clock skew | Unbounded skew tolerance | LOW |
| 7 | `iss` validated | Any issuer's token accepted | HIGH |
| 8 | `aud` validated | A token minted for another service or client accepted here (token substitution) | HIGH |
| 9 | `typ` / explicit typing where several token kinds share an issuer | A refresh token accepted where an access token is expected; an ID token used as an access token | MEDIUM–HIGH |
| 10 | `kid` handled safely | `kid` used as a filesystem path (traversal), a URL (SSRF), or interpolated into SQL | HIGH |
| 11 | `jku` / `x5u` not fetched from attacker-controlled URLs | The verifier fetches the key from a URL inside the token | HIGH |
| 12 | Claims not trusted before verification | Decoding the payload to route or authorize, then verifying (or never verifying) | HIGH |
| 13 | Revocation story | A stateless token with a long TTL, no denylist, and no key rotation: logout, ban, and role downgrade are all cosmetic | MEDIUM–HIGH |
| 14 | Refresh-token rotation and reuse detection | A refresh token reusable forever; no family invalidation on replay | MEDIUM–HIGH |
| 15 | Refresh tokens stored hashed | Plaintext refresh tokens in the database — a dump is a persistent session dump | MEDIUM |
| 16 | No sensitive data in the payload | JWTs are signed, not encrypted: anyone can read the claims. Personal data in a token is an exposure (cross-reference `/ray-custodian`) | MEDIUM |

**Where to look:** the verify call itself, plus any middleware that "pre-parses"
a token for logging or routing. The pre-parse is often where an unverified claim
gets promoted into the request context.

### Signing-crypto misuse behind the token

The RFC 8725 checklist covers the token format; these cover the signature math,
where identity is minted. Flag them when the app signs its own tokens/cookies
rather than delegating to a vetted library's defaults:

- **ECDSA/DSA `k` reuse or bias** — a per-signature nonce that is fixed, low
  entropy, or reused across two signatures recovers the private key, and then
  every token is forgeable. The safe pattern is deterministic `k` (RFC 6979) or a
  CSPRNG the library manages. Home-rolled signing is the tell.
- **HMAC key strength** — an HMAC secret shorter than 256 bits or a dictionary
  word is offline-crackable from one captured token (also RFC 8725 #4).
- **Non-constant-time signature/MAC comparison** — cross-reference `/ray-crucible`
  `TIMING`.
- **RSA signature with a weak key or `NoPadding`** — RSA < 2048, or verification
  that does not check the padding structure.

The fuller catalog of protocol-crypto misuse at rest and in transit (nonce/IV
reuse in AEAD, padding oracles, MAC-then-encrypt, certificate-validation depth)
lives in `/ray-vault`'s `datastore_hardening.md` §3 — report a signing defect here
and an at-rest/in-transit defect there; `/ray-condenser` merges.

______________________________________________________________________

## 5. MFA and Anti-Automation

### MFA

| Control | Expected | Failing shape |
|---|---|---|
| Availability | TOTP and/or WebAuthn (passkeys) offered | No second factor at all on an application holding financial or sensitive data |
| Admin enforcement | Required for privileged roles | Optional for owners and admins |
| Enrollment integrity | Secret generated server-side by a CSPRNG, stored encrypted, confirmed with a code before activation | Secret stored plaintext; activation without confirming a code (locks the user out and proves nothing) |
| Verification | Narrow time window (±1 step), used codes burned | A ±10-step window; codes replayable within the window |
| Recovery codes | Generated once, single-use, stored hashed | Plaintext codes; codes that survive use |
| Rate limiting on the second factor | Present | Unlimited 6-digit guesses — a 10⁶ space falls quickly |
| Bypass paths | None | Reset flow that skips MFA; a legacy API path that ignores it; "remember this device" with no expiry, no binding, and a guessable token |
| Phishing resistance | WebAuthn offered where the threat model warrants | Not a defect on its own; note it in `mitigation` |

### Anti-automation on authentication endpoints

Two independent dimensions, and both are needed:

- **Per account**: stops password spraying against one target (e.g. 5 failures
  per 15 minutes per account, then backoff).
- **Per source IP / ASN / device**: stops one host enumerating many accounts.
  A per-IP-only limiter is defeated by a residential proxy pool; a
  per-account-only limiter is defeated by one guess against a million accounts.

Also check: the counter's storage (an in-process map is per-instance and
therefore ineffective behind a load balancer — this is a very common real
defect), whether the limiter is applied to *all* auth entrypoints (login, reset,
MFA verify, token refresh, GraphQL login mutation, mobile endpoint), and whether
failures are logged for alerting (cross-reference `/ray-sentry`).

______________________________________________________________________

## 6. Account Recovery, Invites, and Enumeration

### Reset tokens

| Control | Expected | Failing shape | Severity |
|---|---|---|---|
| Entropy | ≥128 bits from a CSPRNG | A 6-digit code with no rate limit; a token derived from user id + timestamp; a `uuid.v1()` | HIGH |
| Storage | Hashed at rest | Plaintext tokens in a `password_resets` table — a read-only SQLi or a dump becomes account takeover for every pending reset | MEDIUM–HIGH |
| Lifetime | 15–60 minutes | No expiry | MEDIUM |
| Single use | Invalidated on use and on password change | Reusable link (still in the mailbox, still works) | MEDIUM |
| Delivery | To the stored address only | Address taken from the request body | HIGH |
| Session effect | All sessions invalidated after reset | Attacker session survives the victim's recovery | HIGH |
| Response | Identical whether or not the account exists | "No user with that email" | LOW–MEDIUM |
| Host header | Reset URL built from configuration | URL built from the `Host`/`X-Forwarded-Host` header → password-reset poisoning sends the token to the attacker | HIGH |

### Invites and onboarding privilege

| Control | Expected | Failing shape |
|---|---|---|
| Default role | Least privilege (viewer/member) | New members join as admin or owner by default |
| Invite scope | Bound to one email address and one tenant | A token that any recipient can redeem; a token redeemable into a different tenant |
| Expiry | Present | Invites valid indefinitely |
| Role changes | Explicit, audited | Silent promotion with no audit event |
| Domain-based auto-join | Only for verified domains, and opt-in | Any address on a public mail domain auto-joining an organization |

### Enumeration

Compare, across existing and non-existing accounts: response body, status code,
redirect target, response time (a hash is computed for a real user and skipped
for a fake one — that difference is measurable; the fix is to perform a dummy
verification), and any side effect the client can observe. Signup and invite
flows leak just as readily as login.

______________________________________________________________________

## 7. Federated Identity (OAuth 2.0 / OIDC / SAML)

| Control | Expected | Failing shape | Severity |
|---|---|---|---|
| `state` parameter | Generated per request, bound to the session, verified on callback | Absent or unverified → login CSRF; the victim ends up logged into the attacker's account | MEDIUM–HIGH |
| PKCE | Used for public clients (SPA, mobile), `S256` | Absent, or `plain` | MEDIUM–HIGH |
| Redirect URI matching | Exact string match against a registered list | Prefix or wildcard matching, open-redirect chaining, or a path-traversal-tolerant comparison → authorization code theft → account takeover | HIGH |
| ID token validation | Signature, `iss`, `aud`, `exp`, and `nonce` all verified | Trusting the ID token payload without verification; accepting a token minted for another client | HIGH |
| Account linking | Only on a **verified** email, or with an explicit confirmation step | Auto-linking by unverified email lets an attacker with an IdP account claim an existing local account | HIGH |
| Scope handling | Minimum scopes; downstream tokens not over-privileged | Requesting broad provider scopes the app does not use | LOW |
| SAML | Signature verified over the assertion, `Recipient`/`Audience`/`NotOnOrAfter` checked, XML canonicalization handled by a maintained library | Home-rolled XML parsing (signature wrapping), unsigned assertions accepted | HIGH |

______________________________________________________________________

## 7b. Secrets And Critical-Operation Integrity

### Secrets

| Control | Expected | Failing shape |
|---|---|---|
| No committed secrets | Nothing in source, config, notebooks, fixtures, CI files, Dockerfiles, or manifests — **and nothing in VCS history**, which is checked via the Block A step 5 carve-out in the live repo root | A private key, cloud credential, or signing secret in any of the above. A secret removed in a later commit is still exposed |
| No insecure defaults | The process refuses to start without the secret | `process.env.JWT_SECRET \|\| 'dev'`, `SECRET_KEY = "changeme"`, a committed `.env.example` whose values are the real ones. **The fallback is the finding**, because a misconfigured deploy silently takes it and nothing appears broken |
| Key strength | ≥256 bits from a CSPRNG for signing keys | A dictionary word or a short string — offline-crackable from one captured token |
| Runtime sourcing | Fetched at startup from a secret manager via a workload identity | Static keys on disk or baked into an image layer |
| Rotation | Key id in the token plus an overlap window, so rotation does not invalidate every session at once | No rotation path — which guarantees a leaked key stays in use |
| Scope | One secret per consumer | One shared secret, so revocation is an outage everywhere |

**Every leaked-secret finding must state in `mitigation` that the credential is
compromised and must be rotated.** Removing it from history is housekeeping, not
remediation — and a reader who takes away the wrong lesson is left with a live
credential they believe is dead.

### Critical-operation integrity

Duplicate execution of a value-creating operation is a security defect, not just
a correctness one. Enumerate the operations where running twice creates value or
crosses a limit — coupon redemption, balance withdrawal, credit consumption,
seat assignment, invite acceptance, plan upgrade, referral bonus, quota check —
and check each for one of these:

| Control | Shape |
|---|---|
| Transaction with a lock | `BEGIN; SELECT … FOR UPDATE; …; COMMIT` |
| Atomic conditional write | `UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1` |
| Database constraint | A unique index on `(user_id, coupon_id)` — enforcement below the application |
| Idempotency key | A client-supplied key stored with the result, so a retry returns the first outcome |

The failing shape is a `SELECT` to check, then a separate `UPDATE` to act, with
no transaction around them: a time-of-check/time-of-use window that a double
click or a concurrent request walks straight through. Report it with both line
numbers.

Verify the constraint lives in the **database**, not only in application code —
an in-process mutex or a cached flag is defeated by a second instance, which is
exactly the configuration production runs in. Also note state machines that
allow a backwards transition (refund after refund, activation after
cancellation).

______________________________________________________________________

## 8. Control Ledger IDs

Each id appears exactly once in `workspace/ledgers/ray-turnstile.json`.

| ID | Control |
|---|---|
| `CRED-01` | Passwords hashed with argon2id/scrypt/bcrypt at adequate parameters |
| `CRED-02` | Per-password salt; constant-time verification |
| `CRED-03` | Rehash-on-login when parameters change |
| `CRED-04` | Password policy: length-based, no composition rules, no forced rotation |
| `CRED-05` | Breached-password screening |
| `CRED-06` | Passwords never logged, serialized, or sent to error trackers |
| `SESS-01` | Session ids from a CSPRNG with ≥128 bits |
| `SESS-02` | Session regenerated on privilege change |
| `SESS-03` | Server-side invalidation on logout |
| `SESS-04` | All sessions invalidated on password change/reset |
| `SESS-05` | Idle and absolute timeouts configured |
| `SESS-06` | Session payload signed/encrypted |
| `TOKEN-01` | Algorithm pinned at verification; `alg: none` rejected |
| `TOKEN-02` | No HS/RS confusion; key strength adequate |
| `TOKEN-03` | `exp`, `iss`, `aud` validated |
| `TOKEN-04` | `kid`/`jku` handled without traversal, SSRF, or injection |
| `TOKEN-05` | Revocation path exists (denylist or short TTL + rotation) |
| `TOKEN-06` | Refresh tokens rotated, hashed, with reuse detection |
| `TOKEN-07` | No sensitive data in token payloads |
| `MFA-01` | Second factor available |
| `MFA-02` | Enforced for privileged roles |
| `MFA-03` | Enrollment and verification integrity (encrypted secret, narrow window, replay burn) |
| `MFA-04` | Recovery codes single-use and hashed |
| `MFA-05` | No bypass paths (reset, legacy API, remember-device) |
| `AUTOM-01` | Per-account rate limiting on authentication |
| `AUTOM-02` | Per-source rate limiting on authentication |
| `AUTOM-03` | Limiter state shared across instances |
| `AUTOM-04` | Authentication failures logged for alerting |
| `RECOV-01` | Reset token entropy, hashing, expiry, single use |
| `RECOV-02` | Reset URL built from configuration, not request headers |
| `RECOV-03` | Sessions invalidated after recovery |
| `ENUM-01` | Uniform responses and timing across auth flows |
| `INV-01` | Least-privilege default role for new members |
| `INV-02` | Invite tokens scoped, expiring, single-tenant |
| `INV-03` | Role changes audited |
| `FED-01` | `state` verified on OAuth callback |
| `FED-02` | PKCE (S256) for public clients |
| `FED-03` | Exact redirect-URI matching |
| `FED-04` | ID token / SAML assertion fully validated |
| `FED-05` | Account linking requires verified email |
| `IMP-01` | Impersonation gated, time-boxed, and audit-logged |
| `SEC-01` | No secrets committed to source or history |
| `SEC-02` | No insecure default/fallback secret values |
| `SEC-03` | Secrets sourced at runtime from a manager via workload identity |
| `SEC-04` | Key rotation possible without mass session invalidation |
| `RACE-01` | Critical operations protected by lock, unique constraint, or idempotency key |
| `RACE-02` | Constraints enforced in the database, not only in application code |
