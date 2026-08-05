# Web Surface Baseline — Transport, Headers, Cookies

The graded baseline `/ray-custodian` scores the browser-facing surface against.
Each control states the expected value, the shapes that count as WEAK rather
than PRESENT, and where the control usually lives so "absent" is a conclusion
rather than a guess.

## Table of Contents

- [0. Where To Look Before Declaring A Control Absent](#0-where-to-look-before-declaring-a-control-absent)
- [1. Transport](#1-transport)
- [2. Response Headers](#2-response-headers)
- [3. Cookies and Client Storage](#3-cookies-and-client-storage)
- [4. Content Security Policy In Depth](#4-content-security-policy-in-depth)
- [5. Grading Rules](#5-grading-rules)
- [6. Control Ledger IDs](#6-control-ledger-ids)

______________________________________________________________________

## 0. Where To Look Before Declaring A Control Absent

Headers can be set at five layers. Check all five, outermost first — a control
present at any layer is present, and reporting it as absent because it is not in
the application code is a false positive the validation stages will bounce back.

1. **CDN / edge**: Cloudflare Transform or Response Header Rules (often in
   Terraform: `cloudflare_ruleset`), CloudFront response-headers-policy,
   Fastly VCL, `_headers` (Netlify/Cloudflare Pages), `vercel.json` → `headers`,
   `netlify.toml`, Akamai property JSON.
2. **Reverse proxy / ingress**: `nginx.conf` and `conf.d/*.conf`
   (`add_header`, `ssl_protocols`, `return 301`), `Caddyfile`, Apache
   `.htaccess` / `httpd.conf` (`Header always set`), Traefik middlewares
   (labels or CRDs), Kubernetes Ingress annotations, Envoy/Istio filters.
3. **Framework middleware**: `helmet()` (Express/Fastify/NestJS), Django
   `SECURE_HSTS_SECONDS` / `SECURE_SSL_REDIRECT` / `SESSION_COOKIE_SECURE` /
   `CSP_*` (django-csp), Rails `config.force_ssl` and
   `config.action_dispatch.default_headers`, ASP.NET
   `UseHsts`/`UseHttpsRedirection`, Spring Security `headers()`,
   `next.config.js` → `headers()`, SvelteKit/Nuxt hooks, Laravel middleware.
4. **Per-route / per-response code**: explicit `res.setHeader`,
   `response.headers[...]`, decorators.
5. **Meta tags** (CSP only, and only partially — `<meta http-equiv>` cannot
   express `frame-ancestors`, `report-uri`, or sandbox; treat a meta-only CSP
   as PARTIAL).

**Grep starters** (run under CODE_ROOT, read-only):

```
Strict-Transport-Security|force_ssl|SECURE_SSL_REDIRECT|UseHsts
Content-Security-Policy|contentSecurityPolicy|CSP_DEFAULT_SRC|csp
X-Content-Type-Options|nosniff
X-Frame-Options|frame-ancestors
Referrer-Policy|Permissions-Policy|Feature-Policy
helmet|add_header|Header always set|setHeader
Set-Cookie|res\.cookie|SESSION_COOKIE|cookie_options|SameSite|HttpOnly
ssl_protocols|TLSv1|minimum_protocol_version|SSLProtocol
```

______________________________________________________________________

## 1. Transport

| ID | Control | Expected | WEAK shapes | Notes |
|---|---|---|---|---|
| `TLS-01` | HTTP → HTTPS redirect | 301/308 on every host and path | Redirect on the apex only; redirect that drops the path; app-level redirect that runs after a session cookie was already accepted over plaintext | A `www` vhost or an API subdomain serving plaintext defeats the whole control |
| `TLS-02` | HSTS | `Strict-Transport-Security: max-age=31536000; includeSubDomains` | `max-age` under 15552000 (180 days); `includeSubDomains` missing while subdomains are in scope; HSTS emitted only on some routes | `preload` is a deliberate, hard-to-reverse commitment — recommend it only when every subdomain is HTTPS-only, and never report its absence as a defect on its own |
| `TLS-03` | Protocol floor | TLS 1.2 minimum (`ssl_protocols TLSv1.2 TLSv1.3;`) | Explicit `TLSv1`/`TLSv1.1`/`SSLv3`; `@SECLEVEL=0`; a cipher string pinned to an ancient list | Report the exact config line |
| `TLS-04` | Certificate lifecycle | Automated issuance/renewal (ACME/certbot/managed) | A committed cert with a hand-written renewal note; a cert path with no renewal hook anywhere | Expiry is an availability incident with a security tail (people disable verification to "fix" it) |
| `TLS-05` | Mixed content | Every subresource loaded over HTTPS | `http://` URLs in templates, CSS, bundles, or seed data; `upgrade-insecure-requests` used as a permanent fix rather than a migration aid | Grep `http://` excluding `localhost`, `127.0.0.1`, XML namespaces, and doc comments |
| `TLS-06` | Internal hops | TLS between edge, app, and datastore | Plaintext proxy_pass to an app over a shared network; `sslmode=disable` in a connection string | Datastore transport is scored in depth by `/ray-vault`; note it here and cross-reference |

______________________________________________________________________

## 2. Response Headers

| ID | Header | Expected | WEAK shapes |
|---|---|---|---|
| `HDR-01` | `Content-Security-Policy` | A nonce- or hash-based policy (see §4) | `unsafe-inline` or `unsafe-eval` in `script-src`; `default-src *`; a report-only policy left permanently in report mode with nobody reading the reports |
| `HDR-02` | `X-Content-Type-Options` | `nosniff` | Absent on user-uploaded-content routes specifically — that is where sniffing turns an upload into stored XSS |
| `HDR-03` | Clickjacking protection | `frame-ancestors 'none'` (or an explicit allowlist) in CSP | `X-Frame-Options` only (legacy, still fine as a fallback for old agents but not a substitute); `ALLOWALL`; `ALLOW-FROM` (unsupported by modern browsers) |
| `HDR-04` | `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | Absent on pages whose URLs carry identifiers or tokens — the URL then leaks to every third party the page talks to |
| `HDR-05` | `Permissions-Policy` | Explicitly disable unused powerful features, e.g. `camera=(), microphone=(), geolocation=(), payment=()` | Absent entirely; a policy that enables features the app never uses |
| `HDR-06` | `Cross-Origin-Opener-Policy` | `same-origin` on authenticated pages | Absent where the app opens or is opened by third-party windows |
| `HDR-07` | `Cross-Origin-Resource-Policy` | `same-origin` (or `same-site`) on private resources | Absent on endpoints returning personal data |
| `HDR-08` | `Cache-Control` on authenticated responses | `private, no-store` | `public` or a long `max-age` on a personalized response — a shared cache or CDN will serve one user's data to another (see also `/ray-seam` cache poisoning) |
| `HDR-09` | Server/version disclosure | Suppressed | `Server: nginx/1.18.0`, `X-Powered-By`, framework debug headers — low severity, but free reconnaissance |
| `HDR-10` | `Clear-Site-Data` on logout | `"cookies", "storage"` where the app stores client-side state | Logout that only deletes the server session, leaving tokens and cached personal data in the browser |

______________________________________________________________________

## 3. Cookies and Client Storage

| ID | Control | Expected | WEAK shapes |
|---|---|---|---|
| `COOKIE-01` | `HttpOnly` | Set on every cookie carrying a session or token | Any auth cookie readable from JavaScript — this is what converts a contained XSS into account takeover |
| `COOKIE-02` | `Secure` | Set on every cookie on an HTTPS origin | Missing on the session cookie; set in production config only, absent in the default that a misconfigured deploy will use |
| `COOKIE-03` | `SameSite` | `Lax` minimum for session cookies; `Strict` where no cross-site entry flow is needed | `SameSite=None` without a stated third-party embed requirement; `None` without `Secure` (browsers reject it, so the cookie silently stops working — a correctness bug and a security one) |
| `COOKIE-04` | Scope | Narrowest `Domain` and `Path` that work | `Domain=.example.com` on a session cookie when no subdomain needs it — a subdomain takeover or a vulnerable marketing site then reaches the main session |
| `COOKIE-05` | Lifetime and revocation | Short-lived session cookie plus server-side invalidation | Multi-year `Max-Age` with a stateless token and no denylist: logout cannot actually log anyone out |
| `COOKIE-06` | Prefixes | `__Host-` for session cookies where the deployment allows it | Not a defect on its own; recommend it in `mitigation`. `__Host-` implies `Secure`, `Path=/`, and no `Domain`, which makes several of the above unforgeable by a sibling subdomain |
| `COOKIE-07` | Signing/encryption | Session data signed (and encrypted if it carries anything beyond an opaque id) | A cookie holding a JSON user object with a role field and no signature — trivially forged. Route to `/ray-turnstile` as well |
| `STORE-01` | `localStorage` / `sessionStorage` | No personal data, no tokens | Personal data cached client-side and never cleared on logout; tokens in `localStorage` (primarily `/ray-seam`) |
| `STORE-02` | Service worker / cache API | No authenticated responses cached | A service worker caching personalized JSON that survives logout and is served to the next user of a shared device |

______________________________________________________________________

## 4. Content Security Policy In Depth

A CSP that exists but allows `unsafe-inline` in `script-src` blocks almost no
real XSS. Grade the policy, do not just detect the header.

**Target shape** (nonce-based strict CSP):

```
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic' https: 'unsafe-inline';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  require-trusted-types-for 'script';
  report-uri /csp-report
```

Notes for the auditor:

- `'unsafe-inline'` **after** a nonce and `'strict-dynamic'` is deliberate
  backwards compatibility: browsers that understand nonces ignore it. Do not
  report that combination as a weakness. `'unsafe-inline'` **without** a nonce
  or hash is the real defect.
- `'strict-dynamic'` makes host allowlists irrelevant in supporting browsers,
  which is the point: allowlists leak through JSONP endpoints and permissive
  CDNs. A policy that is a long host allowlist with no nonce is WEAK.
- The nonce must be **per response and unpredictable**. A nonce baked into a
  static asset, reused across responses, or derived from a fixed string is
  equivalent to `unsafe-inline` — check where the nonce is generated.
- `object-src 'none'` and `base-uri 'none'` are cheap and close real bypasses
  (Flash-era plugin injection and `<base>` hijacking of relative script URLs).
- `frame-ancestors` is the modern clickjacking control and, unlike
  `X-Frame-Options`, supports multiple origins.
- `report-uri`/`report-to` with nobody consuming the reports is not a defect,
  but a *report-only* policy that has been in report-only mode for a long time
  (check VCS history in the LIVE repo per Block A step 5) means the control is
  not enforced — report it as PARTIAL.
- Framework caveat: `helmet()`'s default CSP is deliberately conservative and
  often disabled wholesale (`contentSecurityPolicy: false`) during development
  and then shipped. Grep for that exact disabling.

______________________________________________________________________

## 5. Grading Rules

Map each control to exactly one ledger state:

- **PRESENT** — enforced at some layer you read, with a value meeting the
  expectation above. Cite `file:line`.
- **PARTIAL** — enforced but weakened (short `max-age`, `unsafe-inline`, one
  vhost of several, report-only). Cite the line and quote the weakening token.
  PARTIAL normally warrants a finding; severity is usually MEDIUM or LOW.
- **ABSENT** — searched all five layers of §0 and found nothing. Cite the
  composition root where it would go, and list the layers you checked in the
  finding description.
- **NOT_APPLICABLE** — the surface does not exist (e.g. no cookies at all in a
  pure machine-to-machine API; no browser surface in a CLI tool). State why.
- **UNKNOWN** — the control could plausibly be enforced by infrastructure
  outside this repository (a CDN configured by hand, an ingress owned by
  another team). Write the finding with `"status": "NEEDS_RESEARCH"` and name
  the artifact that would resolve it.

**Severity defaults for this baseline** (before `ray-gauge` caps):

| Situation | Default |
|---|---|
| Session cookie without `HttpOnly` or without `Secure` | HIGH |
| No HTTPS enforcement / plaintext session transport | HIGH |
| Authenticated response cached publicly | HIGH |
| CSP absent or `unsafe-inline` on a page that renders user-controlled content | MEDIUM (HIGH if an XSS sink is confirmed nearby — coordinate with `/ray-crucible`) |
| `SameSite` absent on a session cookie in a cookie-authenticated app | MEDIUM |
| Missing `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP | LOW–MEDIUM, no exploit path claimed |
| Server version disclosure | LOW |

Never mark a header finding CRITICAL. A missing hardening header is a
defense-in-depth gap; `ray-gauge` will cap it anyway, and inflating it here just
costs the pipeline validation time.

______________________________________________________________________

## 6. Control Ledger IDs

`TLS-01`…`TLS-06`, `HDR-01`…`HDR-10`, `COOKIE-01`…`COOKIE-07`, `STORE-01`,
`STORE-02` — each appears exactly once in
`workspace/ledgers/ray-custodian.json`, alongside the privacy control ids from
`privacy_docket.md` §10.
