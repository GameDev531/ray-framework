# Seam Docket — seam

Vulnerable→safe patterns for `ray-seam`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## CORS misconfiguration — CWE-942 · A05:2021
- **Broken:** `Access-Control-Allow-Origin: *` (or reflecting the `Origin` header)
  together with `Access-Control-Allow-Credentials: true`; a permissive origin
  allow-list matched by substring (`evilcorp.com` matches `corp.com`).
- **Safe:** an exact origin allow-list; credentials only with a specific origin;
  no reflection of arbitrary `Origin`. This is the video's "any site can hit your
  API" door — flag an open credentialed CORS as a real finding, not hygiene.

## Missing / weak CSP — CWE-1021 · A05:2021
- **Broken:** no CSP, or `script-src 'unsafe-inline' 'unsafe-eval'` / `*`, on a page
  that renders user content.
- **Safe:** a restrictive `script-src` (nonces/hashes), `object-src 'none'`,
  `base-uri 'none'`. (Missing CSP with no XSS sink is a hardening note.)

## Host-header injection — CWE-644
- **Broken:** password-reset links, absolute URLs, or cache keys built from the
  attacker-controllable `Host`/`X-Forwarded-Host`.
- **Safe:** an allow-list of canonical hosts; never build security-relevant URLs from
  the request Host.

## Web cache poisoning / deception — CWE-444
- **Broken:** cache key omits a header that changes the response (`X-Forwarded-Host`,
  `Accept-Language`); a path-confusion caches a private response publicly.
- **Safe:** cache key includes every response-affecting input; no private content on
  cacheable routes; correct `Cache-Control`.

## Clickjacking — CWE-1021
- **Broken:** no `X-Frame-Options`/`frame-ancestors` on a state-changing page.
- **Safe:** `frame-ancestors 'none'`/`'self'`.

## Open redirect — CWE-601 · A01:2021
- **Broken:** `?next=`/`?url=`/`?return=` redirected to without validation (enables
  OAuth-token theft and phishing).
- **Safe:** allow-list of relative paths or vetted hosts; never redirect to a raw
  user URL.

## Mass assignment (boundary view) — CWE-915
- Same class ray-turnstile owns for privilege; here, flag any endpoint binding the raw
  request body to a model without a field allow-list.

## What is NOT a finding here

- A missing security header on a page with no sensitive action and no injectable
  content — that is a hardening note (record as INFORMATIONAL), unless combined with
  an actual sink.
- A same-origin-only CORS setup, or a wildcard origin WITHOUT credentials on a public,
  non-sensitive endpoint — assess impact before reporting.
- Redirects to a validated relative path.
