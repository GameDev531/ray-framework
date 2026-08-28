# Custodian Docket — custodian

Vulnerable→safe patterns for `ray-custodian`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## Cookie flags — CWE-1004 / CWE-614 · A05:2021
- **Broken:** a session/auth cookie missing `HttpOnly` (JS-readable), `Secure`
  (sent over HTTP), or `SameSite` (CSRF exposure). The video's cookie door.
- **Safe:** `HttpOnly; Secure; SameSite=Lax|Strict` on session/auth cookies. (A
  non-sensitive cookie readable by JS by design is not a finding — check what it holds.)

## TLS / transport — CWE-319 · A02:2021
- **Broken:** an HTTP-only endpoint, no HSTS, mixed content, downgrade-able TLS, cert
  validation disabled in a client (`verify=False`).
- **Safe:** HTTPS enforced with HSTS; TLS ≥1.2; certificate validation on.

## PII in logs / URLs / responses — CWE-532 / CWE-359 · A09:2021
- **Broken:** passwords, tokens, full card/SSN, or emails logged; secrets in query
  strings (cached, in referer, in history); an API returning more fields than the UI
  needs (over-fetch).
- **Safe:** PII/secret redaction in logs; sensitive data in POST bodies not URLs;
  response DTOs return only needed fields.

## Data retention & subject rights — A09:2021 / privacy
- **Broken:** no deletion path; "deleted" data still in backups/exports/search;
  export/delete endpoints that leak or over-collect.
- **Safe:** retention limits enforced; data-subject export/delete implemented and
  scoped to the requester.

## Consent & third-party leakage
- **Broken:** PII sent to analytics/third parties before consent; trackers loading on
  a consent-gated page.
- **Safe:** consent gates data sharing; third-party calls audited for what they carry.

## What is NOT a finding here

- A missing security header on a static, non-sensitive page — hardening note.
- A non-sensitive cookie without HttpOnly where JS must read it by design.
- PII in a debug log path that is disabled in production (confirm with ray-magistrate).
