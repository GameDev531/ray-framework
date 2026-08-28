# Sentry Docket — sentry

Vulnerable→safe patterns for `ray-sentry`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## Missing rate limiting — CWE-770 · API4:2023
- **Broken:** login, OTP, password-reset, search, export, or any DB/LLM-backed
  endpoint with no per-principal rate or concurrency limit and no gateway limit in
  front. Enables credential stuffing, enumeration, and cost-amplification.
- **Safe:** a documented limit at app or gateway layer keyed per principal/IP, with
  lockout/backoff on auth. This is the video's "one request can cost you money" door
  — a genuinely unlimited expensive endpoint is a finding, not hygiene. (If limiting
  is at the CDN by design, record it and move on.)

## Exposed internal / debug endpoints — CWE-489 · A05:2021
- **Broken:** `/debug`, `/actuator`, `/metrics`, `/admin`, `/status`, `/env`,
  `/.env`, `/swagger` reachable unauthenticated in production; debug/dev mode toggled
  by a query param or header.
- **Safe:** internal routes bound to loopback/authenticated; debug gated by
  server-side config that the client can't flip.

## Unsigned / unverified webhooks — CWE-345
- **Broken:** an inbound webhook (payment, VCS, CI) whose signature is not verified,
  or verified with a non-constant-time compare, or replayable (no timestamp/nonce).
- **Safe:** HMAC signature verified in constant time, timestamp window, replay cache.

## Shadow / undocumented APIs — API9:2023
- **Broken:** old `/v1` still live and unpatched next to `/v2`; internal endpoints the
  client never calls but the server still serves.
- **Safe:** deprecated versions removed or gated; the served surface matches the
  documented one.

## Verbose errors — CWE-209 · A05:2021
- **Broken:** production responses returning stack traces, SQL errors, internal
  hostnames/paths, framework version banners.
- **Safe:** generic error responses in production; detail only in server logs.

## What is NOT a finding here

- App-level rate limiting "missing" when a gateway/CDN enforces it by design — verify
  the deployment before flagging.
- A debug endpoint that is genuinely unreachable in production builds (confirm, don't
  assume — coordinate with ray-magistrate on viability).
- Error verbosity in a development-only configuration.
