# Target profile: web-app

For a browser-facing web application or SaaS (the target the linked video-guide
audits). Selected with `/ray-conductor --profile=web-app`, which injects the two
override blocks below into `workspace/kb/THREAT_MODEL.md` (via `ray-perimeter`) so
the validation and scoring stages treat this as an operated web product — not a
library or a parser.

Without this profile Ray is domain-agnostic and calibrated conservatively: it
dismisses "missing security header" and "no rate limit" as hygiene (ray-arbiter
rules 02/07) and force-LOWs an unproven dependency CVE (ray-gauge
`third_party_reachability`). On a web SaaS those are exactly the findings the owner
most wants — so this profile lifts them into scope.

## Domain skills to run

`ray-prospector` (floor) + `ray-turnstile` + `ray-crucible` + `ray-seam` +
`ray-sentry` + `ray-vault` + `ray-custodian`, plus `ray-manifest` and `ray-terrain`
if the target ships dependencies / IaC, and `ray-citadel` if multi-service. Add
`ray-oracle` if it has an AI feature. Skip `ray-marrow` unless there is native code.

## Review Overrides  (read by ray-arbiter)

```
Review Overrides:
- IN_SCOPE: cors            # rule 02 (missing hygiene) MUST NOT auto-FALSE_POSITIVE an open/credentialed CORS
- IN_SCOPE: security_headers # rule 02 exception for CSP/HSTS/frame on sensitive pages with a real sink
- IN_SCOPE: rate_limit      # rule 07 (resource-exhaustion DoS) MUST NOT auto-dismiss missing auth/OTP/expensive-endpoint limits
- IN_SCOPE: cookie_flags    # missing HttpOnly/Secure/SameSite on a session/auth cookie is a finding, not hygiene
```

A class marked `IN_SCOPE` is still held to the hunting-doctrine bar (concrete
attack, real impact, no earlier layer already blocking it) — the override removes
the *automatic* dismissal, it does not waive the impact test. An open CORS with no
credentials on a public non-sensitive endpoint is still not a finding.

## Calibration Overrides  (read by ray-gauge)

```
Calibration Overrides:
- LIFT_CAP: third_party_reachability   # a known-vulnerable dependency (ray-manifest) is not auto-LOW just because app-reachability isn't proven; score on the CVE's own severity, note reachability
- LIFT_CAP: minor_config_hygiene       # CORS/cookie/header findings that are in scope here are not capped as "minor hygiene"
```

## Rationale (audit → fix trace)

The framework audit found Ray had three rules that actively DISCARD the web-app
classes the video teaches: ray-arbiter rule 02 (CORS/headers → hygiene), rule 07
(rate limit → ignored), and ray-gauge `third_party_reachability` (CVE → LOW). This
profile is the documented, opt-in way to suspend exactly those three for a web
target, using the existing `Calibration Overrides` hook plus a new `Review
Overrides` hook in ray-arbiter. It does not change behavior for any other target.
