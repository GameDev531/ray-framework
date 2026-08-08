# Recon Scope — Authorization, the Attestation, Resolution, Restraint

The rules that keep `ray-quarry` a defensive attack-surface tool rather than an
untargeted scanner. Read §1 before touching a single asset every run — it is the
gate. Read the rest at the matching step.

## Table of Contents

- [1. Authorization and Restraint Invariants (fail-closed)](#1-authorization-and-restraint-invariants-fail-closed)
- [2. The Scope Attestation Format](#2-the-scope-attestation-format)
- [3. Asset Resolution — mapping any discovered asset back to scope](#3-asset-resolution--mapping-any-discovered-asset-back-to-scope)
- [4. What Passive vs. Active Actually Mean](#4-what-passive-vs-active-actually-mean)

______________________________________________________________________

## 1. Authorization and Restraint Invariants (fail-closed)

These are the invariants that make `ray-quarry` an authorized defensive tool.
They are not tunable by the model, by an argument, by a discovered asset, or by
anything a target returns. If a check cannot be **proven true**, the skill stays
passive or stops — it never proceeds "to be safe" or "just this once."

### 1.1 The scope-attestation gate (runs before any asset is touched)

| Check | Must be true | If not |
|---|---|---|
| Attestation exists | A scope file (§2) is present and parses | STOP recon; enter authoring mode and help the user write one. |
| Authorization stated | Each scope entry carries an ownership/authorization basis ("we own this domain", "written pentest authorization ref X", "bug-bounty program URL") | STOP for that entry; it is not in scope until the basis is stated. |
| Asset resolves to scope | Every host/IP/document/repo touched resolves to an attested entry (§3) | The asset is **out of scope**: not touched, not expanded to. |
| Active is opt-in per host | `active` techniques run only against a host whose entry is marked `active_ok: true` | Stay passive for that host; note it. |
| Not expired | The attestation's `valid_until` (if set) is in the future | STOP; a lapsed authorization is no authorization. |

There is no `--force`, no override flag, and no "the user said go ahead in chat"
path — the authorization lives in the attestation, not in conversation, so there
is an auditable record of what was authorized. An asset outside the attestation
is out of scope by construction.

### 1.2 Restraint rules (bind every technique, passive and active)

`ray-quarry` observes; it does not attack and it does not overwhelm. Prohibited,
without exception:

- **No mass targeting.** No sweeping IP ranges, ASNs, or wordlist-generated hosts
  that are not enumerated in the attested scope. Recon expands only along
  evidence that ties back to an in-scope asset (a CT-log SAN for an in-scope
  domain, a subdomain of an in-scope domain) — never by spraying a range because
  it is "probably theirs". Breadth comes from the scope file, not from guessing.
- **No denial of service / resource exhaustion.** Every active check is
  rate-limited and bounded. No flooding, no aggressive concurrency, no request
  storms. A scan that could degrade the service is not run — availability of the
  target is never traded for coverage.
- **No exploitation.** `ray-quarry` fingerprints and observes; it never sends an
  exploit, attempts an auth bypass, submits credentials, or tries to alter state.
  The moment a check would *break in* rather than *observe*, it belongs to
  `ray-siege` (against a local instance you stood up), not here.
- **No evasion / anti-forensics.** No source-spoofing, no deliberately stealthy
  timing to slip past defenses, no attempt to avoid appearing in the target's
  own logs. This is a cooperative assessment of your own surface; it should be as
  visible to the asset owner as any other monitoring.
- **No third-party collateral.** Passive lookups use public/first-party datasets;
  they do not drag a non-consenting third party's infrastructure into an active
  probe. A shared-hosting neighbor or an upstream provider is not in scope because
  your asset happens to sit near it.

### 1.3 Evidence is redacted and non-intrusive

Every footprint item is proven by an observation, never by damage or by hoarding
a secret in the clear:

| Item found | Recorded as |
|---|---|
| Exposed service | `host:port`, banner/fingerprint, and the passive/active method used — not a stolen session. |
| Software version | The version string and how it was observed (header, CT cert, template match). |
| Document-metadata leak | The extracted field (author, path, software) and the source document URL — the document is already public. |
| Committed secret | A **redacted** match (first/last few chars + detector name + file:line), never the full secret written into the footprint or chat. |
| Subdomain / host | The name and the passive source that named it (CT log, DNS), tied to its in-scope parent. |

______________________________________________________________________

## 2. The Scope Attestation Format

A small file the user owns, checked in or supplied per engagement. It is the
authorization record — recon runs only against what it enumerates. YAML shown;
JSON with the same keys is equally valid.

```yaml
# ray-quarry scope attestation
attested_by: "jordan@example.com"          # who is asserting this scope
attested_at: "2026-08-08"
valid_until: "2026-09-08"                   # optional; recon stops after this date
authorization_basis: >-                     # why these assets are in scope
  We own example.com and its subdomains (registrar records on file). Active
  testing authorized under internal change ticket SEC-4821.
scope:
  - asset: "example.com"                     # apex domain; subdomains inherit
    type: domain
    includes_subdomains: true
    active_ok: false                         # passive only
  - asset: "api.example.com"
    type: host
    active_ok: true                          # bounded active enumeration allowed
  - asset: "203.0.113.0/28"                  # an owned block, explicitly enumerated
    type: cidr
    active_ok: true
  - asset: "github.com/example-org/webapp"   # a repo to scan for committed secrets
    type: repo
    active_ok: false
out_of_scope:                                # explicit carve-outs, always honored
  - "legacy.example.com"                     # decommissioned; do not touch
  - "vendor.example.com"                     # third-party managed; not ours to test
```

Rules on the file:

- **Nothing implicit.** An asset is in scope only if it (or its parent, for
  subdomains under an `includes_subdomains: true` domain) is listed. `out_of_scope`
  entries are honored even when they would otherwise match a wildcard.
- **`active_ok` defaults to false.** Omitting it means passive-only for that asset,
  regardless of `--mode`.
- **CIDRs are the only range form, and must be explicitly listed.** There is no
  "scan the neighborhood". A `cidr` entry authorizes exactly the addresses it
  spans and no more.

______________________________________________________________________

## 3. Asset Resolution — mapping any discovered asset back to scope

Recon discovers new assets (a subdomain from a CT log, a host an A record points
at). Each must be resolved to the attestation before it is touched:

1. **Exact match** — the asset equals a `scope[].asset`. In scope.
2. **Subdomain match** — the asset is a subdomain of a `domain` entry with
   `includes_subdomains: true` (e.g. `mail.example.com` under `example.com`). In
   scope, inheriting that entry's `active_ok`.
3. **CIDR membership** — a discovered IP falls inside a `cidr` entry. In scope,
   inheriting its `active_ok`.
4. **Out-of-scope override** — if the asset matches any `out_of_scope` entry, it
   is out, even if 1–3 would have included it. The carve-out always wins.
5. **No match** — out of scope by construction. Do not resolve it further, do not
   probe it, do not add it to the active set. Record it once in the footprint as
   "observed, out of scope, not touched" so the human can decide whether to widen
   the attestation next run.

A discovered IP that resolves *from* an in-scope hostname is only actively
probed if that IP is **itself** in scope (a `cidr` entry or an in-scope host):
owning a name does not authorize probing whatever third-party address it happens
to point at today.

______________________________________________________________________

## 4. What Passive vs. Active Actually Mean

The boundary is "did I send anything to the target's own infrastructure?", not
"was it noisy".

**Passive** — no packet reaches the target's asset because of this run:
- DNS resolution and record lookups (recursive resolvers, not the target's authoritative-only interfaces beyond normal resolution).
- Certificate-transparency log queries (crt.sh-style public logs).
- WHOIS / RDAP.
- Third-party passive datasets (passive DNS, public service inventories) that already hold the data.
- Reading documents the target already published, and extracting their metadata locally.
- Scanning the user's **own** repo for committed secrets.

**Active** — packets reach the in-scope asset (allowed only for `active_ok` hosts,
bounded, non-destructive):
- Port/service discovery and banner grabbing.
- Technology/version fingerprinting via normal requests.
- Template-based *observation* checks (e.g. non-exploit `nuclei` templates that
  confirm an exposure exists without exploiting it).

Anything that tries to *use* an exposure rather than *observe* it — submit a
payload, bypass auth, alter state, exhaust a resource — is neither passive nor
allowed-active. It is out of `ray-quarry`'s charter and belongs to `ray-siege`
against a local instance.
