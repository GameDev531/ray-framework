# OWASP Mapping — Top 10, API Top 10, ASVS, and CWE Crosswalk

The taxonomy `/ray-crucible` uses to label findings and to check its own
coverage. Two things this file is for:

1. **Labelling.** Give every finding a precise `cwe` and, in the description, the
   OWASP category a stakeholder will recognize.
2. **Coverage.** After the sweep, walk this file's categories and ask which ones
   this codebase could exhibit and whether the sweep looked. Categories that fall
   outside this skill are listed with the Ray skill that owns them — that is how
   the suite avoids a gap between skills.

Do not treat a category label as evidence. A finding is made real by its
source→sink trace, not by its OWASP number.

## Table of Contents

- [1. OWASP Top 10:2025](#1-owasp-top-102025)
- [2. OWASP API Security Top 10:2023](#2-owasp-api-security-top-102023)
- [3. Class → CWE → Category Crosswalk](#3-class--cwe--category-crosswalk)
- [4. ASVS As A Depth Selector](#4-asvs-as-a-depth-selector)
- [5. Coverage Self-Check](#5-coverage-self-check)

______________________________________________________________________

## 1. OWASP Top 10:2025

The 2025 edition reorders the list and adds two categories. Two changes matter
directly to this suite: **SSRF is folded into A01 Broken Access Control**, and
supply chain is promoted to its own category.

| ID | Category | Ray owner | Notes for the auditor |
|---|---|---|---|
| A01:2025 | Broken Access Control (now including SSRF) | `/ray-turnstile` (authorization, IDOR, tenancy); `/ray-crucible` (SSRF) | Still the highest-impact category in practice. The SSRF merge does not change the CWE — keep `CWE-918`. |
| A02:2025 | Security Misconfiguration | `/ray-custodian` (headers, TLS), `/ray-citadel` (infrastructure, environments), `/ray-sentry` (exposed internal endpoints) | Moved up from #5 in 2021. Defaults left on, debug enabled, permissive CORS, verbose errors. |
| A03:2025 | Software Supply Chain Failures | `/ray-crucible` (`DEPS`), `/ray-citadel` (pipeline integrity) | Expanded from 2021's "Vulnerable and Outdated Components" to cover the whole chain: dependencies, build systems, distribution. |
| A04:2025 | Cryptographic Failures | `/ray-turnstile` (password hashing, tokens), `/ray-vault` (at-rest, in-transit, field-level), `/ray-custodian` (TLS) | Was A02 in 2021. |
| A05:2025 | Injection | `/ray-crucible` | SQLi, command injection, XSS, template injection, and friends. |
| A06:2025 | Insecure Design | `/ray-perimeter` (threat model), `/ray-citadel` (architecture) | Not a code-level class; the pipeline addresses it through threat modeling and architecture review. |
| A07:2025 | Authentication Failures | `/ray-turnstile` | Renamed from "Identification and Authentication Failures". |
| A08:2025 | Software and Data Integrity Failures | `/ray-crucible` (`DESER`), `/ray-citadel` (unsigned artifacts, unverified updates) | Insecure deserialization lives here, not under Injection. |
| A09:2025 | Security Logging and Alerting Failures | `/ray-sentry` | Renamed to emphasize alerting: logs nobody reads are not a control. |
| A10:2025 | Mishandling of Exceptional Conditions | `/ray-seam` (error leakage, fail-open paths), `/ray-sentry` (degradation) | New in 2025. Improper error handling, logic errors on abnormal input, and failing open — the last is the one to hunt: a catch block that allows the request through. |

**Compatibility note.** Many stakeholders still cite the 2021 list. When a
report needs it: A01 Broken Access Control, A02 Cryptographic Failures, A03
Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable
and Outdated Components, A07 Identification and Authentication Failures, A08
Software and Data Integrity Failures, A09 Security Logging and Monitoring
Failures, A10 SSRF. Prefer the CWE in machine-readable fields; it is stable
across editions, which the category ids are not.

______________________________________________________________________

## 2. OWASP API Security Top 10:2023

For API-first targets this list is the sharper instrument, because it separates
the three authorization failures that a single "broken access control" label
blurs together.

| ID | Category | Ray owner | The question it asks |
|---|---|---|---|
| API1:2023 | Broken Object Level Authorization (BOLA) | `/ray-turnstile` | Can I read an object by supplying someone else's id? |
| API2:2023 | Broken Authentication | `/ray-turnstile` | Can I forge, replay, or brute-force the credential? |
| API3:2023 | Broken Object Property Level Authorization (BOPLA) | `/ray-turnstile` | Can I write a property I should not (mass assignment), or read one I should not (excessive exposure)? |
| API4:2023 | Unrestricted Resource Consumption | `/ray-sentry` | Can I make the service spend unbounded CPU, memory, storage, or money? |
| API5:2023 | Broken Function Level Authorization (BFLA) | `/ray-turnstile` | Can I call an administrative operation as a normal user? |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | `/ray-sentry` | Can I automate a flow the business assumed a human would perform once (ticket buying, referral bonuses, trial abuse)? |
| API7:2023 | Server Side Request Forgery | `/ray-crucible` | Can I make the server fetch a URL I choose? |
| API8:2023 | Security Misconfiguration | `/ray-custodian`, `/ray-citadel` | Are defaults, headers, CORS, and debug settings hardened? |
| API9:2023 | Improper Inventory Management | `/ray-sentry` | Are there forgotten versions, staging hosts, or undocumented endpoints still serving? |
| API10:2023 | Unsafe Consumption of APIs | `/ray-crucible`, `/ray-seam` | Do we trust third-party responses without validation? |

API6 and API9 deserve a deliberate look because no code pattern reveals them:
an inventory of every route the service exposes, compared against the routes the
team believes exist, is the whole test.

______________________________________________________________________

## 3. Class → CWE → Category Crosswalk

| Docket class | CWE | Top 10:2025 | API Top 10:2023 |
|---|---|---|---|
| `SQLI` | CWE-89 (SQL), CWE-943 (NoSQL) | A05 | — |
| `CMDI` | CWE-78 | A05 | — |
| `XSS` | CWE-79 | A05 | — |
| `SSTI` | CWE-1336 | A05 | — |
| `CSRF` | CWE-352 | A01 | — |
| `SSRF` | CWE-918 | A01 | API7 |
| `DESER` | CWE-502 | A08 | API10 |
| `XXE` | CWE-611 | A05 | — |
| `TRAV` | CWE-22 | A01 | — |
| `UPLOAD` | CWE-434 | A05 / A02 | — |
| `REDIR` | CWE-601 | A01 | — |
| `PROTO` | CWE-1321 | A08 | — |
| `TIMING` | CWE-208 | A04 | — |
| `REDOS` | CWE-1333 | A10 | API4 |
| `CSVI` | CWE-1236 | A05 | — |
| `DEPS` | CWE-1395 | A03 | — |
| IDOR / BOLA (`/ray-turnstile`) | CWE-639 | A01 | API1 |
| Mass assignment (`/ray-turnstile`) | CWE-915 | A01 | API3 |
| Excessive data exposure (`/ray-turnstile`) | CWE-213 | A01 | API3 |
| Weak password hashing (`/ray-turnstile`) | CWE-916 | A04 | API2 |
| Session fixation (`/ray-turnstile`) | CWE-384 | A07 | API2 |
| Improper signature verification (`/ray-turnstile`, `/ray-sentry`) | CWE-347 | A08 | API2 |
| Hardcoded credentials (`/ray-turnstile`) | CWE-798 | A07 | API2 |
| No auth-attempt throttling (`/ray-turnstile`) | CWE-307 | A07 | API2 / API4 |
| Missing cookie flags (`/ray-custodian`) | CWE-1004, CWE-614, CWE-1275 | A02 | API8 |
| Cleartext transmission (`/ray-custodian`) | CWE-319 | A04 | API8 |
| Sensitive data in logs (`/ray-seam`) | CWE-532 | A09 | API8 |
| Verbose error messages (`/ray-seam`) | CWE-209 | A10 | API8 |
| Permissive CORS (`/ray-seam`) | CWE-942 | A02 | API8 |
| Missing rate limit (`/ray-sentry`) | CWE-770 | A02 | API4 |
| Missing security logging (`/ray-sentry`) | CWE-778 | A09 | API9 |
| Improper access control on internals (`/ray-sentry`) | CWE-284 | A01 | API8 |
| Missing encryption at rest (`/ray-vault`) | CWE-311 | A04 | — |
| Excessive DB privileges (`/ray-vault`) | CWE-250, CWE-732 | A01 | — |
| Fail-open error handling (`/ray-seam`) | CWE-636 | A10 | — |

______________________________________________________________________

## 4. ASVS As A Depth Selector

The Application Security Verification Standard (5.0, released May 2025 —
roughly 350 requirements across 17 chapters, including new chapters for Web
Frontend Security, Self-Contained Tokens, and OAuth/OIDC) is the right tool
when someone asks "how deep should this review go?".

Use its levels to set the sweep's depth, and record the choice in the ledger:

| Level | Intended for | What it means for `/ray-crucible` |
|---|---|---|
| L1 | Baseline for all applications | Sweep every class in the docket for reachable, unauthenticated paths. Note that ASVS 5.0 explicitly states that meaningful verification requires access to internal artifacts — black-box-only checking is not a level. |
| L2 | Applications handling sensitive data (the default for most SaaS) | Add second-order flows, chained primitives, and authenticated-attacker paths; trace every sink rather than sampling. |
| L3 | Highest-assurance applications | Add exhaustive call-site sweeps per sink, cross-service flows, and cryptographic detail; pair with `/ray-detonator` for every HIGH. |

ASVS 5.0 also introduces "documented security decisions" — each chapter opens
with a documentation requirement. That maps cleanly onto the ledger this suite
writes: a control recorded as `NOT_APPLICABLE` with a stated reason *is* a
documented security decision, and is worth more than a silent omission.

______________________________________________________________________

## 5. Coverage Self-Check

Run this before writing the ledger. For each row, answer with evidence, not
recollection:

1. Every docket class has a ledger entry of `ASSESSED`, `NO_SINKS`, or
   `NOT_ASSESSED` (the last only when `--classes` excluded it).
2. Every `ASSESSED` class lists the patterns actually run.
3. Every sink has a verdict, and every `NEUTRALIZED` verdict cites the
   neutralizer's `file:line`.
4. Every `UNKNOWN` sink has a `NEEDS_RESEARCH` finding naming what would
   resolve it.
5. Every Top 10:2025 category is either covered by a class above or attributed
   to the Ray skill that owns it, so the report can state coverage honestly
   rather than implying this one stage covered everything.
6. Second-order flows (Step 5 of the skill) were considered for the classes
   where they apply: `XSS`, `SQLI`, `CSVI`, `DESER`, `PROTO`.
7. The dependency block is filled in, including "no manifests found" if that is
   the case.
