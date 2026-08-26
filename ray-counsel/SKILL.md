---
name: ray-counsel
description: >-
  Audits a software project as a legal-engineering layer: AI transparency and advertising claims (FTC-style deceptive-practice risk), Terms of Service and arbitration/class-action clauses, privacy data-mapping, third-party SDK data flows, the Apple App Privacy and Google Play Data Safety labels, consumer-protection and dark-pattern risks, consent, account/data deletion, minors, and payments — always jurisdiction-first, and always checking that the CODE, the DATA it touches, the DOCS (privacy policy / ToS), the UI, and the store listing all describe the same reality.
  Use when a project ships to real users (a site, SaaS, or app — especially one that uses AI, collects personal data, charges money, or publishes to the App Store / Google Play) and you need its legal, regulatory, and platform-compliance obligations identified and its documentation reconciled with what the code actually does.
  Don't use for the technical privacy/web surface (ray-custodian), identity/tenancy (ray-turnstile), the app's own LLM security (ray-oracle), or as a substitute for a qualified lawyer — it identifies obligations and risks, it does not give legal advice or certify a project as legally safe.
---

# Counsel (/ray-counsel)

## Not legal advice — read this first

`ray-counsel` is a **legal-engineering review layer**, not a lawyer. It identifies
obligations, risks, and — most usefully — **divergences between what a project's
code does and what its documents, labels, and marketing claim**. It never certifies
a project as "legally safe," never predicts an enforcement outcome or a fine, and
never invents a law. Anything that turns on a specific statute, jurisdiction, or
fact pattern is flagged **NEEDS-QUALIFIED-COUNSEL** and handed to a human lawyer.
Its value is catching the compliance gap early and precisely, so counsel spends
their time on judgment, not discovery.

## System Goal

**Legal & Compliance Engineer.** A feature can work perfectly and still create a
legal obligation the project never met: the app uses AI but never discloses it
(FTC-style deceptive-practice exposure); the ToS has no arbitration/class-action
posture, so one unhappy user can anchor a class action; the App Store / Google Play
privacy label omits a data type an SDK actually collects. None of these show up in
a functional test — they show up as a **mismatch between the product and its legal
surface**. This stage finds those mismatches and names the obligation behind each.

The core method is an **evidence spine** — nothing here is asserted from the model's
disposition:

```
CODE  →  DATA it collects/shares  →  DOCS (privacy policy, ToS)  →  UI (consent, disclosures)  →  STORE LISTING (Apple/Google labels)
```

Every layer must describe the **same reality**. A finding is a proven **divergence**
between two of these layers (the code shares an email with a third party; the
privacy policy and the Data Safety label don't mention it), anchored at both the
code line and the document line that disagree.

## Command Definition

- **Command:** `/ray-counsel`
- **Description:** Determines jurisdiction, builds a data inventory from the code
  and its SDKs, then audits AI transparency/claims, ToS/arbitration, privacy docs,
  store privacy labels, consumer-protection and consent, minors, payments, and
  incident readiness — reconciling each against the code and emitting findings plus
  a LEGAL & COMPLIANCE STATUS.
- **Arguments (all optional; the orchestrator supplies them):**
  - `--jurisdiction` / operator + user countries/states, target market. If absent,
    **the analysis is provisional** — see Step 1.
  - `--snapshot_root` / `--state_root` — as the other stages.

## Input/Output Contract

- **Reads**: the target — marketing/landing copy, onboarding, App Store / Play
  listing metadata, the ToS and privacy policy files (if any), consent UI, and the
  **code** that collects/stores/shares personal data, imports third-party SDKs, or
  calls AI/model providers; this skill's `references/*.md`.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema, with the legal
  classification of `references/findings_contract.md`); a `workspace/counsel/`
  data-inventory table; the LEGAL & COMPLIANCE STATUS report.
- **Never**: invents a statute, a citation, a version, or an effective date;
  predicts a fine or an enforcement outcome; declares the project "legally safe";
  or treats a platform requirement as a law (or vice versa).

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/compliance_docket.md` | per area, through the run | The area procedures: jurisdiction determination; AI transparency + claims; ToS + arbitration/class-action; the privacy data-map; SDKs/third-parties; Apple App Privacy + Google Data Safety labels; CCPA/CPRA + other regimes; minors/COPPA; payments/dark patterns; consent; account/data deletion; breach readiness; AI training-data; UGC rights; moderation; and the code↔docs consistency spine |
| `references/findings_contract.md` | before the first finding, and at the report | The findings schema; the **legal classification taxonomy** (mandatory-by-law / platform-requirement / best-practice / risk-recommendation / needs-qualified-counsel) that must never be conflated; the currency-verification rule; the not-legal-advice discipline; the STATUS format |

## Instructions

### Step 1 — Jurisdiction first (never skip)
Before applying any rule, determine, per `compliance_docket.md` §1: the operator's
country, the users' countries/states, the target market, the user type (consumer
vs business, B2C vs B2B), the nature of the service, the data processed, the
platform, whether minors may be involved, and which third parties are used. **A
rule from one jurisdiction is never universal.** If jurisdiction is unspecified,
say so, do a **provisional** analysis, mark jurisdiction-dependent items
`NEEDS_RESEARCH`, and present no definitive legal conclusion.

### Step 2 — Build the data inventory (the spine's second node)
From the **code and its SDK imports**, enumerate every personal-data type the
project actually touches (§6, §7): what it is, where it comes from, why, where it's
stored, retention, whom it's shared with, which third party, and the stated basis.
Never list a data type you can't point to in the code; never omit one an imported
SDK collects. This inventory is what the privacy policy, the consent UI, and the
store labels are checked against.

### Step 3 — Run the area audits (only those with a nexus)
Work `compliance_docket.md` §2–§20 for the areas that actually apply to this
project. For each area, the finding is a **divergence** anchored at the code line
and the doc/label/claim line that disagree — e.g. AI used but not disclosed (§2),
an unsubstantiated claim (§3), a missing ToS clause the product's behavior requires
(§4), a data type the Apple/Google label omits (§8–§9). Don't run an area with no
nexus (no payments → skip §13); say you skipped it and why.

### Step 4 — Reconcile the consistency spine
Explicitly walk CODE → DATA → DOCS → UI → STORE LISTING (§21). Every divergence is
a finding. This is the highest-value pass — a privacy policy that says one thing
while the code does another is both a consumer-protection risk and a platform-label
risk at once.

### Step 5 — Classify, never conflate
Give every finding exactly one classification from `findings_contract.md`:
**mandatory-by-law** (name the article), **platform-requirement** (Apple/Google),
**best-practice**, **risk-recommendation**, or **needs-qualified-counsel**. Never
present a platform rule as a law, a best practice as an obligation, or a hypothesis
as a certainty.

### Step 6 — Status and gap analysis
Produce the LEGAL & COMPLIANCE STATUS (`findings_contract.md`): **✅ CLEAR /
⚠️ REVIEW REQUIRED / 🛑 LEGAL BLOCKER**, the jurisdictions analyzed, the potentially
applicable regimes, and the required-before-launch changes vs the
items-requiring-counsel. A **LEGAL BLOCKER** (§23 of the docket — e.g. a feature
depending on consent that doesn't exist, a materially misleading claim, a missing
platform-mandated disclosure) means: **do not declare the project production-ready.**
Do not overstate — a blocker is a specific, evidenced gap, not a vibe.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Legal obligations, AI disclosure, claims, ToS/arbitration, store privacy labels, consumer protection, jurisdiction | `/ray-counsel` (this skill) |
| Technical privacy of the web surface — TLS/headers/cookies, retention enforcement, data-subject-rights *plumbing* | `/ray-custodian` |
| Identity, sessions, authorization, tenancy | `/ray-turnstile` |
| Datastore protection, encryption, credential handling | `/ray-vault` |
| The app's own LLM/AI *security* (prompt injection, output handling) | `/ray-oracle` |
| Rate limiting, abuse, webhook integrity | `/ray-sentry` |

`ray-custodian` asks "is personal data technically protected on the wire and at
rest, and can a data-subject request be fulfilled?"; `ray-counsel` asks "does the
project's **legal surface** — disclosures, claims, contracts, labels — match what
the code actually does, and what obligations does that create?" They meet on
privacy: custodian implements the control, counsel checks the disclosure of it.
`ray-condenser` merges the overlap.
