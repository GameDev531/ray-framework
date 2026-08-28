# Findings Contract — ray-counsel

How this stage writes its output. Read it before the first finding and again at the
report. Same mechanical discipline as the other stages (`ray-condenser` clusters on
`signature`, `ray-arbiter` re-reads `code_paths`), plus the rules that keep a
*legal* review honest.

## Table of Contents

- [1. The non-negotiables of a legal review](#1-the-non-negotiables-of-a-legal-review)
- [2. The classification taxonomy (never conflate)](#2-the-classification-taxonomy-never-conflate)
- [3. Currency verification](#3-currency-verification)
- [4. Evidence discipline](#4-evidence-discipline)
- [5. Severity defaults](#5-severity-defaults)
- [6. Findings schema](#6-findings-schema)
- [7. The LEGAL & COMPLIANCE STATUS report](#7-the-legal--compliance-status-report)

______________________________________________________________________

## 1. The non-negotiables of a legal review

Four rules bind every finding; violating one makes the output worse than nothing.

1. **Never invent a law.** Do not write "the law requires X" without knowing *which*
   law, *which* jurisdiction, *which* version, *which* context, *which* exception,
   and *which* effective date. If you don't have all six, it is `needs-qualified-
   counsel`, not a `mandatory-by-law` claim.
2. **Never certify.** Do not say a project is "legally safe," "compliant," or
   "GDPR-compliant." State the obligation and the gap; the verdict is a lawyer's.
3. **Never predict enforcement.** Name the obligation and the divergence; never
   predict a fine, a lawsuit outcome, or a regulator's action.
4. **Never conflate the classes** (§2). A platform requirement is not a law; a best
   practice is not an obligation; a hypothesis is not a certainty.

## 2. The classification taxonomy (never conflate)

Every finding carries **exactly one** `legal_class`:

| `legal_class` | Meaning | Citation required |
|---|---|---|
| `mandatory-by-law` | A statute/regulation with a nexus to this project requires it | **Yes** — name the article (`GDPR art. 13`, `CCPA §1798.100`, `LGPD art. 9`) and keep the claim narrow |
| `platform-requirement` | Apple App Store / Google Play (or another platform) requires it as a condition of publishing | Name the policy (e.g. "Google Play Data Safety") — it is a contract term, **not** a law |
| `best-practice` | Widely-accepted good practice; not itself an obligation | No |
| `risk-recommendation` | Reduces litigation/regulatory/consumer-protection risk; a judgment call | No |
| `needs-qualified-counsel` | Turns on a specific statute/jurisdiction/fact a lawyer must resolve | State precisely what a lawyer must decide |

When two could apply (a data type is both a law obligation *and* a platform-label
requirement), write **two findings** — one per class — so neither the legal nor the
platform gap is lost. Never blur them into one.

## 3. Currency verification

Laws and platform policies change. For any conclusion involving a law, a regulator,
Apple/Google, the FTC, a privacy framework, or a publishing requirement, prefer the
**most recent official source** before presenting it as current, in this priority:
(1) the official statute/regulator; (2) the platform's official documentation; (3)
reliable case law / legal source; (4) secondary documentation. Never treat an old
blog post as authority. If you cannot verify currency, say so and classify
`needs-qualified-counsel` — do not assert a possibly-stale rule as current.

## 4. Evidence discipline

- **Anchor both sides of a divergence.** A finding is a mismatch between the code
  and a document/label/claim — cite the `file:line` in the **code** (the SDK init,
  the data-collection call, the AI provider call) **and** the location of the
  contrary/absent statement (the policy paragraph, the Data Safety field, the
  marketing line). A finding anchored on only one side is unreviewable.
- **Absence-of-document findings anchor at where it would live** (the missing ToS,
  the missing disclosure in the onboarding component) and say you searched.
- **One obligation, one finding.** Don't bundle "no ToS, no privacy policy, no
  arbitration" into one; don't fragment one absent disclosure across ten screens.
- **Status.** Default `PROVISIONALLY_VALID`; use `NEEDS_RESEARCH` when the item is
  jurisdiction-dependent and jurisdiction is unknown, or the fact can't be settled
  from the snapshot — and say what would resolve it.

## 5. Severity defaults

Severity is **risk exposure**, not a predicted penalty:

| Severity | Shape |
|---|---|
| CRITICAL | A `LEGAL BLOCKER` (docket §20): a feature relying on absent consent; a materially misleading claim live to users; a platform-mandated disclosure missing on a shipping app; sensitive data processed with no basis |
| HIGH | A clear code↔docs divergence a user/regulator would rely on (undeclared data collection; undisclosed AI where it changes understanding); fix before launch |
| MEDIUM | A gap to fix or document before production (an incomplete label; a bundled consent) |
| LOW | A recommended improvement |
| INFO | Context; no action |

## 6. Findings schema

```json
{
  "id": "<uuid>",
  "skill": "ray-counsel",
  "title": "App uses an AI chatbot but never discloses it to users",
  "severity": "HIGH",
  "legal_class": "risk-recommendation",
  "area": "ai-transparency",
  "jurisdiction_scope": ["US"],
  "citation": null,
  "signature": "ai-undisclosed:chatbot",
  "code_paths": ["src/server/chat.ts:42"],
  "doc_paths": ["(none) — no AI disclosure in onboarding or /privacy"],
  "divergence": {
    "code_does": "routes user messages to an LLM provider and returns generated replies",
    "surface_says": "onboarding and marketing imply a human support team; no AI disclosure anywhere"
  },
  "obligation": "Where a reasonable consumer could be misled about interacting with an automated system, disclosure is expected; undisclosed AI in support/marketing is an FTC-style deceptive-practice risk (US).",
  "mitigation": "Add a clear 'You're chatting with an AI assistant' disclosure at the start of the chat and in the relevant marketing copy; keep claims about its accuracy substantiated.",
  "status": "PROVISIONALLY_VALID",
  "needs_counsel": "Whether disclosure is legally required here depends on jurisdiction and how the service is marketed."
}
```

- `legal_class`, `area`, `divergence`, and `obligation` are this domain's required
  fields. `citation` is required when `legal_class` is `mandatory-by-law`, else
  `null`. `jurisdiction_scope` lists the jurisdictions the finding assumes;
  `needs_counsel` is set whenever a lawyer must resolve it.

## 7. The LEGAL & COMPLIANCE STATUS report

Close every run with:

```
## LEGAL & COMPLIANCE STATUS

Status:  ✅ CLEAR  |  ⚠️ REVIEW REQUIRED  |  🛑 LEGAL BLOCKER
(LEGAL BLOCKER ⇒ do not declare the project production-ready.)

Jurisdictions analyzed:            <or: UNSPECIFIED — analysis provisional>
Regulations potentially applicable: <with nexus, per area>
AI transparency:                   <findings / clear / n-a>
Advertising & claims:              ...
Terms of Service & arbitration:    ...
Privacy & data map:                <inventory summary + gaps>
Third-party / SDK data flows:      ...
Platform labels (Apple / Google):  ...
Consumer-protection & consent:     ...
Minors:                            ...
Security (cross-ref ray-vault/custodian): ...

Required before launch:            <mandatory-by-law + platform-requirement blockers/highs>
Items requiring qualified counsel: <every needs-qualified-counsel item, precisely>
```

End with the standing reminder: this identifies obligations and risks and
reconciles the product with its legal surface — it is **not legal advice** and does
not certify the project as legally safe. Items marked `needs-qualified-counsel` go
to a qualified lawyer.
