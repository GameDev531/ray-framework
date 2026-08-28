# Compliance Docket — area procedures

The per-area detail behind `ray-counsel`. Every area obeys three rules from the
`SKILL.md`: **jurisdiction first**, **the finding is a divergence anchored in the
code**, and **classify, never conflate** (`findings_contract.md`). Read the area
when you work it; skip an area with no nexus and say why.

## Table of Contents

- [1. Jurisdiction determination](#1-jurisdiction-determination)
- [2. AI transparency & disclosure](#2-ai-transparency--disclosure)
- [3. Claims & advertising](#3-claims--advertising)
- [4. Terms of Service](#4-terms-of-service)
- [5. Arbitration & disputes](#5-arbitration--disputes)
- [6. Privacy & the data map](#6-privacy--the-data-map)
- [7. SDKs, APIs & third parties](#7-sdks-apis--third-parties)
- [8. Apple App Privacy](#8-apple-app-privacy)
- [9. Google Play Data Safety](#9-google-play-data-safety)
- [10. US state privacy (CCPA/CPRA) & other regimes](#10-us-state-privacy-ccpacpra--other-regimes)
- [11. Minors (COPPA and beyond)](#11-minors-coppa-and-beyond)
- [12. Payments, subscriptions & dark patterns](#12-payments-subscriptions--dark-patterns)
- [13. Consent](#13-consent)
- [14. Account & data deletion](#14-account--data-deletion)
- [15. Breach readiness](#15-breach-readiness)
- [16. AI & user data (training)](#16-ai--user-data-training)
- [17. User-generated content rights](#17-user-generated-content-rights)
- [18. Moderation & abuse](#18-moderation--abuse)
- [19. The consistency spine](#19-the-consistency-spine)
- [20. Legal blockers](#20-legal-blockers)

______________________________________________________________________

## 1. Jurisdiction determination

Determine, before any rule: operator country; user countries; relevant
states/provinces; target market; user type (consumer vs business; B2C vs B2B);
service nature; data types processed; platform (web / iOS / Android); whether
minors may be involved; third parties used. **No single jurisdiction's rule is
universal.** When unspecified: flag the absence, analyze provisionally, mark
jurisdiction-dependent items `NEEDS_RESEARCH`, present no definitive conclusion,
and list which findings would change with jurisdiction.

## 2. AI transparency & disclosure

Trigger whenever the project uses a chatbot, AI agent, content generation,
automated recommendation/scoring, synthetic voice/image/video, or automated
decision-making. Check three things:

- **Representation.** Does any copy state or imply a human is responding when it's
  an AI; that a result is *guaranteed*; that the AI has capabilities it lacks; that
  it's "100% automatic" / "infallible" / "error-free"; or an accuracy/efficacy it
  can't support? An unsupportable AI claim is a deceptive-practice risk (FTC-style,
  US) — flag it (§3 covers the claim mechanics).
- **Disclosure.** Where a reasonable user could be misled about interacting with an
  automated system or AI-generated content, disclosure is expected. Absence of
  disclosure is a **transparency risk**, not automatically a violation — classify
  it as such. Deliberately hiding the automated nature when it would change a
  consumer's understanding is the serious case.
- **Marketing.** Audit landing pages, ads, pricing, onboarding, emails,
  notifications, metatags, and the App Store / Play descriptions with one question:
  *could a reasonable consumer read this differently from reality?* If yes, flag.

The flagship example: **an app uses AI and never says so.** In the US that is a
classic FTC deceptive-advertising exposure; anchor the finding at the AI-calling
code and the missing/contrary disclosure in the UI/marketing.

## 3. Claims & advertising

Every commercial claim needs a basis. Flag especially: *guaranteed, risk-free,
100% secure, 100% accurate, instant, automatic, never fails, safer, best, #1,
saves X%, increases X%, eliminates, prevents, approved, certified, compliance
guaranteed.* Require substantiation, or flag as unsubstantiated. Never turn a
technical hypothesis into a commercial promise. A security claim ("bank-grade
encryption", "GDPR compliant") is a claim like any other — it must match what
`ray-vault`/`ray-custodian` actually found.

## 4. Terms of Service

A project with accounts, subscriptions, payments, user content, a marketplace,
SaaS, APIs, or AI should be assessed for whether it needs ToS, and the ToS must
match the system's real behavior. Check at least: service identity; eligibility/min
age; account creation & termination; acceptable use; user content & the license
granted to the service; IP; AI-generated-content terms; availability/limitations;
pricing, renewal, cancellation, refunds, chargebacks; suspension & termination;
software ownership; third-party use; external links; abuse handling; contact
mechanism; governing law; dispute resolution; and the process for changing the
terms. A ToS clause that contradicts the product (says "no refunds" while the code
issues them, or omits the AI-content terms the feature requires) is a finding.

## 5. Arbitration & disputes

**Never auto-add an arbitration clause just because a ToS exists.** First
determine jurisdiction, user type (consumer vs business), applicable law, and
whether local law limits or shapes arbitration and class-action waivers. When
arbitration is relevant, assess separately: (1) the arbitration clause; (2)
forum/venue; (3) choice of law; (4) jury-trial waiver where applicable; (5)
class-action waiver *where legally permitted*; (6) an opt-out procedure; (7) the
notice mechanism; (8) consent/assent formation. **Never write "arbitration
prevents lawsuits."** Frame it as a contractual dispute-resolution mechanism
subject to applicable law and its limits. The flagship example: **no arbitration /
class-waiver posture at all**, so a single dissatisfied consumer can anchor a class
action — flag as a risk to weigh with counsel, classified needs-qualified-counsel.

## 6. Privacy & the data map

Before any privacy-policy check, build the **data inventory** from the code. For
each personal-data type the project actually touches — name, email, phone, address,
IP, device ids, cookies, analytics, location, payment info, auth data, uploaded
content, prompts, files, images, voice, video, history, usage data, **inferred**
data, **sensitive** data, third-party-processed data — record:

| Data | Source | Purpose | Storage | Retention | Shared with | Third party | Stated basis |

Never invent a row you can't point to in the code; never omit one an SDK collects
(§7). This table is the ground truth the policy, consent UI, and store labels are
checked against.

## 7. SDKs, APIs & third parties

Own code is not the whole story. Audit imported third parties — Google Analytics,
Meta Pixel, Stripe, Firebase, Supabase, Auth0, Sentry, PostHog, OpenAI, Anthropic,
Google, email/storage/CDN/maps services, mobile ad SDKs — and for each ask **"what
data does this third party receive?"** The privacy policy **and** the store labels
must reflect third-party processing: Apple's App Privacy and Google's Data Safety
both require that third-party SDK data practices be represented. A data flow to an
SDK that the policy/label omits is a finding anchored at the SDK-init/usage line.

## 8. Apple App Privacy

If the project ships on the App Store, review: the accessible privacy policy; the
App Privacy "nutrition label" data types; collection, use, sharing, retention,
deletion; consent; permissions; SDKs; tracking and **ATT** where applicable;
account creation **and account deletion** (Apple requires in-app account deletion
where accounts exist); and App Review specifics. The rule that matters: **the label
must match the app's real behavior** (and its SDKs' — §7), not merely "have a
privacy policy." A label that under-declares a collected data type is the flagship
Apple finding.

## 9. Google Play Data Safety

If the project ships on Google Play, review the **Data Safety** form and the
privacy policy: data collected, data shared, purpose, retention, deletion, SDKs,
permissions, sensitive data. The Data Safety section must reflect the app's **real**
collection/use/sharing, including via third-party SDKs/libraries. Divergence
between Data Safety and the code is the flagship Google finding.

## 10. US state privacy (CCPA/CPRA) & other regimes

Don't treat "CPA" as shorthand for all privacy law, and don't treat every known law
as applicable — establish a **nexus** first. When California applies, check:
applicability thresholds; personal vs **sensitive** personal information; notice at
collection; rights to know/delete/correct/opt-out; "sale" and "sharing";
behavioral advertising; **Global Privacy Control** honoring; retention; data
minimization; purpose limitation; service-provider/contractor terms; consumer-
request handling. Note that CPRA amended the CCPA (not a wholly separate law), and
that newer California obligations (risk assessments, cybersecurity audits, and
rules around automated-decisionmaking technology in some scenarios) may apply —
verify the current text (`findings_contract.md` currency rule) rather than asserting
specifics from memory. Beyond California, per market: **LGPD, GDPR, COPPA, FERPA,
HIPAA, GLBA**, other US state laws, and sector rules — each only where a nexus
exists.

## 11. Minors (COPPA and beyond)

Determine whether the product is directed to minors, may be used by minors,
collects minors' data, has social features, serves ads, uses AI, profiles, or
personalizes. If minors may be involved, add a pass on min age, consent (parental
where required), data collection, advertising, profiling, content, retention, and
deletion. **An "18+" or min-age gate must be reflected technically**, not just
shown as a visual — a checkbox with no enforcement is a finding.

## 12. Payments, subscriptions & dark patterns

For subscriptions, free trials, recurring/usage-based billing, credits,
upgrades/downgrades: check price, currency, frequency, renewal, trial terms, **when
the charge occurs**, cancellation, refunds, taxes where applicable, chargebacks,
and change communication. The UI must never hide a material term of the purchase.
Flag **dark patterns**: a hard-to-find cancel, a pre-checked upsell, a trial that
silently converts, an obscured total. These are consumer-protection findings
anchored at the checkout/billing UI and code.

## 13. Consent

Not every "I Accept" is legally sufficient consent. Determine what is being
accepted; whether it's a contract or a consent; whether there's a specific purpose;
whether the user can understand it; whether there's an affirmative action; whether
consent must be **separate**; whether it can be withdrawn; and how it's recorded.
Separate, where needed: ToS acceptance, privacy acknowledgement, marketing consent,
tracking consent, sensitive-data consent. One bundled checkbox covering all of them
is a finding.

## 14. Account & data deletion

Accounts require a specific analysis for account deletion, data deletion, legal
retention, backups, third-party data, fraud-prevention data, and data under legal
hold. A user's deletion request does **not** mean everything can be destroyed
immediately — identify the legally-applicable exceptions and whether the code
honors both the deletion and the exceptions. "Delete account" that only
soft-flags a row while the policy promises erasure is a finding.

## 15. Breach readiness

Any project storing personal data needs a strategy to: detect an incident; log it;
identify affected data; identify affected users; identify third parties involved;
assess notification obligations; preserve evidence; document the response. **Do not
assume a universal notification deadline** — it depends on law, jurisdiction,
incident nature, and facts. The finding is the *absence of the capability/plan*,
not a predicted timeline.

## 16. AI & user data (training)

Always determine: **"is user-submitted data used for training?"** — prompts, files,
images, audio, video, messages, personal data — and check retention, training,
fine-tuning, storage, logging, and the model providers' terms (§7). Never assume.
The user-facing documentation must match the real behavior; a policy silent on
training while the code forwards prompts to a provider that trains on them is a
finding.

## 17. User-generated content rights

If users upload or generate content, analyze copyright, license, ownership,
permissions, third-party content, prohibited content, removal, complaints,
copyright notices, and liability. **Never auto-state "you own everything the AI
generates"** — ownership of AI output depends on jurisdiction, facts, and the
provider's terms. A ToS over-claiming a broad license, or contradicting the model
provider's terms, is a finding.

## 18. Moderation & abuse

For chat, comments, uploads, marketplace, community, or generation features,
analyze handling of abuse, spam, fraud, impersonation, illegal content,
harassment, reporting, blocking, suspension, and appeal. The product's internal
rules must be coherent with the ToS (§4). A ToS promising a reporting/appeal
mechanism the product doesn't implement is a finding.

## 19. The consistency spine

The highest-value pass. Walk **CODE → DATA → DOCS → UI → STORE LISTING** and make
every layer describe the same reality:

- a privacy policy that says one thing while the code does another;
- a ToS incompatible with the product's behavior;
- an Apple App Privacy label ≠ reality;
- a Google Data Safety declaration ≠ reality;
- marketing that promises more than the product delivers.

Each divergence is one finding, anchored at both sides (the code line and the
document/label/claim line). This pass is where the three flagship risks — undeclared
AI, missing arbitration posture, mislabeled data collection — most often surface.

## 20. Legal blockers

Escalate to **LEGAL BLOCKER** (do not declare production-ready) when: a feature
depends on consent that doesn't exist; data is collected without adequate
documentation; code and policy materially diverge; marketing makes a potentially
misleading claim; the app lacks a platform-mandated disclosure; sensitive data is
processed without review; essential terms are missing where required; or a relevant
regulatory obligation is unaddressed. A blocker is a **specific, evidenced** gap —
never a vibe, and never a prediction of a fine.
