# Privacy Docket — LGPD / GDPR Obligation Set

The obligation set `/ray-custodian` scores personal-data handling against. Each
section states the obligation, the mechanical test that decides whether the
codebase satisfies it, and the finding to raise when it does not.

This is a security-review aid, not legal advice. Describe the obligation and
the gap; do not predict enforcement outcomes or fine amounts in findings.

## Table of Contents

- [1. Data Classification Taxonomy](#1-data-classification-taxonomy)
- [2. Lawful Basis](#2-lawful-basis)
- [3. Minimization and Purpose Limitation](#3-minimization-and-purpose-limitation)
- [4. Consent Quality](#4-consent-quality)
- [5. Data-Subject Rights](#5-data-subject-rights)
- [6. Retention and Erasure](#6-retention-and-erasure)
- [7. Incident Notification](#7-incident-notification)
- [8. International Transfer](#8-international-transfer)
- [9. Processors, Sub-processors, and Third-Party Egress](#9-processors-sub-processors-and-third-party-egress)
- [10. Control Ledger IDs](#10-control-ledger-ids)

______________________________________________________________________

## 1. Data Classification Taxonomy

Classify every field found in the Step-2 inventory into exactly one class. The
class sets the floor for severity and decides which obligations apply.

| Class | Examples | Notes for the auditor |
|---|---|---|
| `IDENTIFIER` | user id, username, account number, device id, cookie id | Pseudonymous identifiers are still personal data under both regimes when they can be linked back to a person. |
| `CONTACT` | email, phone, postal address, CEP/ZIP | The most common leak vector; almost always present. |
| `GOVERNMENT_ID` | CPF, CNPJ, RG, SSN, passport, driver's licence | High value for fraud. Field-level encryption is expected (see ray-vault). |
| `FINANCIAL` | card PAN, IBAN, Pix key, bank account, transaction history | PCI-DSS may apply on top of the privacy regime; card data in application logs is a finding on its own. |
| `BEHAVIORAL` | page views, clickstream, geolocation, IP address, session replay | IP address is personal data under GDPR (Breyer, C-582/14) and treated as personal data under LGPD. Session replay captures far more than teams expect. |
| `SENSITIVE` | health, biometric, genetic, racial or ethnic origin, religious or philosophical belief, political opinion, union membership, sex life or orientation | LGPD art. 5 II ("dado pessoal sensível") / GDPR art. 9. Narrower lawful bases; higher severity floor. |
| `CHILDREN` | any personal data of a child or adolescent | LGPD art. 14 requires specific and prominent consent by at least one parent or guardian, and best-interest treatment. GDPR art. 8 sets a consent age (13–16 by member state) for information society services. |

**Severity floor rule.** A reachable exposure of `SENSITIVE`, `CHILDREN`,
`GOVERNMENT_ID`, or `FINANCIAL` data starts at HIGH. A reachable exposure of
`IDENTIFIER` or `BEHAVIORAL` data alone starts at MEDIUM. `ray-gauge` still
applies its caps afterwards — the floor here is a discovery-stage default, not
a final score.

______________________________________________________________________

## 2. Lawful Basis

Every act of processing needs a basis. The code rarely states one; the test is
whether the *repository or its docs* let a reviewer name one for each field.

**LGPD art. 7 — ten bases for personal data:** consent; compliance with a legal
or regulatory obligation; public administration executing public policy; studies
by a research body (with anonymization where possible); performance of a contract
or preliminary procedures at the data subject's request; regular exercise of
rights in proceedings; protection of life or physical safety; health protection
(by health professionals or health services); legitimate interest of the
controller or a third party; and credit protection.

**LGPD art. 11 — sensitive personal data** has its own, narrower list:
essentially specific and prominent consent, or a small set of non-consent
hypotheses (legal obligation, public policy, research, exercise of rights,
protection of life, health protection, fraud prevention and subject security).
**Legitimate interest is NOT available for sensitive data.**

**GDPR art. 6 — six bases:** consent; contract; legal obligation; vital
interests; public task; legitimate interests. **GDPR art. 9** governs special
categories with its own exhaustive list (explicit consent, employment/social
security law, vital interests, not-for-profit bodies, data manifestly made
public, legal claims, substantial public interest, health and social care,
public health, archiving/research).

### Mechanical tests

| Test | Finding when it fails |
|---|---|
| Every inventory field maps to a stated basis in policy docs, schema comments, or a data map in the repo | `UNKNOWN` if the repo plausibly does not carry privacy documentation; a documentation finding when policy docs exist and omit the field. |
| No `SENSITIVE` field relies on legitimate interest | Finding: sensitive data processed under an unavailable basis (LGPD art. 11 / GDPR art. 9). |
| Legitimate interest is not used for marketing to non-customers, profiling, or third-party ad sharing without an assessment | Finding: legitimate interest claimed without a balancing test; note that LGPD art. 10 §3 lets the ANPD require a legitimate-interest impact report. |
| A basis change is not implicit | Finding: the same field collected for one purpose is used for another (see §3). |

______________________________________________________________________

## 3. Minimization and Purpose Limitation

- **Minimization** (LGPD art. 6 III / GDPR art. 5(1)(c)): collect only what the
  stated purpose needs.
- **Purpose limitation** (LGPD art. 6 I / GDPR art. 5(1)(b)): do not repurpose.

### Mechanical tests

| Test | How to run it | Finding |
|---|---|---|
| Collected-but-unused fields | For each inventory field, grep for any read of it outside the write path. A column written and never read is collected without purpose. | Minimization finding anchored at the collection point. |
| Over-broad SELECT into a response | Look for `SELECT *`, `.findAll()` without attribute lists, or serializers that dump the whole model into an API response or template. | Excessive exposure — a client that renders three fields but receives forty leaks the other thirty-seven to anyone who opens DevTools. |
| Repurposing | Production personal data used to train a model, seed a demo, populate a test fixture, or feed an external inference API. | Purpose-limitation finding; also route to ray-vault when it involves a production data copy. |
| Free-text fields that collect more than intended | Support-ticket bodies, "observações" fields, and file uploads routinely capture sensitive data with no classification. | Note in the inventory as `UNKNOWN` classification with a recommendation to classify and redact. |

______________________________________________________________________

## 4. Consent Quality

Where consent IS the basis, it must be free, informed, unambiguous, specific to
a purpose, and revocable (LGPD art. 8 / GDPR art. 4(11) and art. 7). LGPD art. 8
§2 places the burden of proving consent on the controller — which is exactly
why the *record* matters as much as the checkbox.

### The ordering test (the one that produces defensible findings)

> Does any non-essential script, pixel, or cookie fire before a consent
> decision exists?

Trace, in load order: `<head>` partials, tag-manager containers, framework
`_document`/`_app` files, layout components, service workers, and any
`useEffect` that initializes analytics. A tracker that loads unconditionally and
is *later* "disabled" by a consent callback has already fired — that is a
finding, and the anchor is the injection line.

### Consent checklist

| Requirement | Failing shape |
|---|---|
| Opt-in, not opt-out | Checkboxes pre-checked; "by continuing to browse you agree"; a banner with only an "OK" button. |
| Refusing is as easy as accepting | "Accept all" button with rejection buried two modals deep. |
| Granular per purpose | One switch covering analytics, advertising, and personalization together. |
| Recorded | No persisted record of who consented, to what, when, and under which policy version. Store the version string — a policy change invalidates prior consent for new purposes. |
| Revocable | No UI or endpoint to withdraw; withdrawal that does not actually stop the processing or delete the cookie. |
| Not a precondition | Service refused unless the user accepts non-essential tracking, where the tracking is not necessary for the service (LGPD art. 8 §4 / art. 9 §3). |
| Children | Any `CHILDREN` data collected without the parental-consent flow of LGPD art. 14 / GDPR art. 8. |

**Essential vs. non-essential.** Session cookies, CSRF tokens, load-balancer
affinity, and consent-state storage itself are essential and need no consent.
Analytics, advertising, A/B testing, session replay, and heatmaps are not.

______________________________________________________________________

## 5. Data-Subject Rights

**LGPD art. 18** grants: confirmation that processing exists; access to the
data; correction of incomplete, inaccurate, or outdated data; anonymization,
blocking, or deletion of unnecessary, excessive, or unlawfully processed data;
portability to another provider; deletion of data processed under consent;
information about public and private entities the data has been shared with;
information about the possibility of refusing consent and its consequences; and
revocation of consent. Art. 20 adds a right to request review of decisions taken
solely on automated processing that affect the subject's interests. Requests are
free of charge (art. 18 §5); where the controller cannot act immediately it must
respond stating why (art. 18 §4), and specific deadlines are set by ANPD
regulation — for the simplified "confirmation of existence / access" reply,
art. 19 I allows an immediate response in simplified format, with the complete
declaration due within 15 days of the request.

**GDPR ch. 3** grants: transparency (arts. 12–14), access (15), rectification
(16), erasure (17), restriction (18), notification of rectification/erasure to
recipients (19), portability (20), objection (21), and rights around automated
decision-making and profiling (22). Art. 12(3) sets one month to respond,
extendable by two further months for complex requests.

### Mechanical tests

| Right | What to look for in code | Finding when absent or broken |
|---|---|---|
| Confirmation / access | An account-data or "my data" endpoint, or a documented manual process | Absent → finding anchored at the router/controller index. |
| Portability | An export producing a structured, machine-readable format (JSON/CSV), not a PDF screenshot | Absent or non-machine-readable → finding. |
| Correction | A profile-update path covering the fields actually stored | Fields the subject cannot correct → finding. |
| Erasure | A deletion path that cascades to caches, search indexes, object storage, analytics, and derived tables | A `deleted_at` soft-delete presented as erasure → finding. Backups may be excluded from immediate erasure if there is a documented rotation that eventually removes them; the absence of any such rotation is a finding. |
| Sharing disclosure | A maintained list of processors/recipients | Third-party SDKs found in Step 7 that appear in no disclosure → finding. |
| Consent revocation | An endpoint or UI that flips consent state AND stops the processing | Revocation that only hides a banner → finding. |
| Automated decisions | Scoring, ranking, pricing, or moderation decisions applied to subjects with no review path | Finding under LGPD art. 20 / GDPR art. 22. |

### Rights endpoints are exfiltration primitives

Audit every rights endpoint as an attack surface, not just as a compliance box:

- **Authorization**: `GET /api/export?user_id=…` without an ownership check is a
  bulk personal-data dump. Raise it as an access-control finding too, with a
  precise reproduction hint, so `ray-detonator` can prove it.
- **Authentication strength**: erasure or export behind a bare emailed link with
  a guessable token is both an account-enumeration oracle and an exfiltration
  channel.
- **Rate limiting**: an unmetered export endpoint is a cheap way to scrape the
  whole user table one authenticated account at a time; cross-reference
  `/ray-sentry`.
- **Verification**: an erasure endpoint that accepts an arbitrary email with no
  ownership proof is a denial-of-service against other users' accounts.

______________________________________________________________________

## 6. Retention and Erasure

Storage limitation: LGPD art. 15–16 (termination of processing and the narrow
cases where retention is allowed) and GDPR art. 5(1)(e).

| Test | Finding |
|---|---|
| Any documented or implemented retention period per data category | No retention mechanism anywhere for stored personal data → finding at the model/migration. |
| Deletion or anonymization is automated | Retention exists only as prose in a policy document with no job, TTL, or lifecycle rule → finding: unenforced retention policy. |
| Logs are covered | Access/application logs containing personal data with no rotation limit → finding (also see `/ray-seam` for what should never be logged in the first place). |
| Backups are covered | Erasure that does not eventually reach backups, with no documented rotation → finding. |
| Anonymization is real | "Anonymized" records that keep an email hash joinable to another table are pseudonymized, not anonymized (LGPD art. 12 treats reversible data as personal data) → finding. |
| Inactive accounts | No policy for accounts untouched for years → finding, severity scaled by the data classes retained. |

______________________________________________________________________

## 7. Incident Notification

The pipeline's job is to check that the *capability* exists, not to run the
notification.

**LGPD art. 48**, as regulated by **Resolução CD/ANPD nº 15 de 24 de abril de
2024**: the controller communicates a security incident that may cause relevant
risk or damage to the ANPD and to the affected subjects within **3 business
days** of becoming aware that the incident affected personal data, with a
**complementary report within 20 business days** where the initial
communication was incomplete. Records of incidents — including those not
communicated — must be kept for at least **5 years**.

**GDPR art. 33**: notify the supervisory authority without undue delay and,
where feasible, within **72 hours** of becoming aware, unless the breach is
unlikely to result in a risk to rights and freedoms. **Art. 34**: communicate to
data subjects without undue delay when the risk is high.

### Mechanical tests

| Test | Finding |
|---|---|
| Detection capability exists at all | No audit logging of access to personal data → you cannot know an incident occurred, let alone within 3 days. Finding; cross-reference `/ray-sentry` and `/ray-vault`. |
| An incident runbook exists in the repo or docs | Absent → finding (low severity, high leverage): name who is paged, how credentials are revoked, and how subjects are contacted. |
| Contactability | No stored channel to reach affected subjects (e.g. accounts with no verified email) → notification is impossible in practice. |
| Incident register | No place where incidents (including non-notified ones) are recorded and retained → finding under Res. 15/2024. |

______________________________________________________________________

## 8. International Transfer

LGPD arts. 33–36 (adequacy decisions, standard contractual clauses approved by
ANPD, binding corporate rules, specific consent, and the other hypotheses);
GDPR ch. V (arts. 44–50).

| Test | How to run it | Finding |
|---|---|---|
| Where does the data physically go? | Read IaC for region settings, and inventory every third-party SDK's processing location. | Personal data leaving the country of collection with no identified transfer mechanism → finding (documentation-level unless combined with a technical exposure). |
| Sub-processors | Cloud region + CDN + error tracker + analytics + inference API each add a jurisdiction. | Undisclosed transfer chain → finding. |
| Region pinning | A bucket, database, or queue defaulting to a region far from the stated one. | Finding at the IaC line. |

______________________________________________________________________

## 9. Processors, Sub-processors, and Third-Party Egress

Every third-party call that carries personal data creates a processor
relationship (LGPD art. 39 / GDPR art. 28) and expands the breach surface.

Enumerate and classify every outbound integration:

| Integration type | What typically leaks |
|---|---|
| Analytics / product analytics | URLs (which may contain ids or tokens), user traits, event properties assembled from records. |
| Session replay / heatmaps | Entire DOM including form fields, unless input masking is explicitly enabled — check the masking config, not the vendor's marketing default. |
| Error trackers | Request bodies, headers, cookies, local variables in stack frames. Check the scrubbing hook (`beforeSend`, `before_send`, `denyUrls`, `sendDefaultPii`). A default-on "send PII" flag is a finding. |
| Feature flags / A/B | User traits used as targeting attributes. |
| Support / CRM / email / SMS | Full contact records; often the widest export surface in the company. |
| Inference APIs (LLM/embedding) | Prompt content assembled from records, plus retrieved documents. Check for a redaction step and a stated basis; check whether the provider trains on submitted data. |
| Payment | Card data — verify the app never touches the PAN (tokenized/hosted fields) rather than that it handles it carefully. |
| CDN / WAF | Full request stream including cookies. |

**Finding shapes.** (a) Egress with no consent gate where consent is the basis;
(b) egress of a data class the integration does not need (minimization); (c)
egress with no scrubbing where the payload demonstrably carries personal data;
(d) egress to an undisclosed recipient (art. 18 II/VII).

______________________________________________________________________

## 10. Control Ledger IDs

Use these ids in `workspace/ledgers/ray-custodian.json` so passes stay
comparable. Every id below MUST appear exactly once per ledger, with a state of
`PRESENT`, `PARTIAL`, `ABSENT`, `NOT_APPLICABLE`, or `UNKNOWN`.

| ID | Control |
|---|---|
| `MAP-01` | Personal-data inventory built (fields, classification, lifecycle) |
| `MAP-02` | Sensitive / children data identified and flagged |
| `BASIS-01` | Lawful basis identifiable for every inventory field |
| `BASIS-02` | Sensitive data not processed under legitimate interest |
| `MIN-01` | No collected-but-unused personal-data fields |
| `MIN-02` | API/template responses do not over-expose record fields |
| `PURP-01` | No repurposing of production personal data (training, demos, fixtures) |
| `CONS-01` | No non-essential tracker fires before a consent decision |
| `CONS-02` | Consent is opt-in, granular, and refusal is as easy as acceptance |
| `CONS-03` | Consent recorded with timestamp, scope, and policy version |
| `CONS-04` | Consent withdrawal implemented and effective |
| `RIGHT-01` | Access / confirmation path exists |
| `RIGHT-02` | Portability export is machine-readable |
| `RIGHT-03` | Correction path covers stored fields |
| `RIGHT-04` | Erasure cascades beyond the primary row |
| `RIGHT-05` | Rights endpoints enforce ownership and are rate limited |
| `RIGHT-06` | Sharing/recipient disclosure maintained |
| `RIGHT-07` | Automated-decision review path exists where applicable |
| `RET-01` | Retention period defined per data category |
| `RET-02` | Retention enforced by an automated job / TTL / lifecycle rule |
| `RET-03` | Logs and backups covered by retention |
| `RET-04` | Anonymization is irreversible where claimed |
| `INC-01` | Access to personal data is audit-logged (detection capability) |
| `INC-02` | Incident runbook and register exist |
| `XFER-01` | Cross-border transfer mechanism identified for each destination |
| `EGRESS-01` | Third-party integrations inventoried |
| `EGRESS-02` | Scrubbing/masking configured for replay and error trackers |
| `EGRESS-03` | No personal data in URLs, query strings, or `Referer` |
| `EGRESS-04` | No unanonymized production data in non-production environments |
| `EGRESS-05` | No dangling DNS delegation to decommissioned services |
