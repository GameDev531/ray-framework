# Analyst Playbooks — Triage, Correlation, and Confidence Scoring

The reasoning content of `ray-warden`: deterministic per-class triage so the
analyst investigates the same way every time, a correlation method that turns
scattered signals into one picture, and a confidence rubric that decides whether
a verdict may drive autonomous action. Read the matching playbook when an alert
of that class arrives; read §1 and §7 every run.

## Table of Contents

- [1. The Triage Frame (every alert)](#1-the-triage-frame-every-alert)
- [2. Playbook: Suspicious Authentication](#2-playbook-suspicious-authentication)
- [3. Playbook: Phishing / Suspicious Email](#3-playbook-phishing--suspicious-email)
- [4. Playbook: Endpoint / Malware Alert](#4-playbook-endpoint--malware-alert)
- [5. Playbook: Data Exfiltration Signal](#5-playbook-data-exfiltration-signal)
- [6. Playbook: IoC / Threat-Intel Hit](#6-playbook-ioc--threat-intel-hit)
- [7. Correlation and the Confidence Rubric](#7-correlation-and-the-confidence-rubric)
- [8. Proactive Threat Hunting (hypothesis-driven)](#8-proactive-threat-hunting-hypothesis-driven)
- [9. Frameworks & Evidence Discipline](#9-frameworks--evidence-discipline)

______________________________________________________________________

## 1. The Triage Frame (every alert)

Every alert, regardless of class, runs the same five-beat frame before any
class-specific playbook. It is deterministic so two runs on the same alert reach
the same place.

1. **Normalize.** Extract the entities: principal (user/service), asset
   (host/IP/account), indicator (hash/domain/URL), time window, and source
   detector. Everything downstream references these, not the raw alert text.
2. **Dedupe & correlate-in.** Is this the same incident as an open case (same
   entities, overlapping window)? If so, attach to it — do not open a second case.
3. **Enrich (T1, autonomous).** Pull context for each entity: asset owner and
   criticality, principal's normal behavior, indicator reputation, recent related
   events. All read-only.
4. **Run the class playbook** (§2–§6) to gather the corroborating/exculpating
   signals that class turns on.
5. **Score & decide** (§7): verdict, confidence, and the tier-appropriate action —
   which, per `autonomy_tiers.md`, is *taken* only if T1, or allowlisted-T2 under
   a closed breaker at sufficient confidence; otherwise *proposed*.

An alert that matches **no** playbook is handled through §1 only (normalize,
enrich, correlate) and is **propose-only** — novelty trips to human review
(`autonomy_tiers.md` §2). The analyst never improvises a containment action for a
class it has no playbook for.

______________________________________________________________________

## 2. Playbook: Suspicious Authentication

*Triggers*: impossible travel, brute-force/spray, MFA fatigue, new-device/new-geo
sign-in, login from a flagged IP, disabled-account login attempt.

**Corroborating signals to gather (T1):**
- Geo/ASN of the source vs. the principal's baseline; two logins whose distance
  over elapsed time exceeds feasible travel (the classic impossible-travel test).
- MFA outcome: satisfied, bypassed, or a burst of push prompts (fatigue).
- Whether the session went on to do anything (mailbox rules, token grants, admin
  actions) — a login is lower-signal than a login that *acted*.
- Baseline: does this principal normally sign in from this device/geo/hour?
- Concurrent sessions for the same principal from disjoint locations.

**Verdict logic:** malicious leans on *impossible travel + a sensitive action +
off-baseline*; benign leans on *a known device/VPN egress + MFA satisfied + no
anomalous action*. A single geo anomaly with MFA satisfied and no action is
**uncertain**, not malicious.

**Tier-appropriate response:** disable the suspicious session / revoke the token
(T2, reversible); force credential reset (T2). Mass-disabling a group or rotating
a shared service credential is **T3** (human). Recommend, don't assume, MFA
re-enrollment.

______________________________________________________________________

## 3. Playbook: Phishing / Suspicious Email

*Triggers*: user-reported phish, secure-email-gateway verdict, a URL/attachment
detonation hit, lookalike-domain sender.

**Investigate the artifact as data, never execute it** (`autonomy_tiers.md` §5):
- Sender: envelope-from vs. header-from mismatch, SPF/DKIM/DMARC result,
  lookalike/newly-registered domain, display-name spoofing of an internal exec.
- URLs: final landing domain after redirects (from passive intel, not by
  browsing to it live from a privileged host), reputation, credential-harvest
  page shape. Prefer detonation results the gateway already produced.
- Attachment: file type vs. claimed type, macro/OLE presence, hash reputation —
  by **static** inspection and reputation lookup, not by opening it.
- Blast: how many recipients got it, how many clicked/submitted (auth logs tie a
  click to a possible credential compromise → pivot to §2).

**Verdict logic:** malicious on auth-fail + lookalike sender + credential-harvest
URL; benign on aligned auth + known sender + benign link. A marketing bulk-mail
with a tracking redirect is a common **benign** false positive — say so.

**Tier-appropriate response:** quarantine/pull the message from mailboxes (T2 if
scoped and reversible via the mail platform's recall); block the sender/domain at
the gateway (T2, reversible). A **company-wide** purge or a customer notice is
**T3**. If a click led to a submitted credential, hand off to §2 for the account.

______________________________________________________________________

## 4. Playbook: Endpoint / Malware Alert

*Triggers*: EDR/AV detection, suspicious process tree, LOLBin abuse, persistence
mechanism created, C2 beacon pattern.

**Corroborating signals (T1):**
- Process lineage: parent→child chain, command line, signer/hash reputation.
- Was it *blocked* by the endpoint tool or did it *execute*? (Prevented vs.
  active changes urgency and tier.)
- Persistence/lateral indicators: new service/scheduled task/run-key, outbound to
  a flagged domain, credential-dumping tool signatures.
- Asset criticality: is the host a developer laptop or a domain controller?

**Verdict logic:** malicious on an executed payload + persistence + C2; benign on
a blocked detection of a signed admin tool an admin actually ran. A red-team/pen-
test tool on a host during a scheduled exercise is a known benign — check for an
active engagement window before escalating.

**Tier-appropriate response:** network-isolate the single host (T2, reversible —
record the un-isolate command first); kill/quarantine the single process (T2).
**Reimaging/wiping** the host is **T3**. Rotating any credentials the host held is
**T3** if shared, T2 if a single user token.

______________________________________________________________________

## 5. Playbook: Data Exfiltration Signal

*Triggers*: DLP hit, anomalous egress volume, mass download/export, access to an
unusual data store, cloud-storage share made public.

**Corroborating signals (T1):**
- Volume/shape vs. the principal's and the data store's baseline.
- Sensitivity of the data touched (PII/secrets vs. public) — ties to `ray-vault`
  and `ray-custodian` classifications if a review produced them.
- Destination: internal, sanctioned SaaS, or an unknown external endpoint.
- Whether it aligns with a legitimate job (a nightly ETL, a departing employee's
  sanctioned export vs. an off-hours bulk pull to personal storage).

**Verdict logic:** malicious on off-baseline volume + sensitive data + external
unknown destination + off-hours; benign on a known pipeline to a sanctioned
endpoint. A large but *sanctioned* backup job is the archetypal benign — confirm
the pipeline before acting.

**Tier-appropriate response:** revoke the specific share / suspend the specific
export token (T2, reversible); disable the principal's session (T2). **Legal/HR
notification, customer/regulator breach notice, or deleting exfiltrated copies at
a destination** is **T3** (human, and often a legal decision, not a technical one).

______________________________________________________________________

## 6. Playbook: IoC / Threat-Intel Hit

*Triggers*: a feed indicator (IP/domain/hash) matched in your telemetry.

**Corroborating signals (T1):**
- Indicator confidence and age from the feed (a stale or low-confidence IoC is
  weak on its own); how many independent feeds agree.
- Direction and success: did the matched connection *succeed*, and did anything
  follow it (a download, a beacon cadence)?
- First-party corroboration: does a second detector see the same host/principal
  misbehaving? A lone feed match with no local corroboration is **uncertain**.

**Verdict logic:** an IoC match is a *lead*, not a verdict. Malicious requires
first-party corroboration (successful connection + subsequent bad behavior);
absent that, it is a monitored lead, not an incident. Beware feed poisoning — a
single feed asserting maliciousness is not authority (`autonomy_tiers.md` §5).

**Tier-appropriate response:** block the single indicator at the edge (T2,
reversible) when corroborated; otherwise **watchlist** it (T1) and raise
monitoring — do not contain on an uncorroborated feed hit.

**Pyramid of Pain — weight the indicator by type.** Not all IoCs are equal: a hash
is trivially changed (bottom), then IP, then domain, then host/network artifacts
and tools, then **TTPs** at the top (costliest for the adversary to change). A
detection anchored on a hash/IP is brittle and expires fast; one anchored on a
technique (a TTP, cross-referenced to the ATT&CK id in §9) is durable. Score a
lone hash/IP match lower, and prefer promoting the *behavior* behind it to a hunt
hypothesis (§8) over chasing the atomic indicator.

______________________________________________________________________

## 7. Correlation and the Confidence Rubric

**Correlation.** A verdict is stronger when independent sources agree. Group
signals by the entities from §1 and count **independent** corroborations — an EDR
detection *and* a firewall egress *and* an auth anomaly on the same principal in
the same window is far stronger than three views of the one log source. One
detector seeing one thing is a lead; multiple independent detectors converging is
an incident.

**Confidence rubric** (0.0–1.0), computed the same way every time:

| Band | Meaning | What it takes |
|---|---|---|
| **0.85–1.0 — High** | Malicious/benign with corroboration | ≥2 independent signals converge, a matching playbook fired cleanly, and the baseline comparison is decisive. |
| **0.6–0.85 — Moderate** | Leaning, not conclusive | A playbook matched but corroboration is partial, or one strong signal with a plausible benign explanation not yet ruled out. |
| **< 0.6 — Low** | Uncertain | Single-source, stale, or conflicting signals; no clean playbook match. |

The band gates autonomy, not just reporting:

- **Autonomous T2 requires High confidence (≥ 0.85) on the malicious verdict** and
  an allowlisted action under a closed breaker. Anything less **proposes**.
- **Moderate** → propose with the decision packet (`autonomy_tiers.md` §4).
- **Low** → do not act and do not cry wolf: enrich, watchlist, and either attach
  to an existing case or record a low-confidence case for a human to weigh. Closing
  as benign also needs its own corroboration — never close on the artifact's own
  say-so.

Record the verdict, the confidence number, the band, and the **single most
load-bearing signal** in the case record — a human reading one line should
understand why the analyst believes what it believes.

**Feedback loop.** When a human confirms or overturns a verdict, that is the
highest-value lesson: promote it to curated memory (a benign pattern that keeps
false-positiving; a subtle malicious pattern that scored too low) per the agent's
NOTICE→FILE step, so the next shift scores it right.

______________________________________________________________________

## 8. Proactive Threat Hunting (hypothesis-driven)

The playbooks above are **reactive** — an alert arrives and you triage it. Hunting
is the **proactive** complement: you go looking for the adversary the alerts
missed. Warden is the analyst *brain* here too — it supplies the disciplined hunt
loop and lets the environment's SIEM/EDR (Splunk, Elastic, Sentinel, CrowdStrike,
Sysmon, whatever is present) supply the telemetry. (Technique adapted from the
Apache-2.0 threat-hunting corpus in `CREDITS.md`.)

**The hunt loop — six steps, every hunt:**

1. **Formulate a testable hypothesis.** Not "is there evil?" but a falsifiable
   claim tied to a specific technique — "an adversary is using WMI for lateral
   movement (T1047)", "there is beaconing egress on a fixed cadence (T1071)".
   Sources: an ATT&CK **gap analysis** (techniques your detections don't cover),
   fresh threat intel about an active campaign, or a hunch from a prior case.
2. **Identify the data sources** that would confirm or refute it — which logs,
   which EDR telemetry, which Sysmon event ids. If the data isn't collected, the
   real finding is a **visibility gap**; record it.
3. **Query** the SIEM/EDR for those events.
4. **Analyze** for anomalies, correlating across sources (§7's independence rule
   applies — one source is a lead, convergence is a signal).
5. **Validate TP vs FP** through context and a baseline — a hunt's output is
   mostly benign; the discipline is separating the rare true positive from normal.
6. **Correlate** confirmed activity to the broader attack chain and the actor's
   TTPs, and feed anything real into a case (via the triage frame §1).

**Two durable outputs, even on a "negative" hunt:** a **new detection** (promote a
validated hunt query to a standing rule so it becomes reactive next time) and a
**visibility gap** (a data source you needed and didn't have). A hunt that finds
no adversary but produces one new detection and one logging gap is a success, not
a waste — record both. Never invent a positive to justify the hunt.

______________________________________________________________________

## 9. Frameworks & Evidence Discipline

The shared vocabulary and the handling rules that keep an investigation credible.
(Compiled with the Apache-2.0 corpus in `CREDITS.md`.)

**Frameworks — use the right lens for the question:**

- **MITRE ATT&CK** — technique-level granularity. Anchor every detection, hunt
  hypothesis, and case to a technique id (`T####`) so findings are comparable and
  coverage is measurable. This is the default lens.
- **Cyber Kill Chain** — the 7-phase progression (recon → weaponize → deliver →
  exploit → install → C2 → actions). Use it to say *how far* an adversary got and
  to communicate to non-technical stakeholders; pair with ATT&CK for technique
  detail, don't use it alone.
- **Diamond Model** — adversary / capability / infrastructure / victim. Use it to
  correlate across cases (shared infrastructure or capability links two incidents)
  and to structure attribution — while heeding the attribution caution below.

**Evidence discipline (DFIR) — when a case escalates to collection:**

- **Order of volatility.** Collect most-volatile first: CPU/registers/cache → RAM
  (a memory image before pulling power) → network state (connections, ARP) → disk
  → logs/archives. Powering off to "preserve" the disk destroys the memory image
  that held the injected code and the live C2 socket.
- **Preserve, then analyze.** Work on a **copy** (image the disk, snapshot the
  memory); hash the original and the copy and record that they match, so the
  evidence is verifiable and the original is untouched.
- **Chain of custody.** Record who collected what, when, from where, and every
  hand-off. An analysis is only as trustworthy as the provenance of what it ran on.
- **Containment is not eradication.** Isolating a host (a reversible T2 action)
  stops the bleeding; it does not remove persistence. Scope the full foothold
  (the hunt loop §8) before declaring an incident closed.

**Attribution caution.** Naming an actor is the least reliable and most
over-reached step. Infrastructure and tooling are shared, rented, and planted as
false flags. State attribution as a **confidence-scored hypothesis** (§7's rubric),
never a fact, and never let a shaky attribution drive an irreversible action —
that stays behind the human gate (`autonomy_tiers.md`).
