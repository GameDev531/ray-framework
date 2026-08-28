# Agent Coverage Map — the opponents, the referee, and the charter boundary

Ray's agents fall into three roles: two **asymmetric opponents** (red and blue) and
a **referee** (green) that checks the product actually works and that the fixes
held. The red/blue asymmetry is a design decision, not a limitation:

- **Red (`ray-reaver`) — think like the attacker, *within the local slice*.** It
  breaks into the disposable local app for real, proving each entry with a canary.
  It performs the part of the attacker's playbook that fits a local-only,
  non-destructive, single-app engagement: reconnaissance, enumeration, web/API
  exploitation, and escalation *on the disposable target*.
- **Blue (`ray-bulwark` fixes the code; `ray-warden`/`ray-vigil` detect and
  respond) — must understand the *whole* attacker playbook.** A defender cannot
  detect what it does not understand, so the blue side carries knowledge of the
  full kill chain — persistence, lateral movement, C2, defense evasion — as
  **detection targets**, even for tactics the red reaver never performs.

- **Green (`ray-vantage`/`ray-usher`) — the referee at the user's seat.** It neither
  attacks nor detects: it drives the running app in a real browser like a person,
  proving the product actually works end-to-end (front-to-back coherence — a
  backend feature with no button is as real a failure as a vulnerability), and
  **re-verifying that the blue team's fixes hold when the app is operated by hand**.
  It closes UI wiring gaps; it reports, but never patches, a security regression.

> Red teaches you to think like the attacker. Blue teaches you to detect,
> investigate, and respond to the attacker. Green checks that, after all of it, the
> product still works for a real user and the fixes actually hold. Ray's red
> performs the local slice; Ray's blue detects the entire chain; Ray's green sits in
> the user's chair.

This file maps the three community subject-indexes the maintainers reviewed
(paulveillard/cybersecurity, yeyintminthuhtut/Awesome-Red-Teaming, A-poc/
BlueTeam-Tools) to where each subject lives in Ray — or why it is deliberately out
of scope.

______________________________________________________________________

## Red-team subjects (Awesome-Red-Teaming map)

| Subject | Ray status |
|---|---|
| **Fundamentals** (Linux, Windows, networks, TCP/IP, DNS, HTTP, PowerShell, Bash, Python) | Background knowledge the host model already has — not agent capability. Not a docket. |
| **Pentest › Reconnaissance** | `ray-quarry` (external, scope-attested) + reaver recon tools (`nmap`, `httpx`). ✅ |
| **Pentest › Enumeration** | reaver arsenal (`ffuf`, `arjun`, `nuclei`, `nikto`). ✅ |
| **Pentest › Vulnerabilities** | The whole static domain suite (`ray-crucible`/`turnstile`/`seam`/…). ✅ |
| **Pentest › Exploitation in a lab** | `ray-siege` live loop against the disposable local app. ✅ |
| **Pentest › Web security** | `reaver_arsenal.md` + the enriched injection/identity/seam/oracle dockets. ✅ |
| **Red Team › Initial Access** | ✅ **This is what the reaver does** — the proven web/API break-in *is* Initial Access. |
| **Red Team › Execution / local Privilege Escalation** | ✅ In-charter *on the disposable target* (`live_exploitation.md` §4, incl. container-escape). |
| **Red Team › Persistence, Credential Access, Lateral Movement, C2, Defense Evasion** | ⛔ **Off-charter for the siege.** These are persistent, multi-host, evasion-oriented tactics that require a lab of several machines and a human-in-the-loop gate, and are destructive/persistent by nature — the opposite of the siege's non-destructive local charter. The reaver **reports** them as *impact* ("a real adversary would now do X") but does not perform them (`reaver_arsenal.md` §5). A different engagement model (adversary emulation with a human gate) would be a separate tool, which `ray-siege` is not. |
| **Advanced › MITRE ATT&CK** | ✅ Anchored throughout (reaver positioning, warden §9/§11). |
| **Advanced › Active Directory attacks** | ⛔ Off-charter (no AD in a single local web/API/LLM app). |
| **Advanced › Threat emulation / Red Team Operations** | ⛔ Off-charter engagement model (see above). |

**Verdict (red):** the reaver is **complete for its charter**. The gaps are all the
off-charter enterprise-adversary tactics, which are out of scope *by construction*,
not by omission. The one improvement worth making is **framing**: the reaver should
know where its break-in sits in the full chain and report the rest as impact —
added in `reaver_arsenal.md` §5.

______________________________________________________________________

## Blue-team areas (BlueTeam-Tools map)

Blue is where the real, in-charter gaps were — a defender must cover the whole
chain.

| Area | Ray status |
|---|---|
| **Threat Hunting** | `analyst_playbooks.md` §8 (hypothesis-driven hunt loop). ✅ |
| **Network Discovery** (Nmap, Nuclei, Masscan, Shodan…) | Partially — as *blue* asset-discovery / rogue-host detection it now anchors in §11; the tools themselves are the reaver's/quarry's. ✅ |
| **Vulnerability Management** (OpenVAS, Nessus, Lynis) | Owned by the static pipeline (`ray-manifest`/`terrain`/`prospector`), not the analyst. Cross-referenced. ✅ |
| **Security Monitoring** (Sysmon, Kibana, Velociraptor, SysmonSearch) | §10 (analyst-driven telemetry platforms). ✅ |
| **Threat Intelligence** (Maltego, MISP, ThreatConnect) | §6 (IoC playbook) + §9 (Pyramid of Pain, intel lifecycle). ✅ |
| **Incident Response** | §9 (DFIR evidence discipline) + now the **PICERL lifecycle** frame in §11. ✅ |
| **Malware Analysis** (VirusTotal, IDA, Ghidra, YARA) | §4 (endpoint/malware playbook, static) + §10 (YARA). Deep RE (IDA/Ghidra) is a specialist bench outside the analyst brain — noted. ✅ |
| **Threat Detection** (LOLBAS, GTFOBins, YARA, Chainsaw, CyberChef, PersistenceSniper) | §10 (Sigma/YARA/Chainsaw) **+ new §11 living-off-the-land (LOLBAS/GTFOBins) detection**. ✅ |

**Verdict (blue):** the genuine gap was **detecting the full kill chain** — the
tactics the reaver never performs but a real adversary does. Filled in
`analyst_playbooks.md` §11 (kill-chain-as-detection-targets, LOLBAS/GTFOBins,
PICERL).

______________________________________________________________________

## The boundary, stated plainly

Ray's siege is an **authorized, local-only, non-destructive** exercise against your
own disposable app. That is what makes it safe to run as a defensive tool. The
enterprise red-team kill chain (AD, C2, lateral movement, persistence, evasion) is
a different, higher-authority engagement that needs a multi-host lab and a human on
every irreversible step — Ray does not pretend to be that, and the reaver will not
drift into it. The blue side, by contrast, is expected to **understand and detect
all of it**, because detection has no such blast radius. That is the asymmetry, and
it is deliberate.

______________________________________________________________________

## Green — the referee at the user's seat (`ray-vantage` / `ray-usher`)

A third role, outside the attack/defend duel: **does the thing actually work for a
person, and did the fixes survive contact with a real browser?** This is the gap
neither opponent covers — the red team proves a hole exists, the blue team writes a
fix, but neither one sits in the user's chair and *operates the product*. An app can
be provably secure and still be broken (a `/scan` endpoint the UI never exposes),
or a fix can look right in the diff and fail in the browser.

| Concern | Ray status |
|---|---|
| **Front-to-back coherence** — every backend capability reachable through the UI; no dead buttons; results actually render | `ray-vantage` builds the capability↔affordance matrix and drives a real browser to confirm each; gaps are fixed as minimal frontend wiring (`ray-usher`). ✅ |
| **End-to-end "it works"** — core user flows complete, with console/network failures caught (not just what a screenshot shows) | `ray-usher` drives the pre-installed Chromium, scores 1–5 with evidence. ✅ |
| **Fixes hold from the user's seat** — the IDOR really 403s, the stored XSS really renders inert, when driven by hand | `ray-vantage` re-verifies siege/domain findings through the running UI (report-only; a regression routes back to `ray-siege`/`ray-bulwark`). ✅ |
| **Accessibility / performance / SEO quality** | ⛔ Out of scope — dedicated tools own these; green is about *works* and *fixes-held*, not broader web-quality. |

**Where green sits in the flow.** It runs **after** a build and **after** the blue
team has patched — it is the "walk the floor before opening" pass. Its charter
mirrors the others' discipline: evidence-first (no on-screen proof, no verdict),
own-software-only, and it **fixes only its own domain** (UI wiring), reporting
security regressions rather than patching them — the same read/act separation that
keeps `ray-vigil` from pulling the switch it recommends.

**The three-role summary.**

| Role | Agent(s) | Performs | Never |
|---|---|---|---|
| 🔴 Red | `ray-reaver` | Initial Access + local escalation on the disposable app | The rest of the kill chain (reports it as impact) |
| 🔵 Blue | `ray-bulwark`, `ray-vigil` | Fix the code; detect & investigate the whole chain | Attack; act on an irreversible step without the gate |
| 🟢 Green | `ray-usher` | Operate the app as a user; close UI wiring gaps; confirm fixes hold | Attack, detect, or patch security; invent backend features |
