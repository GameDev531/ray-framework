# Agent Coverage Map — the two opponents, and the charter boundary

Ray's red and blue agents are **asymmetric opponents**, and that asymmetry is a
design decision, not a limitation:

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

> Red teaches you to think like the attacker. Blue teaches you to detect,
> investigate, and respond to the attacker. Ray's red performs the local slice;
> Ray's blue detects the entire chain.

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
