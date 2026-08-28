# Credits & Third-Party Attribution

The Ray Framework is original work, but some of its **domain dockets** were
enriched with attack/defense technique material adapted from third-party
open-source security-skill corpora. This file records that attribution as those
licenses require. Nothing here is copied verbatim — the material was rewritten to
fit Ray's dockets, conventions, and its local-only, non-destructive charter — but
the underlying technique knowledge and its standards mappings deserve credit.

## mukul975/anthropic-cybersecurity-skills

- **Source:** https://github.com/mukul975/anthropic-cybersecurity-skills
- **License:** Apache License 2.0
- **Used for:** enrichment of the web/API/LLM attack-technique dockets — the
  MITRE ATT&CK / MITRE ATLAS / OWASP (Web & API & LLM 2025) standards mappings and
  several modern technique specifics.
- **Where it landed in this repo (adapted, not copied):**
  - `ray-oracle/references/llm_security_docket.md` — OWASP LLM 2025 / MITRE ATLAS
    map; indirect-injection hiding channels; MCP tool poisoning; model
    extraction/inversion/membership; vector & embedding weaknesses.
  - `ray-turnstile/references/identity_docket.md` — JWT header-parameter attacks
    (kid/jku/x5u), algorithm confusion, OAuth2 flaws; OWASP API Top 10 map.
  - `ray-crucible/references/injection_docket.md` — SSTI, XXE, insecure
    deserialization, prototype pollution, HTTP request smuggling, type juggling.
  - `ray-seam/references/seam_docket.md` — web cache poisoning/deception, CORS,
    host-header injection, clickjacking, CSP bypass, WebSocket.
  - `ray-warden/references/analyst_playbooks.md` — proactive hypothesis-driven
    threat hunting; ATT&CK / Cyber Kill Chain / Diamond framing; DFIR evidence
    discipline (order of volatility, chain of custody); Pyramid of Pain.
  - `ray-cloak/references/secret_hygiene_docket.md` — CI / pre-commit secret-scan
    gate (shift-left).
  - `ray-terrain/references/iac_docket.md` — container-image hardening checklist
    and image CVE scanning (trivy/grype/dockle).
  - `ray-siege/references/bulwark_arsenal.md` — shift-left CI gates that keep a
    fix closed (SAST/DAST/secret/SCA/IaC in the pipeline).
  - `ray-vault/references/datastore_hardening.md` — cryptographic-primitive audit
    checklist and post-quantum (harvest-now-decrypt-later) readiness.
  - `ray-siege/references/live_exploitation.md` — container-escape-to-host as an
    in-charter reaver escalation (proven with a host-side canary).

## Canonical security corpora referenced (not copied)

The agent dockets point analysts and operators at well-known community and vendor
security corpora **by name and URL** — they are cited as references to consult, not
copied into this repo. Each is governed by its own upstream license; consult the
project for terms. Referenced in:

- `ray-siege/references/reaver_arsenal.md` §4 — PayloadsAllTheThings, SecLists,
  OWASP Cheat Sheet Series, The Hacker Recipes (web/API sections only).
- `ray-siege/references/bulwark_arsenal.md` §5 — OWASP Cheat Sheet Series, OWASP
  SKF, OWASP ModSecurity Core Rule Set.
- `ray-warden/references/analyst_playbooks.md` §10 — Sigma, YARA, MITRE ATT&CK
  STIX data, Atomic Red Team, osquery, Velociraptor, Volatility 3, Chainsaw, Zeek,
  Suricata, Arkime, Wazuh, Security Onion.

Off-charter offensive corpora from the same source list (Metasploit, Impacket,
BloodHound, CrackMapExec, Responder, Evilginx2, Mimikatz, WinPEAS, Caldera) are
deliberately **not** integrated — they fall outside Ray's local-only,
non-destructive charter; the dockets say so and why.

Additional subject-index corpora used as a **gap map** to size the agents'
coverage (referenced, not copied):

- paulveillard/cybersecurity, yeyintminthuhtut/Awesome-Red-Teaming,
  A-poc/BlueTeam-Tools — mapped in `docs/coverage-map.md` (per-agent
  covered / in-charter-gap / off-charter status).
- LOLBAS (lolbas-project.github.io) and GTFOBins (gtfobins.github.io) —
  living-off-the-land detection references in `ray-warden` §11.
- web-quality-skills (the QA methodology, rubric, and field-tested browser
  gotchas), agent-browser, and browser-use / browser-harness — adapted into
  `ray-vantage`'s `browser_ops.md` and `coherence_and_qa.md` (the real-browser
  driving method, the 1–5 QA rubric, and the output format). Referenced/adapted,
  not copied; each project keeps its own license.
- eudk/awesome-cybersecurity-tools — used as a tool index to source the
  missing in-charter tools: `dalfox` (XSS) and `tplmap` (SSTI) added to the
  runnable arsenal (`scripts/ray_arsenal.py`, `reaver_arsenal.md` §2), plus
  `schemathesis`/`kiterunner`/`dirsearch`/CMS-scanners/`mitmproxy` as reaver
  references (§4) and the DFIR/intel platforms (Autopsy, plaso/Timesketch, KAPE,
  MISP, OpenCTI) in `ray-warden` §10. Off-charter categories (AD/Windows,
  wireless, C2, tunneling/pivoting, RE) were reviewed and excluded.

## Apache-2.0 attribution (continued)

Per the Apache-2.0 terms, the upstream copyright notices and license are
preserved by this attribution; the upstream `LICENSE` (Apache-2.0) is compatible
with this project's MIT license for the adapted, non-verbatim technique material.
The authors of the upstream skills (credited in each upstream skill's frontmatter)
retain credit for the original technique write-ups.
