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

Per the Apache-2.0 terms, the upstream copyright notices and license are
preserved by this attribution; the upstream `LICENSE` (Apache-2.0) is compatible
with this project's MIT license for the adapted, non-verbatim technique material.
The authors of the upstream skills (credited in each upstream skill's frontmatter)
retain credit for the original technique write-ups.
