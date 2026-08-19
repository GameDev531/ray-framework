# Ray Framework — Agent Routing Map

**This is the router. Read it first, then pull only the one or two skills the task
actually needs — do not read all 31 `SKILL.md` files.** Ray is a library of
single-responsibility security skills, each with a lean `SKILL.md` workflow and
deeper `references/*.md` dockets that load **only when that skill is invoked**.
Matching the task to the right skill here is what keeps context small and fast.

This file is tool-agnostic. Tool-native entry files (`CLAUDE.md`, `GEMINI.md`,
`.cursor/rules/…`) carry the loading specifics and point back here.

______________________________________________________________________

## The one rule

**Route, don't read everything.** Find the task below → invoke that skill (or open
that docket) → follow it. A skill's `SKILL.md` is a short workflow; its
`references/*.md` hold the depth and are read only at the step that needs them. For
a one-off question, go straight to the single relevant docket — do not run the
whole pipeline. Prefer the **real tools** (the `ray-tools` MCP server, or the
`scripts/*.py` helpers directly) over narrating what a tool would do.

______________________________________________________________________

## Pick by situation

### A. "Analyze this codebase for security" — the full static pipeline

Run in order; each stage writes to `workspace/` and the next reads it. Stages
degrade gracefully if an upstream one is absent.

```
1. map        ray-lattice  → ray-prism → ray-blueprint     (index, digests, knowledge base)
2. plan       ray-perimeter → ray-compass                   (threat model, review plan)
3. audit      ray-prospector + the domain suite (§C)         (static findings)
4. validate   ray-condenser → ray-arbiter → ray-magistrate   (dedupe, false-pos filter, viability)
5. prove      ray-detonator                                  (PoC / crash reproducer)
6. score      ray-gauge → ray-chronicle                      (risk score, report packet)
   (learn)    ray-retrospective                              (cross-run insights)
```

### B. Map & plan only

| Need | Skill |
|---|---|
| Structural/semantic index of the source | `ray-lattice` |
| Per-directory security digests | `ray-prism` |
| Interlinked knowledge base | `ray-blueprint` |
| Threat model (trust boundaries, attacker profiles) | `ray-perimeter` |
| A targeted review plan | `ray-compass` |

### C. Audit one security domain (pick the docket that matches the concern)

| The concern | Skill | Its docket |
|---|---|---|
| Untrusted-input canon — SQLi/NoSQL, XSS, CMDi, SSTI, XXE, deserialization, SSRF, traversal, prototype pollution, request smuggling, type juggling, HPP | `ray-crucible` | `injection_docket.md` |
| Identity & access — credential storage, sessions, **JWT/OAuth**, MFA, reset/invite, **BOLA/BFLA/tenancy**, OWASP API Top 10 | `ray-turnstile` | `identity_docket.md`, `tenancy_isolation.md` |
| Client/server trust seam — validation, mass assignment, CORS, cache poisoning, **host-header/clickjacking/CSP headers** | `ray-seam` | `seam_docket.md` |
| Abuse & observability — rate limiting, exposed internal endpoints, webhook signatures, shadow APIs | `ray-sentry` | `service_docket.md` |
| Datastore exfiltration — privileges, reachability, **encryption + crypto-primitive/PQC audit** | `ray-vault` | `datastore_hardening.md` |
| Deployed architecture — network layering, isolation, secrets management at scale | `ray-citadel` | `architecture_baseline.md` |
| Privacy & web surface — TLS/headers, cookies, consent, retention, data-subject rights | `ray-custodian` | `privacy_docket.md`, `web_surface_baseline.md` |
| Native/unsafe memory safety — OOB, UAF, double-free, integer overflow, FFI | `ray-marrow` | `memory_safety_docket.md` |
| The app's own LLM/AI feature — OWASP LLM 2025 / MITRE ATLAS, prompt injection, MCP tool poisoning, model extraction | `ray-oracle` | `llm_security_docket.md` |
| Dependencies — SBOM (CycloneDX), known-vulnerable versions, typosquats | `ray-manifest` | (drives `scripts/ray_sbom.py`) |
| IaC / cloud / **containers** — Terraform/CFN/K8s/Docker misconfig, image hardening | `ray-terrain` | `iac_docket.md` (drives `scripts/ray_iac.py`) |
| Maintenance over time — dependency EOL, patch cadence, backup+restore, DR | `ray-steward` | `maintenance_docket.md` |

### D. Beyond static review

| Need | Use |
|---|---|
| **Live attack + fix loop** against your own local app (red/blue) | `ray-siege` → agents `ray-reaver` (red), `ray-bulwark` (blue). See §Agents. |
| **External attack-surface recon** (OSINT, DNS, cert transparency), authorized | `ray-quarry` |
| **Detection & response** on a running estate (alert triage, hunting, IR) | `ray-warden` → agent `ray-vigil`. See §Agents. |
| **General code review** of a change (correctness + security delegation) | `ray-loupe` → agent `ray-scrivener` |
| **Stop secrets leaking into files/commits** (write-time guard) | `ray-cloak` |
| Build a custom deterministic orchestrator harness | `ray-foundry` |

______________________________________________________________________

## Agents (subagents with their own reading flow)

Each agent's `agents/<name>.md` opens with a **"Your reading flow (in order)"** —
follow it; it already scopes each team to its own docs.

- **`ray-reaver`** (red / offensive) — reads the *attack* side: siege gate →
  `ray_arsenal_list` → `live_exploitation.md` → `reaver_arsenal.md` → the attack
  half of the §C dockets.
- **`ray-bulwark`** (blue / fix) — reads the *fix* side: the finding →
  `bulwark_arsenal.md` (+ CI gates) → the safe-pattern half of the §C dockets →
  Ray-owned fixes.
- **`ray-vigil`** (blue / detection) — reads the *analyst* docs only:
  `autonomy_tiers.md` → `analyst_playbooks.md` (triage / class / hunt / frameworks)
  → warden `findings_contract.md`.
- **`ray-scrivener`** (code review) — dispatched by `ray-loupe`; delegates deep
  security to the §C skills.

Red reads the red docs; blue reads the blue docs. The shared §C domain dockets are
read by both siege teams for **different halves** (attack vs safe-pattern).

______________________________________________________________________

## Real tools (prefer over narration)

The `ray-tools` MCP server (`scripts/ray_mcp_server.py`) exposes helpers that
**provably run** — a call executes or errors, it cannot be faked. Where MCP is not
wired, run the same `scripts/*.py` directly with `python3` (all are stdlib-only,
zero-install).

| Tool | Does | Helper |
|---|---|---|
| `ray_metadata_extract` | Leaked metadata from PDF/Office/images (FOCA) | `ray_metadata.py` |
| `ray_memory_recall` / `_add` / `_list` | Curated cross-run agent memory | `ray_memory.py` |
| `ray_sbom_generate` | Lockfiles → CycloneDX SBOM + known-vuln flags | `ray_sbom.py` |
| `ray_iac_scan` | Bounded IaC misconfig scan | `ray_iac.py` |
| `ray_arsenal_list` / `ray_arsenal_run` | Discover + drive the red/blue pentest arsenal through the siege gate | `ray_arsenal.py` |
| `ray_secret_scan` | Redacting secret-leak scan (ray-cloak) | `ray_secrets.py` |

______________________________________________________________________

## How to go deep (only when the task needs it)

1. The router above → the **one** matching skill.
2. That skill's `SKILL.md` = the workflow (lean, always safe to read in full).
3. Its `references/*.md` dockets = the depth — read the **specific section** the
   step points to, not the whole file.
4. Findings follow each skill's `references/findings_contract.md`.

Do not pre-load dockets "to be thorough." Thoroughness here is routing precisely,
then reading deeply *only* the branch the task is on.
