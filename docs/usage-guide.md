# Ray Framework — Usage Guide (when to use what, and the full-audit flow)

The operating manual for Ray: **when to use each skill, when to use each agent,
and the exact order to run a complete audit** — both the static skill pipeline and
the agents' live tool flow. For the one-line router, see [`AGENTS.md`](../AGENTS.md);
for the charter boundary of the two agents, see [`coverage-map.md`](./coverage-map.md).

- **31 skills** — single-responsibility stages and domain auditors.
- **4 agents (subagents)** — `ray-reaver`, `ray-bulwark`, `ray-vigil`, `ray-scrivener`.
- **Real tools** — the `ray-tools` MCP server / `scripts/*.py` (provably run).

______________________________________________________________________

## Part 1 — When to use each SKILL

Skills are grouped by role. Auto-trigger by description, or invoke `/ray-<name>`.

### 1a. Pipeline — map & plan (run first, in order)

| Skill | Use it when | Produces |
|---|---|---|
| **`ray-lattice`** | You have a codebase and need a structural/semantic index before any analysis | A content-addressed unit index |
| **`ray-prism`** | The index exists and you want per-directory security digests to focus planning | `ray-prism.md` digests |
| **`ray-blueprint`** | You need an interlinked knowledge base of the system to reason over | The KB |
| **`ray-perimeter`** | You need a threat model — trust boundaries, attack surfaces, attacker profiles | A living threat model |
| **`ray-compass`** | The threat model exists and you need a *targeted* review plan (what to look at, in what order) | `workspace/plan.json` |

### 1b. Pipeline — audit (the domain suite; run the ones that fit the target)

| Skill | Use it when the concern is… |
|---|---|
| **`ray-prospector`** | General static audit driven by the plan (the generalist sweep) |
| **`ray-crucible`** | Untrusted input — SQLi/NoSQL, XSS, CMDi, SSTI, XXE, deserialization, SSRF, traversal, prototype pollution, request smuggling, type juggling, HPP |
| **`ray-turnstile`** | Identity & access — credential storage, sessions, JWT/OAuth, MFA, reset/invite, BOLA/BFLA/tenancy, OWASP API Top 10 |
| **`ray-seam`** | The client/server trust boundary — validation, mass assignment, CORS, cache poisoning, host-header/clickjacking/CSP headers |
| **`ray-sentry`** | Abuse & observability — rate limiting, exposed internal endpoints, webhook signatures, shadow APIs |
| **`ray-vault`** | Datastore exfiltration — DB privileges, network reachability, encryption + crypto-primitive/PQC audit |
| **`ray-citadel`** | Deployed architecture — network layering, isolation, secrets management at scale |
| **`ray-custodian`** | Privacy & web surface — TLS/headers, cookies, consent, retention, data-subject rights |
| **`ray-marrow`** | Native/unsafe memory safety — OOB, UAF, double-free, integer overflow, FFI (C/C++/Rust-unsafe) |
| **`ray-oracle`** | The app's own LLM/AI feature — OWASP LLM 2025 / MITRE ATLAS, prompt injection, MCP tool poisoning, model extraction |
| **`ray-manifest`** | Dependencies — SBOM (CycloneDX), known-vulnerable versions, typosquats |
| **`ray-terrain`** | IaC / cloud / containers — Terraform/CFN/K8s/Docker misconfig, image hardening |
| **`ray-steward`** | Maintenance over time — dependency EOL, patch cadence, backup+restore, DR readiness |
| **`ray-counsel`** | Legal/compliance surface — AI disclosure (FTC), advertising claims, ToS + arbitration/class-action, privacy data-map, third-party SDK flows, Apple/Google privacy labels, consumer protection (jurisdiction-first; not legal advice) |

> **Pick by concern, not all at once.** For a web SaaS you'd typically run
> custodian + turnstile + crucible + seam + sentry + vault + citadel (+ manifest +
> terrain). Skip `ray-marrow` unless there's native code; skip `ray-oracle` unless
> there's an LLM feature.

### 1c. Pipeline — validate → prove → score (run after the audit)

| Skill | Use it when |
|---|---|
| **`ray-condenser`** | Raw findings exist and need dedup/merge across the domain sweeps |
| **`ray-arbiter`** | Consolidated findings need the false-positive filter (guilty-until-disproven review) |
| **`ray-magistrate`** | Validated findings need a viability judgment (filter debug-only/assertion/test-only paths) |
| **`ray-detonator`** | A viable finding needs a **reproduced** proof (PoC / crash reproducer, sanitizer trace) |
| **`ray-gauge`** | Findings are processed and need the final evidence-based risk score |
| **`ray-chronicle`** | The review is done and you need the human-readable report packet |
| **`ray-retrospective`** | End of a loop — extract cross-run learnings |

### 1d. Standalone skills (use any time, outside the pipeline)

| Skill | Use it when |
|---|---|
| **`ray-siege`** | You want a **live** attack+fix loop against your own locally-running app (dispatches the agents) |
| **`ray-quarry`** | You need **external** attack-surface recon (OSINT/DNS/cert transparency) on assets you own/are authorized to assess |
| **`ray-warden`** | You need **detection & response** on a running estate — alert triage, hunting, IR (dispatches `ray-vigil`) |
| **`ray-loupe`** | You want a **general code review** of a change (dispatches `ray-scrivener`, delegates deep security to the suite) |
| **`ray-vantage`** | You need to know the built app **actually works for a user** — front-to-back coherence (missing/dead buttons), real-browser QA, and re-verifying fixes hold in the UI (dispatches `ray-usher`) |
| **`ray-cloak`** | You're writing/editing files and must **not leak secrets** — a write-time guard + `ray_secret_scan` sweep |
| **`ray-foundry`** | You want to build your own deterministic orchestrator harness |

______________________________________________________________________

## Part 2 — When to use each AGENT

Agents are **subagents** dispatched by a parent skill (never standalone). Each has
its own isolated context, curated memory, and a **reading flow** in `agents/<name>.md`.

| Agent | Team | Dispatched by | Use it when | Reads |
|---|---|---|---|---|
| **`ray-reaver`** | 🔴 Red (offensive) | `ray-siege` | You need something **actually broken into** on the local disposable app, proven with a canary | The *attack* side: siege gate → `ray_arsenal_list` → `live_exploitation.md` → `reaver_arsenal.md` → the attack half of each domain docket |
| **`ray-bulwark`** | 🔵 Blue (fix) | `ray-siege` | A proven break-in needs a **minimal, idiomatic code fix** committed | The *fix* side: the finding → `bulwark_arsenal.md` (+ CI gates) → the safe-pattern half of the domain docket → Ray-owned fixes |
| **`ray-vigil`** | 🔵 Blue (detection) | `ray-warden` | An alert/case needs **investigation → scored verdict → tier-appropriate recommendation** (read-only) | The *analyst* docs: `autonomy_tiers.md` → `analyst_playbooks.md` (triage/class/hunt/frameworks/kill-chain) → warden `findings_contract.md` |
| **`ray-scrivener`** | ⚪ Review | `ray-loupe` | A code change needs a **high-precision review** with security delegated to the suite | The change + the relevant domain dockets |
| **`ray-usher`** | 🟢 QA | `ray-vantage` | The app must be **proven to work for a user** — drive a real browser, close wiring gaps, confirm fixes hold | `browser_ops.md` → `coherence_and_qa.md` → the domain docket (for security-hold semantics) |

**The red/blue asymmetry (by design):** the reaver *performs* only the local slice
(Initial Access + local escalation) and *reports* the rest of the kill chain as
impact; the blue side must *detect* the whole chain. Full rationale in
[`coverage-map.md`](./coverage-map.md).

______________________________________________________________________

## Part 3 — The ideal flow for a COMPLETE audit

A complete audit has **two tracks**. Run the static track always; add the live
track when you have a runnable app and want proof-by-exploitation.

### Track A — Static audit (the skill pipeline)

```
   ┌─ MAP ────────────────────────────────────────────────┐
   │ ray-lattice → ray-prism → ray-blueprint               │  index → digests → KB
   └───────────────────────────┬──────────────────────────┘
   ┌─ PLAN ────────────────────▼──────────────────────────┐
   │ ray-perimeter → ray-compass                            │  threat model → plan.json
   └───────────────────────────┬──────────────────────────┘
   ┌─ AUDIT (run the domains that fit the target) ─────────▼┐
   │ ray-prospector  +  crucible · turnstile · seam ·       │
   │ sentry · vault · citadel · custodian · marrow ·        │  → workspace/findings/*.json
   │ oracle · manifest · terrain · steward                  │
   └───────────────────────────┬──────────────────────────┘
   ┌─ VALIDATE ────────────────▼──────────────────────────┐
   │ ray-condenser → ray-arbiter → ray-magistrate           │  dedupe → false-pos → viability
   └───────────────────────────┬──────────────────────────┘
   ┌─ PROVE ───────────────────▼──────────────────────────┐
   │ ray-detonator                                          │  PoC / reproduce
   └───────────────────────────┬──────────────────────────┘
   ┌─ SCORE & REPORT ──────────▼──────────────────────────┐
   │ ray-gauge → ray-chronicle   (+ ray-retrospective)      │  risk score → report packet
   └───────────────────────────────────────────────────────┘
```

**Before you start:** if the codebase pulls dependencies or ships IaC/containers,
`ray-manifest` and `ray-terrain` slot into the AUDIT band. If you're editing files
during the work, keep `ray-cloak` on as a write-time guard.

### Track B — Live audit (the agents' tool flow, via `ray-siege`)

Run **after** you can stand the app up locally. `ray-siege` orchestrates the loop;
the agents drive the real arsenal under the fail-closed gate (loopback-only,
non-destructive, canary proof).

```
  ray-siege  (orchestrator: authz gate → stand up disposable local app → seed canaries)
      │
      ▼  round N:
  ┌─────────────────────────────────────────────────────────────────┐
  │ ATTACK   ray-reaver                                              │
  │   RECALL memory → ray_arsenal_list (what's installed)           │
  │   → drive tools via ray_arsenal_run (gate-checked):             │
  │       nmap/httpx (recon) · ffuf/nuclei/nikto (discovery)       │
  │       sqlmap (SQLi) · dalfox (XSS) · tplmap (SSTI)             │
  │       arjun/jwt_tool (API/identity) · garak/promptfoo (LLM)   │
  │   → each break-in proven with a CANARY → write finding         │
  ├─────────────────────────────────────────────────────────────────┤
  │ PATCH    ray-bulwark                                             │
  │   read finding → semgrep (root cause + siblings)               │
  │   → minimal idiomatic fix → gitleaks (no leaked secret)        │
  │   → one finding, one commit → propose CI gate (shift-left)     │
  ├─────────────────────────────────────────────────────────────────┤
  │ REBUILD → REATTACK (≥3 boundary variants) → verdict            │
  │   VERIFIED_SECURE only if all variants fail to bypass          │
  └─────────────────────────────────────────────────────────────────┘
      │  repeat until a clean round (nothing new + all closed) or round cap
      ▼
  siege report + patch branch for you to review
```

### Track C — Detection & response (independent, ongoing)

Not part of a point-in-time audit — run when you operate a **running estate** and
have alerts/telemetry to work:

```
  ray-warden (orchestrator: authority-tier gate → ingest & correlate alerts)
      │
      ▼  per case:  ray-vigil
          RECALL memory → triage frame → class playbook (auth/phishing/
          endpoint/exfil/IoC) → correlate → score verdict + confidence
          → proactive hunt (§8) · kill-chain detection (§11) · DFIR (§9)
          → recommend tier-appropriate action (read-only; the gate acts)
```

### How the tracks connect

- **Static → Live:** a `ray-crucible`/`ray-turnstile` static finding becomes a
  `ray-siege` target to *prove* live; the reaver's break-in is the same class the
  docket flagged.
- **Live → Static:** a `ray-bulwark` fix cross-references the domain docket's
  safe-pattern; a vector the reaver couldn't break is logged as an insight for the
  next static pass.
- **Both → Detection:** the reaver's kill-chain *impact* notes are exactly the
  detection targets `ray-vigil` hunts for (`analyst_playbooks.md` §11) — red's
  output seeds blue's coverage.

______________________________________________________________________

## Quick decision cheatsheet

| I want to… | Use |
|---|---|
| Audit a codebase end-to-end, no running app | Track A (full skill pipeline) |
| Prove a finding is really exploitable | `ray-detonator` (static PoC) or `ray-siege` (live) |
| Break in + fix in a loop on my local app | `ray-siege` → reaver/bulwark (Track B) |
| Check one domain only (e.g. auth) | that domain skill (e.g. `ray-turnstile`) |
| Review a PR / code change | `ray-loupe` |
| Investigate an alert / hunt threats | `ray-warden` → vigil (Track C) |
| Know if the built app actually works for a user | `ray-vantage` → usher |
| Check legal/compliance: AI disclosure, ToS, store privacy labels | `ray-counsel` |
| Map what's exposed externally | `ray-quarry` |
| Stop secrets leaking as I code | `ray-cloak` |
| Just the right router, one line | [`AGENTS.md`](../AGENTS.md) |
