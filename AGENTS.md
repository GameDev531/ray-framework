# AGENTS.md — one-line router

Ray is an evidence-first security-review pipeline of composable skills. Pick the
entry point; each skill auto-triggers by its description or is invoked as
`/ray-<name>`. Full detail: `docs/usage-guide.md`. Charter & profiles:
`docs/coverage-map.md`.

| I want to… | Entry point |
|---|---|
| Audit a codebase end-to-end (no running app) | `/ray-conductor --sync` (Track A) |
| …as a web SaaS (keep CORS/rate-limit/CVE in scope) | `/ray-conductor --sync --profile=web-app` |
| Prove a finding is really exploitable | `/ray-detonator` (sandbox) or `/ray-siege` (live) |
| Break in + fix in a loop on my local app | `/ray-siege` (Track B → ray-reaver, ray-bulwark) |
| Check one domain only (e.g. auth) | that domain skill, e.g. `/ray-turnstile` |
| Review a PR / code change | `/ray-loupe` (→ ray-scrivener) |
| Investigate an alert / hunt threats | `/ray-warden` (Track C → ray-vigil) |
| Map what's exposed externally | `/ray-quarry` (authorized assets only) |
| Stop secrets leaking as I code / scan for leaks | `/ray-cloak` |
| Build my own orchestrator harness | `/ray-foundry` |

**Pipeline order (Track A):** map (`ray-lattice`? → `ray-prism` → `ray-blueprint`)
→ plan (`ray-perimeter` → `ray-compass`) → audit (`ray-prospector` + the domain
skills that fit) → validate (`ray-condenser` → `ray-arbiter` → `ray-magistrate`) →
prove (`ray-detonator`; patch with `ray-anvil`; chain with `ray-cascade`) → report
(`ray-gauge` → `ray-chronicle` → `ray-retrospective`). `ray-ledger` mines history
up front; `ray-cloak` guards writes throughout.

**Agents** are subagents, dispatched by a parent skill, never standalone:
`ray-reaver`/`ray-bulwark` (by `ray-siege`), `ray-vigil` (by `ray-warden`),
`ray-scrivener` (by `ray-loupe`).
