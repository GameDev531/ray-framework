# Ray Framework — Claude Code

Ray is a security-review plugin: **31 single-responsibility skills**, 4 subagents,
and a `ray-tools` MCP server. This repo installs as the plugin `ray@ray-framework`.

## Loading (Claude Code)

- Skills auto-trigger by their `description`, or invoke explicitly with
  `/ray-<name>` (e.g. `/ray-siege`, `/ray-crucible`).
- The `ray-tools` MCP server registers automatically with the plugin — call its
  tools (`ray_secret_scan`, `ray_sbom_generate`, `ray_arsenal_run`, …) directly.
- Subagents live in `agents/`; each opens with its own **reading flow**.

## The one rule — route, don't read everything

**Do not read all 31 `SKILL.md` files.** Match the task to the right skill, invoke
it, and let its `references/*.md` dockets load only at the step that needs them. A
one-off question goes straight to the single relevant docket, not the whole
pipeline. **The full routing map is in [`AGENTS.md`](./AGENTS.md) — read it first.**

## Quick router (the common cases)

| Task | Start with |
|---|---|
| Full static security audit of a codebase | the pipeline in `AGENTS.md` §A (`ray-lattice` → … → `ray-chronicle`) |
| Injection / untrusted input (SQLi, XSS, SSRF, SSTI, deser…) | `ray-crucible` |
| Auth / JWT / OAuth / IDOR / tenancy / API Top 10 | `ray-turnstile` |
| Client-server trust, CORS, headers, mass assignment | `ray-seam` |
| Datastore exposure, encryption, crypto/PQC | `ray-vault` |
| Dependencies / SBOM | `ray-manifest` · IaC / containers → `ray-terrain` |
| The app's LLM/AI feature | `ray-oracle` |
| Live attack+fix loop on your own local app | `ray-siege` (agents `ray-reaver`/`ray-bulwark`) |
| Detection / alert triage / hunting | `ray-warden` (agent `ray-vigil`) |
| Stop secrets leaking into files/commits | `ray-cloak` |
| Review a code change | `ray-loupe` |

Everything else, and the per-domain docket map, is in **`AGENTS.md`**.
