# Ray Framework — Gemini CLI

Ray is a security-review library: **31 single-responsibility skills**, 4 subagent
role definitions, and stdlib-only helper tools. It is host-agnostic — Gemini CLI
supplies the execution surface (Bash + `python3`), Ray supplies the discipline.

## Loading (Gemini CLI)

- Gemini CLI reads this `GEMINI.md` and the `.gemini/skills/` directory.
- Each `ray-*/SKILL.md` is a **procedure to follow** — open the one the task needs
  and execute its steps; its `references/*.md` dockets hold the depth.
- Run the real tools directly (all stdlib, zero-install):
  `python3 scripts/ray_secret_scan.py …` → actually `python3 scripts/ray_secrets.py <path> --json`,
  `python3 scripts/ray_sbom.py`, `ray_iac.py`, `ray_arsenal.py`, `ray_metadata.py`,
  `ray_memory.py`. Or start the MCP server (`python3 scripts/ray_mcp_server.py`) if
  your client speaks MCP. Prefer running a tool over describing it.
- Subagent roles are in `agents/`; each opens with its own **reading flow**. With
  no native subagent runner, adopt the role's charter yourself for that pass.

## The one rule — route, don't read everything

**Do not read all 31 `SKILL.md` files.** Match the task to the right skill, then
read deeply only the docket branch that step points to. A one-off question goes
straight to the single relevant docket. **The full routing map is in
[`AGENTS.md`](./AGENTS.md) — read it first.**

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
| Live attack+fix loop on your own local app | `ray-siege` (roles `ray-reaver`/`ray-bulwark`) |
| Detection / alert triage / hunting | `ray-warden` (role `ray-vigil`) |
| Stop secrets leaking into files/commits | `ray-cloak` |
| Review a code change | `ray-loupe` |

Everything else, and the per-domain docket map, is in **`AGENTS.md`**.
