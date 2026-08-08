# Ray Agent Memory — Curated, Global, Per-Agent (Layer 1)

How Ray agents learn across runs so they get sharper every time. This is the
contract behind `scripts/ray_memory.py`. It is a deliberately small, local,
free memory layer inspired by the curated-memory design of assistants like
Hermes/James: memory is a personal notebook the agent owns, not a data vacuum.

## The one rule that defines it: no ingestion

Memory is born **only** from the agent's own work — the attacks it ran, the
patches that held or got bypassed, the review defects it saw. There is a
deliberate barrier between this memory and external sources: it never ingests
email, files, browser history, or a codebase wholesale. If a broader ingestion
system is ever wanted, it must be a separate, opt-in feature — never mixed into
this curated layer.

## The loop: NOTICE → FILE → RECALL

- **NOTICE** — pull durable facts out of ordinary work, without being told
  "remember this." When an attack technique works, a defense blocks you, a fix
  holds under re-attack, or a review defect recurs, that is a fact worth keeping.
- **FILE** — write it to the agent's own Markdown file
  (`~/.claude/ray-memory/<agent>.md`). Plain Markdown the agent owns — no
  database, no vectors, no external service for this layer.
- **RECALL** — read the memory **before acting**, as part of default reasoning,
  not only when asked "do you remember X?". Consulting memory is the first step
  of a dispatch, not an on-demand lookup.

## Frozen-snapshot semantics

An agent reads its memory once, at the start of a dispatch — a frozen snapshot
for that run. Writes made during the run take effect on the **next** dispatch,
not mid-run. This is automatic here because each agent dispatch is a fresh
context; it keeps a run's reasoning stable.

## Where it lives

Global: `~/.claude/ray-memory/<agent>.md`, one file per agent
(`reaver.md`, `bulwark.md`, `scrivener.md`). Global (not per-project) is
deliberate — the hacker, the fixer, and the reviewer should get better across
**every** project over time, which is the whole point of "learn from each fix."

## The character cap (not tokens)

Each file has a hard **character** cap (default 6000). When full, `add`/`replace`
refuse and the agent must curate — remove a low-value entry, then retry. The cap
is the forcing function that keeps memory high-signal instead of a dump. Think of
it as a notebook with a fixed number of pages, not an append-only log.

## When to save (priority order)

Save, in descending priority:
1. **Preferences / corrections / specific details** — "this project's `update()`
   spreads the request body, so mass-assignment reaches `is_admin`"; "the fix that
   held was an RLS `WITH CHECK`, not just an app-layer scope."
2. **Stable environment facts** — "this repo's auth middleware is in
   `src/mw/auth.ts` and runs before route handlers."
3. **Reusable procedures** — "for this framework, prove IDOR by logging in as the
   seeded canary and iterating `/:id`."

Do **not** save: the obvious, anything easily rediscovered by looking, or
task/run progress (that is temporary state, not memory). A good entry teaches the
next run something it would otherwise have to relearn the hard way.

## Actions (`scripts/ray_memory.py`)

- `recall --agent <name>` — print the file (empty is normal; succeeds silently).
- `add --agent <name> --section "<section>" --text "<lesson>"` — append a bullet.
- `replace --agent <name> --find "<unique snippet>" --text "<new>"` — locate an
  entry by a **unique** text snippet (no IDs) and rewrite it.
- `remove --agent <name> --find "<unique snippet>"` — delete that entry.
- `list` — agents with memory and their sizes.

A non-unique snippet is refused (give a longer trecho); an over-cap write is
refused (curate first). Writing memory is **Level-1 risk** — a personal note, not
a system action — so it needs no confirmation each time.

## How agents use it

The orchestrator (`ray-siege`, `ray-loupe`) resolves the absolute path to
`ray_memory.py` from the plugin and passes it to the subagent it dispatches. Each
agent, in its charter:
- **RECALLs** at the start (reads `~/.claude/ray-memory/<agent>.md`) and applies
  the lessons to this run.
- **NOTICE→FILEs** at the end of a round, promoting only high-signal, durable
  lessons from the ephemeral `workspace/insights.jsonl` into curated memory via
  the when-to-save rule above.
- Falls back gracefully: if the helper path was not provided, the agent reads the
  fixed global file directly and appends with the same discipline (it has Bash).
  Absent memory is never a reason to stop.

## Suggested sections per agent

- `reaver.md` — *Attack techniques that worked*, *Defenses that blocked me*,
  *Per-stack notes*.
- `bulwark.md` — *Fixes that held (VERIFIED_SECURE)*, *Patches that got bypassed
  and why*, *Idiomatic patterns per framework*.
- `scrivener.md` — *Recurring defects*, *House style / project conventions*,
  *False-positive traps to avoid*.

## Extending to other agents

The pattern is reusable: give any agent a `<name>.md`, add a RECALL step at the
start and a NOTICE→FILE step at the end, and use the same helper. Nothing about
the helper is siege- or review-specific.

## Layer 2 (future, optional — NOT built)

The original design has a deeper structured layer: a local SQLite database with
FTS5 full-text search, facts + entities, a trust score (facts gain/lose
confidence on feedback), and `search`/`probe`/`related`/`contradict` actions for
memory hygiene. It stays 100% local and free (SQLite ships with Python; no
NumPy, no vectors). It is deliberately **not** built here — Layer 1 (this file)
is the MVP and covers the large majority of the practical value. Add Layer 2 only
if composite, cross-entity recall is genuinely missed. The paid/SaaS memory
providers (mem0, honcho, supermemory, etc.) are out of scope by the same rule
that keeps the rest of Ray local and dependency-free.
