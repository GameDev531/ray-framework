# Usage Guide

How to install, run, and extend Ray. For the one-line router see `AGENTS.md`; for
what each skill owns and the target profiles see `docs/coverage-map.md`.

## Install

The skills live as `ray-*/` directories at the repo root (the distribution layout).
To make them invocable by an assistant, install them into that assistant's skill
folder:

```sh
bin/ray-install.sh                    # into ./.claude/skills (copy)
bin/ray-install.sh --link             # symlink (portable relative links inside this repo)
bin/ray-install.sh --assistant gemini # ./.gemini/skills
bin/ray-install.sh --assistant codex  # ./.codex/skills
bin/ray-install.sh --assistant cursor # ./.cursor/rules
bin/ray-install.sh --dest /path/repo  # into another project
```

Claude Code discovers `.claude/skills/*/SKILL.md` and `.claude/agents/*.md`; this
repo ships both wired up. Restart / reload skills after installing.

## Run a full static audit (Track A)

The reference orchestrator handles the deterministic sync/pin/archive bookkeeping;
the LLM stages run in order against the pinned snapshot.

```sh
# 1. begin a pass — pin an immutable, content-hashed snapshot + write the sentinel
python3 bin/ray-conductor.py begin --target . --state . --sync

# 2. run the pipeline (drive with the ray-conductor skill, or invoke stages)
#    map:      /ray-prism  → /ray-blueprint
#    plan:     /ray-perimeter → /ray-compass
#    audit:    /ray-prospector + the domain skills that fit the target
#    validate: /ray-condenser → /ray-arbiter → /ray-magistrate
#    prove:    /ray-detonator   (patch: /ray-anvil, chain: /ray-cascade)
#    report:   /ray-gauge → /ray-chronicle → /ray-retrospective

# 3. archive the pass's findings
python3 bin/ray-conductor.py archive --state . --pass 1

python3 bin/ray-conductor.py show --state .   # inspect state at any time
```

Or let the `ray-conductor` skill drive all of it: `/ray-conductor --sync --profile=web-app`.

### Modes

- **`--sync` (PINNED, recommended):** freezes a content-hashed snapshot; every
  finding carries `discovery_commit`; drift between passes is detected and routed to
  `NEEDS_RESEARCH`, never silently dropped.
- **no `--sync` (MODE-OFF, default):** runs against the live tree, no snapshot
  guarantees. Fine for a quick look; not for a tracked campaign.

## Target profiles

Add `--profile=<web-app|native|library|llm-app>` so the pipeline tunes to the target
type. On a web SaaS, `--profile=web-app` keeps CORS, rate-limit, cookie-flag, and
dependency-CVE findings in scope instead of dismissing them as hygiene. See
`docs/coverage-map.md` and `profiles/*.md`.

## Prove & fix

- **Sandbox reproduction:** `/ray-detonator` builds a PoC/crash reproducer and only
  records `reproduced` on genuine execution evidence (fail-closed Tier gate).
- **Static patch:** `/ray-anvil` writes a minimal root-cause patch on a private
  shadow and re-attacks it (original PoC + ≥3 boundary variants). `VERIFIED_SECURE`
  requires all variants to fail (INV-1).
- **Live loop (Track B):** `/ray-siege` against a disposable local app — `ray-reaver`
  breaks in and proves it with a canary; `ray-bulwark` writes the fix; rebuild →
  re-attack until clean. Authorization + disposability are mandatory.

## Detection (Track C)

`/ray-warden` on a running estate with alerts/telemetry dispatches `ray-vigil` to
triage/hunt and return a scored verdict with a tier-appropriate recommendation. The
analyst recommends; a tier gate acts.

## The finding contract

Every stage reads and writes one JSON shape defined by `schema.json` (repo root).
Validate finding files any time:

```sh
python3 validate_findings.py workspace/findings/*.json
python3 validate_findings.py --self-test        # the gate tests
```

The validator uses `jsonschema` if installed, and a zero-dependency fallback
otherwise. The four gates it enforces: `VALID ⇒ no UNKNOWN/FAIL` in the triage
checklist, `FAIL ⇒ FALSE_POSITIVE`, `VERIFIED_SECURE ⇒ failed_to_bypass + ≥3 clean
variants`, `DUPLICATE ⇒ duplicate_of`.

## Extend

- **New domain skill:** copy an existing `ray-<domain>/` (SKILL.md + a
  `references/<domain>-docket.md`), keep Block A byte-identical, add the routing row
  to `ray-prospector/references/attack-classes.md` and `docs/coverage-map.md`.
- **Custom orchestrator:** `/ray-foundry` guides building your own harness around the
  Pass Lifecycle Contract; `bin/ray-conductor.py` is the reference implementation.
