---
name: ray-manifest
description: >-
  Software-composition analysis: parses a project's dependency manifests and lockfiles across ecosystems, builds an SBOM (CycloneDX), and flags known-vulnerable versions (via OSV.dev or an installed scanner), risky licenses, typosquats/dependency-confusion, and unmaintained or floating dependencies.
  Use to audit third-party risk — the vulnerabilities you inherit rather than write — for any project with a dependency lockfile, producing an SBOM and a ranked list of dependency findings.
  Don't use it for vulnerabilities in the project's own source (that's ray-crucible and the domain suite); it audits the dependencies, not the code that calls them.
---

# Manifest (/ray-manifest)

## System Goal

Software-Composition Analyst. Most of the code that ships in a modern system is
code the team never wrote — it is dependencies, and their transitive
dependencies. `ray-manifest` audits *that* surface: it reads the project's
lockfiles, resolves the full direct-plus-transitive dependency set, emits a
standard **SBOM**, and flags every component that carries known risk — a version
with a published CVE, a license that is incompatible or copyleft-surprising, a
name that is one keystroke from a popular package (typosquat), or a dependency
that floats instead of pinning.

It is a drop-in sibling of `ray-prospector`: it writes the same finding JSON, so
its dependency findings flow through condensation, scoring, and reporting exactly
like source findings. The difference is where it looks — the manifest, not the
module.

**Honesty about CVE matching.** Mapping a version to a CVE requires a
vulnerability database. `ray-manifest` uses the **public OSV.dev API** (free, no
key) or an installed scanner (`osv-scanner`, `grype`, `npm audit`, `pip-audit`) —
and when neither the network nor a scanner is available, it says so and falls
back to the structural checks it *can* do offline (typosquat, floating ranges,
SBOM). It never fabricates a CVE it did not get from a real source.

## Command Definition

- **Command:**
  `/ray-manifest [--repo_root=<path>] [--offline] [--sbom_out=<path>] [--state_root=<path>]`
- **Description:** Discovers and parses every supported lockfile under the repo,
  builds the SBOM, matches known vulnerabilities, and writes one finding per
  dependency risk worth acting on.
- **Arguments (all optional):**
  - `--repo_root`: the project working tree to analyze. Absent → current directory.
  - `--offline`: skip the OSV.dev network query and any scanner that needs the
    network; do structural checks only and label CVE matching as skipped.
  - `--sbom_out`: also write the CycloneDX SBOM to this path (for the SBOM to
    live in the repo or a release artifact). Absent → the SBOM still lands in
    `workspace/recon`-style state output, just not in the repo tree.
  - `--state_root`: parent of `workspace/`. Absent → `./workspace/...`.

## Input/Output Contract

- **Reads**: dependency manifests and lockfiles under `--repo_root`
  (`package-lock.json`/`yarn.lock`, `requirements.txt`/`Pipfile.lock`/`poetry.lock`,
  `go.mod`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`); this skill's
  `references/*.md`; the OSV.dev API or an installed scanner (driven via the
  bundled helper or Bash); a prior `workspace/findings/` for lineage.
- **Writes**:
  - `workspace/findings/<uuid>.json` — one per dependency risk (standard schema
    plus SCA fields; see `references/findings_contract.md`).
  - `workspace/manifest/sbom.cyclonedx.json` — the CycloneDX SBOM.
  - `workspace/manifest/sca_report.json` — the raw component + vulnerability +
    typosquat report from the helper (evidence the findings draw on).
  - `workspace/manifest_report.md` — the human report.
- **Preconditions**: at least one supported lockfile. Absent → the skill reports
  that no dependency graph was found (a project may legitimately vendor nothing).
- **Idempotency Guarantee**: findings are UUID files (`ray-condenser` semantics
  apply); the SBOM and report overwrite in place; re-running re-queries risk from
  scratch (dependency risk is time-moving, like recon).

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/sca_docket.md` | during analysis | Per-ecosystem manifest/lockfile parsing, the OSV.dev query method and scanner-driving, the CycloneDX shape, and the license / typosquat / dependency-confusion / floating-range heuristics |
| `references/findings_contract.md` | before the first finding | The dependency-finding schema, the four computed fields, the SCA-specific fields, the `dependency_risk` enum, and evidence discipline (fixed-version + transitive path + exploitability caveat) |

The engine is the bundled helper `scripts/ray_sbom.py` (stdlib-only): lockfile →
CycloneDX SBOM + OSV.dev client + typosquat heuristics. Where the Ray MCP server
is available, the same capability is the `ray_sbom_generate` tool
(`{"path": "...", "offline": false}`) — a real tool call, not a narrated one.

## Instructions

### Step 0: Locator Resolution (Block A)

```
LOCATOR RESOLUTION (before reading ANY artifact):
0. ROLE: ray-manifest reads dependency lockfiles under --repo_root; it does NOT
   read a pinned code snapshot for source review. NEVER stop merely because a
   code snapshot is unset.
1. REPO_ROOT = --repo_root if passed, else the current directory. Read-only.
2. STATE_ROOT: from --state_root if passed, else ./workspace/... relative to the
   current directory. All SBOM/report/findings output is STATE-RELATIVE and is
   NEVER written under REPO_ROOT unless --sbom_out explicitly names a repo path.
3. Every shell command uses ABSOLUTE paths and sets its own working directory.
```

### Step 1: Build the SBOM

Run `scripts/ray_sbom.py <REPO_ROOT> --json` (or the `ray_sbom_generate` MCP
tool). It discovers every supported lockfile, parses the direct-plus-transitive
component set, de-dupes by `(ecosystem, name, version)`, and emits the CycloneDX
SBOM. Persist the SBOM to `workspace/manifest/sbom.cyclonedx.json` (and to
`--sbom_out` if given). Record which lockfiles were found and any that failed to
parse (`references/sca_docket.md` §1) — a lockfile that could not be parsed is a
coverage gap to report, not a silent skip.

### Step 2: Match known vulnerabilities

Unless `--offline`, match each component against known vulnerabilities: prefer an
installed scanner if one is present (`references/sca_docket.md` §2), else the
OSV.dev query the helper performs. For each hit, capture the advisory id(s)
(GHSA + CVE aliases), the severity, and the **fixed version** — the single most
actionable field. If the network and scanners are both unavailable, record CVE
matching as *not performed* and continue with the structural checks; do not
present an empty result as "no vulnerabilities".

### Step 3: Structural checks (always, offline-safe)

From the parsed graph, flag independent of any database:
- **Typosquat / dependency-confusion** — a name a single edit from a popular
  package, or an internal-looking name resolvable from a public registry.
- **Floating versions** — ranges (`^`, `~`, `*`, `latest`, unpinned) where a
  lockfile or pin is expected, which make the build non-reproducible.
- **License risk** — a copyleft or unknown license where the project's
  distribution model makes it a problem (best-effort from available metadata).
- **Maintenance / EOL** — a component far behind or unmaintained (hand this
  trajectory to `ray-steward`, which owns freshness over time).

### Step 4: Write findings and report

Write one finding per risk worth acting on per `references/findings_contract.md`:
a vulnerable version (with its fixed-version and transitive path), a typosquat
suspect, a confusion-prone name. Anchor `code_paths` at the lockfile
(`package-lock.json`) — the artifact that pins the risk. A component that is
present and clean is **SBOM inventory, not a finding**. Note the exploitability
caveat honestly: a CVE in a dependency is reachable-in-theory; whether the
project calls the vulnerable path is a source question for the domain suite.

Write `workspace/manifest_report.md`: the SBOM summary, the vulnerable
dependencies ranked by severity × fixed-version-availability, and the structural
flags. Report to the user the counts (components / vulnerable / typosquats) and
the SBOM path; do not dump the whole SBOM into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Vulnerabilities in the project's **own** source | `/ray-crucible` + the domain suite |
| Whether a vulnerable dependency path is actually **reached/called** | `/ray-prospector` (source reachability) |
| Dependency **freshness / EOL trajectory** over time | `/ray-steward` |
| Supply-chain **build/pipeline** integrity (signing, provenance) | `/ray-citadel` |
| Committed **secrets** (not dependencies) | `/ray-quarry` |

`ray-manifest` owns the dependency inventory and its known risk; it hands
reachability to the source stages and freshness to `ray-steward`. A vulnerable
component it finds is a first-class finding — `ray-condenser` merges it, `ray-gauge`
scores it, `ray-chronicle` reports it — and the SBOM it emits is a reusable
artifact for release and compliance.
