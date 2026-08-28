# SCA Docket — Ecosystems, Vulnerability Matching, SBOM, and Heuristics

The technique reference for `ray-manifest`. Read the section for the ecosystem or
check you are running. Every capability has a bundled dependency-free path
(`scripts/ray_sbom.py`) and an optional richer path via an installed scanner —
inventory tools first (`command -v osv-scanner grype trivy npm pip-audit`), use
the richer path when present, and never skip a class for want of a tool.

## Table of Contents

- [1. Per-Ecosystem Manifests & Lockfiles](#1-per-ecosystem-manifests--lockfiles)
- [2. Vulnerability Matching (OSV.dev and scanners)](#2-vulnerability-matching-osvdev-and-scanners)
- [3. The SBOM (CycloneDX)](#3-the-sbom-cyclonedx)
- [4. Structural Heuristics (offline-safe)](#4-structural-heuristics-offline-safe)

______________________________________________________________________

## 1. Per-Ecosystem Manifests & Lockfiles

Prefer the **lockfile** over the manifest — the lockfile has resolved, exact
versions (including transitive), which is what vulnerability matching needs. The
manifest (`package.json`, `pyproject.toml`) gives *direct* deps and the declared
range, useful for the floating-version check (§4).

| Ecosystem | Lockfile(s) parsed | OSV ecosystem | purl type |
|---|---|---|---|
| npm | `package-lock.json` (v1/v2/v3), `npm-shrinkwrap.json`, `yarn.lock` (v1) | `npm` | `npm` |
| pip | `requirements.txt` (pinned `==`), `Pipfile.lock` | `PyPI` | `pypi` |
| poetry | `poetry.lock` | `PyPI` | `pypi` |
| cargo | `Cargo.lock` | `crates.io` | `cargo` |
| go | `go.mod` (`require`) | `Go` | `golang` |
| composer | `composer.lock` | `Packagist` | `composer` |
| rubygems | `Gemfile.lock` | `RubyGems` | `gem` |

The helper walks the tree (skipping `node_modules`, `vendor`, `.venv`, `target`,
build dirs), parses each found lockfile, tags every component with its source
file, and de-dupes by `(ecosystem, name, version)`. A lockfile that fails to
parse is recorded as a **coverage gap** in the report — never a silent skip.
`pnpm-lock.yaml` and Gradle/Maven resolved trees are not parsed by the bundled
helper (no stdlib YAML/Gradle resolver); for those, drive `osv-scanner` or the
ecosystem's own audit tool and say so if it is absent.

______________________________________________________________________

## 2. Vulnerability Matching (OSV.dev and scanners)

**OSV.dev (bundled path, free, no key).** The helper POSTs the component set to
`https://api.osv.dev/v1/querybatch` (`{"queries":[{"package":{"name","ecosystem"},"version"}...]}`),
then fetches each returned advisory from `/v1/vulns/<id>` to extract:
- the advisory **id** and its **aliases** (so a GHSA carries its CVE and vice versa),
- the **severity** (CVSS vector or the database-specific severity),
- the **fixed version(s)** — parsed from the advisory's `affected[].ranges[].events[].fixed`,
  filtered to the matching package name. This is the most actionable field:
  "upgrade to ≥ X".

Network etiquette and honesty: the query is batched and bounded; on any network
failure (including a proxy 403 in a restricted environment) the helper returns
`osv_status: unavailable ... CVE matching skipped` and the skill reports that
plainly rather than presenting an empty list as "clean".

**Installed scanners (richer path).** When present, prefer:
- `osv-scanner --lockfile <file>` or `osv-scanner -r <dir>` — same OSV data,
  broader ecosystem coverage.
- `grype dir:<dir>` / `trivy fs <dir>` — additional advisory sources.
- `npm audit --json`, `pip-audit -f json`, `cargo audit --json` — the ecosystem's
  own audit, good for transitive nuance.
Normalize their output to the same `{package, version, ids, severity, fixed}`
shape so findings are uniform regardless of which tool produced them.

**Exploitability caveat (always record it).** A CVE in a dependency means the
*version* is vulnerable, not that the project *reaches* the vulnerable code path.
State this in every vuln finding: reachability is a source question owned by
`ray-prospector`/the domain suite. Do not inflate a dependency CVE to CRITICAL
on severity alone if the vulnerable API is plausibly never called — say what is
known and what is not.

______________________________________________________________________

## 3. The SBOM (CycloneDX)

The helper emits a **CycloneDX 1.5** JSON document: `bomFormat`, `specVersion`,
`metadata.tools`, and `components[]` each `{type: "library", name, version, purl}`
with a correct package-URL (`pkg:npm/lodash@4.17.4`, `pkg:pypi/django@3.2.4`, …).

The SBOM is a first-class deliverable, not just an intermediate: it is the
inventory a release attaches, a compliance program requires, and a future scan
diffs against. Write it to `workspace/manifest/sbom.cyclonedx.json` and, when
`--sbom_out` is given, to that path too (e.g. a repo or release artifact). Keep
it valid CycloneDX so downstream tools (dependency-track, etc.) can ingest it.

______________________________________________________________________

## 4. Structural Heuristics (offline-safe)

These need no database and run even fully offline — they are the honest floor of
value when CVE matching is unavailable.

**Typosquat / dependency-confusion.** A dependency whose name is a single edit
(Levenshtein 1, case- and separator-normalized so `Django` ≠ a squat of `django`)
from a popular package is flagged as a squat suspect. A name that looks internal
but resolves from a public registry is a **dependency-confusion** risk (an
attacker publishes your private name publicly at a higher version). Flag; the
finding recommends scoping the registry / reserving the name.

**Floating versions.** A direct dependency declared as a range (`^1.2`, `~1.2`,
`*`, `latest`, or unpinned) — read from the *manifest* — where the build should
be reproducible is a supply-chain and reproducibility risk (a compromised upgrade
lands silently). Flag with the recommendation to pin + use a lockfile.

**License risk.** Where component metadata carries a license, flag copyleft
(GPL/AGPL) in a proprietary-distribution context, or an unknown/missing license
(legal ambiguity). Best-effort: lockfiles often omit license, so this is reported
with its confidence and never asserted beyond the metadata seen.

**Maintenance / EOL.** A component many majors behind, or a runtime/language at
end-of-life, is a *trajectory* risk. Note it and hand the freshness/EOL
trajectory to `ray-steward` (§ Boundary in the SKILL) — `ray-manifest` states the
current fact; `ray-steward` owns the over-time cadence.
