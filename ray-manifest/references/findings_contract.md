# Findings Contract — ray-manifest

How `ray-manifest` writes its findings. It reuses the standard Ray finding schema
and the four computed fields, adds the SCA-specific fields, and stays consistent
with the pipeline so a dependency finding is first-class — `ray-condenser` merges
it, `ray-gauge` scores it, `ray-chronicle` reports it. Read before the first
finding, and again at Step 4.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Finding vs. SBOM Inventory](#2-finding-vs-sbom-inventory)
- [3. Severity Defaults for Dependency Risk](#3-severity-defaults-for-dependency-risk)
- [4. The Four Computed Fields](#4-the-four-computed-fields)
- [5. SCA-Specific Fields and the dependency_risk Enum](#5-sca-specific-fields-and-the-dependency_risk-enum)
- [6. CWE Set](#6-cwe-set)
- [7. Findings Schema](#7-findings-schema)

______________________________________________________________________

## 1. Evidence Discipline

**A real advisory or a structural fact — never a guess.** A vulnerability finding
cites a real advisory id (GHSA/CVE) from OSV.dev or a scanner, with its severity
and fixed version. A structural finding (typosquat, floating range) cites the
concrete fact (the name and its near-match; the unpinned range). `ray-manifest`
never invents a CVE; if CVE matching could not run, it says so and writes only
the structural findings it can prove.

**Anchor at the lockfile.** `code_paths[0]` is the manifest/lockfile that pins the
risk (`package-lock.json`, `requirements.txt`), optionally with the line. That is
where the fix is applied. A reviewer must be able to find the exact pinned
component from the finding.

**Carry the fixed version and the transitive path.** The two most actionable
facts: *upgrade to ≥ X*, and *why is this even here* (which direct dependency
pulled the vulnerable transitive one). Include both when known.

**State the exploitability caveat.** A dependency CVE means the version is
vulnerable, not that the code path is reached. Say what is known (vulnerable
version present) and what is not (whether the project calls it) — reachability is
owned by the source stages.

______________________________________________________________________

## 2. Finding vs. SBOM Inventory

The SBOM (`workspace/manifest/sbom.cyclonedx.json`) lists **every** component,
clean or not. A **finding** is written only for a component that carries
**actionable risk**: a known vulnerability, a typosquat/confusion suspect, a
license conflict, or a reproducibility-breaking floating range. A present,
current, clean dependency is inventory — it does not become a finding. Do not
inflate the finding count with healthy dependencies.

______________________________________________________________________

## 3. Severity Defaults for Dependency Risk

Set an honest discovery-stage severity; `ray-gauge` applies final caps. Weigh the
advisory severity **and** the fix availability and plausibility of reach.

| Risk | Default |
|---|---|
| Critical/High CVE with a known exploited path or trivially-reachable API, fix available | HIGH (CRITICAL only if reachability is evident) |
| High CVE, fix available, reachability unknown | HIGH–MEDIUM (state the caveat; don't assume reach) |
| Medium CVE, or High with no fixed version yet | MEDIUM |
| Dependency-confusion-prone internal name resolvable publicly | HIGH (a real, exploited-in-the-wild class) |
| Typosquat suspect (name near a popular package) | MEDIUM (verify it is not a legitimate fork) |
| Floating/unpinned direct dependency; copyleft/unknown license | LOW–MEDIUM |
| Clean, current component | not a finding |

`attacker_position` for a dependency vuln is usually `SUPPLY_CHAIN`;
`privileges_required`/`user_interaction` describe what exploiting the dependency's
flaw would take, when known from the advisory — otherwise say `UNKNOWN`.

______________________________________________________________________

## 4. The Four Computed Fields

**`cwe`** (optional) — from §6, or the advisory's own CWE when provided.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`, where
`primary_target` is the purl minus version (`pkg:npm/lodash`) so the same
component links across versions/runs; if empty, hash `sorted(code_paths)`.

**`lineage_id`** — inherit from an archived finding with the same `signature`
(the same component flagged before), highest wins; else a fresh UUIDv4.

**`discovery_commit`** — the repo commit the lockfile was read at (the pinned
state the risk was found in). Dependency risk moves with the lockfile, so this
records *which pin* was vulnerable.

______________________________________________________________________

## 5. SCA-Specific Fields and the dependency_risk Enum

| Field | Meaning |
|---|---|
| `dependency_risk` | `known_vulnerability` / `typosquat` / `dependency_confusion` / `floating_version` / `license` / `unmaintained`. |
| `component` | Object: `{ "ecosystem": "...", "name": "...", "version": "...", "purl": "..." }`. |
| `advisories` | For `known_vulnerability`: array of `{ "id": "GHSA-…", "aliases": ["CVE-…"], "severity": "...", "fixed": ["4.17.12"] }`. |
| `transitive_path` | The dependency chain from a direct dependency to this component, when known (`app → a@1 → lodash@4.17.4`). |
| `fixed_version` | The lowest version that resolves it, when the advisory gives one. |
| `exploitability` | `reachability_unknown` (default for a dependency CVE) / `reachable` (a source stage confirmed the call) / `not_reached`. |

______________________________________________________________________

## 6. CWE Set

`CWE-1104` (unmaintained third-party component), `CWE-1035`/`CWE-937` (using
components with known vulnerabilities), `CWE-1357` (reliance on insufficiently
trustworthy component), `CWE-829` (inclusion from untrusted control sphere —
dependency confusion), plus the advisory's own CWE for the underlying flaw
(e.g. `CWE-1321` prototype pollution). Omit if none applies.

______________________________________________________________________

## 7. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Known-vulnerable dependency: lodash 4.17.4 (prototype pollution)",
  "description": "package-lock.json pins lodash@4.17.4, which is affected by GHSA-jf85-cpcp-j695 / CVE-2019-10744 (prototype pollution). Fixed in 4.17.12. Pulled transitively via app → cli-utils@2 → lodash. Reachability of the vulnerable API in this project is not established here.",
  "impact": "Prototype pollution can lead to property injection and, depending on downstream use, denial of service or privilege escalation — IF the vulnerable lodash path is reached by the application.",
  "severity": "HIGH",
  "privileges_required": "UNKNOWN",
  "attacker_position": "SUPPLY_CHAIN",
  "user_interaction": "UNKNOWN",
  "status": "VALID",
  "code_paths": ["package-lock.json"],
  "discovery_commit": "abc1234",
  "cwe": "CWE-1321",
  "signature": "16 hex chars, per §4.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "Upgrade lodash to >= 4.17.12 (update the offending direct dependency or add a resolutions/override pin); then confirm the transitive pin moved in the lockfile.",
  "dependency_risk": "known_vulnerability",
  "component": {"ecosystem": "npm", "name": "lodash", "version": "4.17.4", "purl": "pkg:npm/lodash@4.17.4"},
  "advisories": [
    {"id": "GHSA-jf85-cpcp-j695", "aliases": ["CVE-2019-10744"], "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "fixed": ["4.17.12"]}
  ],
  "transitive_path": "app → cli-utils@2 → lodash@4.17.4",
  "fixed_version": "4.17.12",
  "exploitability": "reachability_unknown",
  "history": [
    {"stage": "manifest-sca", "action": "matched", "details": "OSV.dev hit on lodash@4.17.4; fixed in 4.17.12", "timestamp": "<iso8601>"}
  ]
}
```

Use `"status": "VALID"` — the pinned vulnerable version is a fact. For a
structural finding (`typosquat`/`floating_version`), drop `advisories`/`fixed_version`
and put the concrete structural fact in `description`. The `history` stage is
namespaced `manifest-sca` for provenance.
