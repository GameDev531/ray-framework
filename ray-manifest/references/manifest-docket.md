# Manifest Docket — manifest

Vulnerable→safe patterns for `ray-manifest`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## Known-vulnerable versions — CWE-1035 / CWE-937 · A06:2021
- **Broken:** a resolved dependency version with a published CVE/advisory; an EOL major
  version with no security backports.
- **Safe:** versions at or above the fixed release; no advisory match. Report the CVE
  id, affected range, fixed version, and — where determinable — whether the vulnerable
  function is reachable from app input.

## Unpinned / floating dependencies — CWE-1104
- **Broken:** `^`/`~`/`*`/`latest` ranges with no lockfile; a lockfile out of sync with
  the manifest; git deps on a mutable branch.
- **Safe:** pinned versions with a committed lockfile; integrity hashes present.

## Typosquats & lookalikes — CWE-506
- **Broken:** a dependency whose name is a near-miss of a popular package; an unexpected
  registry/source.
- **Safe:** names verified against the intended package; scoped/official sources.

## Malicious install/build scripts — CWE-506
- **Broken:** `postinstall`/`preinstall`/build hooks that fetch and run remote code,
  read env/secrets, or phone home.
- **Safe:** no network-fetching install scripts; scripts reviewed; `--ignore-scripts`
  in CI where feasible.

## SBOM (artifact)
- On request, emit a CycloneDX SBOM (`workspace/sbom.cyclonedx.json`) listing components,
  versions, and known advisories — the machine-readable inventory ray-steward reuses for
  EOL/patch-cadence tracking.

## What is NOT a finding here

- A dev-only dependency's CVE that never ships to production (note it, down-weight it).
- A CVE in a package whose vulnerable function is provably unreachable — report as
  informational with the reachability analysis, don't inflate.
- "A newer version exists" with no security content — that is maintenance, route to
  ray-steward.
