---
name: ray-quarry
description: >-
  Maps the external attack surface of assets you own or are explicitly authorized to assess: passive OSINT (DNS, certificate transparency, published-document metadata à la FOCA, leaked secrets in your own repos) first, and bounded active enumeration (port/service/tech fingerprinting, template-based probing) only behind a fail-closed scope-attestation gate.
  Use before a security review to learn what an attacker can discover about your own surface — hostnames, exposed services, software versions, internal paths and usernames leaked in document metadata — so the threat model starts from reality, not a guess.
  Don't point it at anything you cannot attest you own or are authorized to test (the scope gate fails closed); don't use it for mass-targeting, DoS, or evasion — it refuses all three by construction. For attacking a running app you stood up, use ray-siege; for static source audit, use ray-prospector and the domain suite.
---

# Quarry (/ray-quarry)

## System Goal

External Attack-Surface Cartographer. Discovers what a competent attacker
could learn about a surface **you own or are authorized to assess** before they
send a single exploit: the hostnames and certificates that name your estate, the
services and software versions exposed at its edge, and the quiet leaks — a
username and an internal file path baked into a published PDF's metadata, an API
key committed to your own repo — that hand an attacker a foothold for free.

This is the reconnaissance stage that the rest of the pipeline assumes has
happened. `ray-perimeter` builds a threat model of trust boundaries and attacker
profiles; it is far sharper when it starts from a *measured* surface than from an
architecture diagram. `ray-quarry` produces that measurement: a footprint of the
real, currently-exposed surface, written as standard Ray findings so the threat
model, the domain sweeps, and `ray-siege` can all consume it.

**This is authorized, defensive security tooling.** It maps only assets the user
attests they own or are explicitly authorized to test, for the sole purpose of
finding and closing exposure before an adversary does — the "know what you leak"
half of attack-surface management. The authorization and restraint rules in
`references/recon_scope.md` §1 are invariants, not suggestions: they fail closed,
and the skill stays passive (or stops) rather than touching anything it cannot
prove is in an attested scope.

## Command Definition

- **Command:**
  `/ray-quarry [--scope_file=<path>] [--mode=<passive|active>] [--depth=<map|enumerate>] [--targets=<host,host,...>] [--docs=<dir>] [--state_root=<path>] [--repo_root=<path>]`
- **Description:** Reads (or helps you write) a signed scope attestation, then
  gathers the external footprint of the in-scope assets — passive by default,
  active only when the scope file authorizes it — and writes one finding per
  exposure worth closing.
- **Arguments (all optional):**
  - `--scope_file`: path to the scope attestation (`references/recon_scope.md`
    §2 gives the format). Absent → the skill helps you author one and does
    **not** proceed until it exists and validates. Nothing outside it is touched.
  - `--mode`: `passive` (default) — only observation that sends nothing intrusive
    to the target (public DNS, certificate transparency, your own document
    metadata and repos, third-party passive datasets); `active` — additionally
    runs bounded, non-destructive enumeration **against hosts the scope file
    marks `active_ok`**. `active` with no `active_ok` host stays passive and says so.
  - `--depth`: `map` (default) — breadth: enumerate hosts, services, and leaks
    without deep probing; `enumerate` — for the `active_ok` hosts, add
    service/version fingerprinting and template-based checks (never exploitation —
    that is `ray-siege`).
  - `--targets`: an explicit subset to scope this run to. Every entry must already
    be covered by the scope file; any that is not is dropped with a note.
  - `--docs`: a directory of already-downloaded documents to mine for metadata
    (the dependency-free extractor). Absent → the skill mines only documents it
    reached through in-scope public sources.
  - `--state_root`: parent of `workspace/` (state directory). Absent →
    `./workspace/...` relative to the current directory.
  - `--repo_root`: a working tree to scan for committed secrets as part of the
    footprint (your own repo — what you leak in source). Absent → skips repo
    secret-scanning.

## Input/Output Contract

- **Reads**: the scope attestation at `--scope_file`; `workspace/.ray_state.json`
  (for provenance, if a pipeline is running); this skill's `references/*.md`; any
  documents under `--docs`; the working tree at `--repo_root` for committed
  secrets; the output of whatever recon tools happen to be installed (driven via
  Bash — see the docket), falling back to the bundled dependency-free helpers.
- **Writes**:
  - `workspace/findings/<uuid>.json` — one per exposure worth closing (standard
    schema plus recon fields; see `references/findings_contract.md`).
  - `workspace/recon/footprint.json` — the structured inventory (hosts, services,
    certificates, documents-and-their-metadata, leaked secrets) the findings are
    drawn from.
  - `workspace/recon/evidence/` — the raw evidence per item (STATE-RELATIVE):
    tool output, the extracted metadata record, the redacted secret match. Never
    written into `--repo_root`.
  - `workspace/recon/scope_check.json` — the recorded result of the §1 gate for
    this run (which asset was resolved to which attested scope entry, and when).
  - `workspace/recon_report.md` — the footprint report for a human.
- **Preconditions**: a valid scope attestation covering every asset touched. Absent
  or unsatisfiable → the skill stays in scope-authoring mode and does not recon.
- **Idempotency Guarantee**: findings are UUID files (`ray-condenser` semantics
  apply if a full pipeline also runs); the footprint and scope-check are
  overwritten in place; re-running re-resolves the scope gate from scratch (a
  stale attestation never carries a run).

## Reference Files

Read these as the run calls for them — the body stays lean and the detail loads
only when a step needs it.

| File | Read it | What it carries |
|---|---|---|
| `references/recon_scope.md` | before Step 0, and whenever a new asset appears | The authorization invariants (fail-closed scope attestation, passive-vs-active boundary), the no-mass-targeting / no-DoS / no-evasion rules, the scope-file format, and how to resolve any discovered asset back to an attested entry |
| `references/recon_docket.md` | during collection (Steps 2–3) | The technique encyclopedia: passive sources (DNS, CT logs, WHOIS/RDAP, passive datasets), the FOCA-style document-metadata method, repo/secret leakage, and bounded active enumeration — for each, what it yields, how to drive the tool that does it (or the dependency-free fallback), what counts as evidence, and which downstream skill consumes it |
| `references/findings_contract.md` | before writing the first finding, and at Step 4 | Findings schema, the four computed fields, the recon-specific fields, the `exposure_status` enum, evidence/redaction discipline, and severity defaults for exposure |

The dependency-free document-metadata extractor is `scripts/ray_metadata.py`
(resolved from the plugin root). It reads PDF, Office (OOXML), and image (EXIF)
metadata with the Python standard library alone — no FOCA, no external
dependency — so the FOCA-style method works even in a bare environment.

## Instructions

### Step 0: Locator Resolution (Block A) + Scope-Attestation Gate

```
LOCATOR RESOLUTION (before reading ANY target artifact):
0. ROLE: ray-quarry reads external assets and (optionally) --repo_root; it does
   NOT read a pinned snapshot's source. Treat --repo_root as a plain working tree
   for secret-scanning only. NEVER stop merely because a code snapshot is unset.
1. Determine REPO_ROOT (only if --repo_root passed): use it verbatim for
   read-only secret scanning. Absent → skip all repo scanning; do not stop.
2. STATE_ROOT: from --state_root if passed, else ./workspace/... relative to the
   current directory. All recon output is STATE-RELATIVE under STATE_ROOT/workspace
   and is NEVER written under REPO_ROOT.
3. Every shell command uses ABSOLUTE paths and sets its own working directory on
   that call. Do NOT assume the working directory persists between calls.
```

Then run the **Scope-Attestation Gate** in `references/recon_scope.md` §1 before
resolving a single hostname or reading a single document. It is fail-closed:

- If `--scope_file` is absent or does not validate, **do not recon**. Switch to
  authoring mode: walk the user through writing the attestation (§2 format), have
  them state the assets they own or are authorized to test and the authorization
  basis, and stop. Reconnaissance begins only against a validated scope.
- Every asset touched — every hostname, IP, document URL, repo — must resolve to
  an entry in the scope file (§3 resolution rules). An asset that does not is
  **out of scope by construction**: it is not touched, and it is not silently
  expanded to. There is no `--force` and no override.
- `active` mode is gated a second time: it runs only against hosts the scope file
  explicitly marks `active_ok`, and only with the non-destructive, non-mass,
  non-evasive techniques the docket allows. Anything else stays passive.

Record the gate result to `workspace/recon/scope_check.json` before Step 1.

### Step 1: Plan the sweep

From the validated scope, build the collection plan: which passive sources apply,
which documents/repos are in reach, and — only if `--mode=active` and there are
`active_ok` hosts — which bounded active checks are authorized at `--depth`.
Inventory which recon tools are actually installed (the docket lists the checks
per tool); for every capability with no tool present, record the dependency-free
fallback so the sweep degrades gracefully instead of skipping the class.

### Step 2: Passive collection (always)

Follow `references/recon_docket.md` §1–§3. Gather, sending nothing intrusive to
the target:

- **Naming and edge**: DNS records and subdomains, certificate-transparency
  entries (they name hosts you forgot you exposed), WHOIS/RDAP, and any passive
  service datasets available — mapped back to in-scope assets only.
- **Published-document metadata (the FOCA method)**: for every in-scope document
  reached (or supplied via `--docs`), run `scripts/ray_metadata.py` and harvest
  what the file leaks — authoring software and versions, author/operator
  usernames, internal file paths and share names, printer/host names, embedded
  or tracked-change remnants. This is often the highest-signal, lowest-noise leak
  a surface has, and it is entirely passive.
- **Your own leaked secrets**: if `--repo_root` is set, scan the working tree for
  committed credentials and tokens (drive `gitleaks`/`trufflehog` if present, else
  the docket's entropy+pattern fallback), recording matches **redacted**.

### Step 3: Bounded active enumeration (only if authorized)

Run **only** for `--mode=active` against `active_ok` hosts. Follow
`references/recon_docket.md` §4 and stay inside the §1 restraint rules:
service/port and technology/version fingerprinting, and — at `--depth=enumerate`
— non-intrusive template checks (e.g. `nuclei` with non-exploit templates) that
*observe* exposure without exploiting it. Rate-limited, bounded, one surface at a
time. No exploitation (that is `ray-siege`), no DoS, no auth-bypass attempts, no
evasion. If a check would cross that line, it is not run.

### Step 4: Write the footprint and the findings

Assemble `workspace/recon/footprint.json` (the full structured inventory), then
write one finding per **exposure worth closing** per `references/findings_contract.md`:
an exposed service that should not face the internet, a software version with
known-vulnerable exposure, a document leaking internal identifiers, a committed
secret. Each finding carries its redacted evidence, the `exposure_status`, and
`code_paths`/locators anchored at the leaking artifact (the repo path for a
secret, the document URL for metadata, the host:port for a service). An item that
is merely *informational* (a host that is supposed to be public, serving what it
should) goes in the footprint, not into a finding.

### Step 5: Report and hand off

Write `workspace/recon_report.md`: the measured surface, the exposures ranked by
what they hand an attacker, and — explicitly — the map from each exposure to the
downstream skill that acts on it (`ray-perimeter` folds the surface into the
threat model; `ray-siege` can attack an in-scope host you stand up locally;
`ray-turnstile`/`ray-vault`/`ray-sentry` own the classes a leaked credential or
exposed service implies). Report to the user the counts (hosts / services /
leaking documents / secrets / findings) and where the report is; do not print
raw secrets or full finding bodies into chat — evidence stays redacted on disk.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Turning the measured surface into a threat model (boundaries, attacker profiles) | `/ray-perimeter` |
| Attacking a running app you stood up locally, with proof | `/ray-siege` |
| Static source audit of the code behind an exposed service | `/ray-prospector` + the domain suite |
| Deep audit of an exposed datastore's reachability and privileges | `/ray-vault` |
| Rate-limiting, exposed-internal-endpoint, and service-auth review of a found service | `/ray-sentry` |

`ray-quarry` measures the outside; the rest of Ray reasons about the inside. It
never exploits and never leaves the attested scope — it hands a *measured*
attack surface to the stages that model, audit, and (locally, with a gate) attack
it. A footprint item that names a running host you own can be fed to `ray-siege`
(stand a local copy up and prove it); a leaked secret or exposed service becomes
a first-class finding the pipeline scores and reports like any other.
