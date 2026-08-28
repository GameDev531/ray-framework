# Findings Contract — ray-crucible

How this stage writes its output. Read it before writing the first finding of a
pass, and again when assembling the sink ledger.

This stage feeds `/ray-detonator` more than any other, so the contract has an
extra job here: a finding must carry enough for someone else to build a
reproduction without re-deriving the analysis. A class name and a file path is
not that.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults](#2-severity-defaults)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. CWE Set For This Domain](#4-cwe-set-for-this-domain)
- [5. Findings Schema](#5-findings-schema)
- [6. Sink Ledger](#6-sink-ledger)

______________________________________________________________________

## 1. Evidence Discipline

**Anchor at the sink, and include the source.** `code_paths[0]` is the sink
line; add the source line as a second entry once you have identified it. A
finding carrying only a class name and a file cannot be reviewed or reproduced.

**State the neutralizer you ruled out.** This is what makes a finding survive
`/ray-arbiter`, whose first move is to look for the protection you might have
missed. "No parameterization; the `.raw()` call at line 44 bypasses the query
builder used everywhere else in this module" pre-empts that.

**Do not report framework-default-protected code.** React interpolation,
auto-escaped templates, parameterized ORM calls, and safe-by-default APIs are
protection. Reporting them burns validation budget and, worse, trains reviewers
to skim this stage's output.

**Send no payloads anywhere.** No requests to the target, no test payloads to
third-party hosts, no DNS callbacks, no live scanning. Static analysis here;
sandboxed proof in `/ray-detonator`. Put the reproduction recipe in the
description and `mitigation` so the detonator can build it.

**One sink, one finding**, with every reaching source listed. When a single
unsafe helper is used in twenty places, report it once at the helper and list
the call sites in `code_paths` — the fix is at the helper, and twenty findings
would obscure that.

**Do not overstate a chain.** Where one primitive would enable another (SSRF →
metadata credentials → cloud access), report the primitive you evidenced and
describe the chain in `impact` as a consequence, not as an observation.

**Never fabricate advisory data.** No invented CVE identifiers, CVSS scores, or
advisory text. If you could not verify it from the snapshot or a tool you
actually ran, say the version is outdated and let a scanner confirm.

**Status.** Default `PROVISIONALLY_VALID`. Use `NEEDS_RESEARCH` for `UNKNOWN`
sinks — paths crossing dynamic dispatch, reflection, or a plugin boundary you
cannot resolve statically. Never round `UNKNOWN` down to safe.

______________________________________________________________________

## 2. Severity Defaults

Discovery-stage defaults; `ray-gauge` applies the final caps. Note especially
its `strict_xss` rule, which caps XSS aggressively — scoring XSS high here does
not survive, it just costs the pipeline a round trip.

| Class | Default |
|---|---|
| Command injection, unsafe deserialization, template injection, upload-to-execute | HIGH |
| SQL injection | HIGH |
| SSRF reaching cloud metadata or internal services | HIGH |
| SSRF with no demonstrated internal reach | MEDIUM |
| Path traversal | MEDIUM–HIGH by what it reads or writes |
| Stored XSS | MEDIUM–HIGH (HIGH only for zero-click execution in a critical admin context) |
| Reflected or DOM XSS | MEDIUM |
| CSRF on a state-changing, cookie-authenticated route | MEDIUM |
| XXE with file read | MEDIUM–HIGH |
| Prototype pollution | MEDIUM, or by the concrete gadget found |
| CSV formula injection | LOW–MEDIUM |
| Open redirect | LOW (MEDIUM when chained into an OAuth flow) |
| Timing leak on a secret comparison | LOW–MEDIUM |
| Vulnerable dependency, reachability unproven | LOW |
| Vulnerable dependency, reachable path traced | by the CVE's own impact |

Reserve CRITICAL for a described, unauthenticated path to full compromise.

______________________________________________________________________

## 3. The Four Computed Fields

**`cwe`** — this stage should almost always set it; the class→CWE mapping is in
`owasp_mapping.md` §3 and each docket section names its CWE. Decide it first; it
is an input to the signature.

**`signature`** — first 16 hex characters of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:

- `normalized_title` = `title` lowercased with every non-`[a-zA-Z0-9]`
  character stripped; empty result → first 16 hex of
  `sha256(<raw title as UTF-8>)`.
- `cwe_part` = the `cwe` value or the empty string.
- `primary_target` = the first `code_paths` entry minus any trailing `:line`;
  if empty or a non-source LOCATOR, hash
  `normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(",")`.

**Order `code_paths` with the sink first, always.** The signature depends on it,
so an unstable order re-reports the same finding as new on the next pass.
Compute the signature once at creation and never recompute it.

**`lineage_id`** — inherit from an archived finding with the same `signature`
under `workspace/archive/findings_pass_*/` or
`workspace/archive/loop*_findings/` (highest pass wins); otherwise a fresh
UUIDv4. `ray-prospector/SKILL.md` Step 5a's basename-rename fallback applies.
STATE-RELATIVE paths.

**`discovery_commit`** — `active_snapshot.snapshot_id` verbatim when pinned;
**omit the key entirely** in DEGRADED mode.

`signature` and `lineage_id` are always computed; only `discovery_commit` is
mode-dependent.

______________________________________________________________________

## 4. CWE Set For This Domain

| Class | CWE |
|---|---|
| `SQLI` | `CWE-89` (SQL), `CWE-943` (NoSQL / data query) |
| `CMDI` | `CWE-78`, or `CWE-88` for argument injection |
| `XSS` | `CWE-79` |
| `SSTI` | `CWE-1336` |
| `CSRF` | `CWE-352` |
| `SSRF` | `CWE-918` |
| `DESER` | `CWE-502` |
| `XXE` | `CWE-611` |
| `TRAV` | `CWE-22` (`CWE-23`, `CWE-36` for the specific variants) |
| `UPLOAD` | `CWE-434` |
| `REDIR` | `CWE-601` |
| `PROTO` | `CWE-1321` |
| `TIMING` | `CWE-208` |
| `REDOS` | `CWE-1333` |
| `CSVI` | `CWE-1236` |
| `DEPS` | `CWE-1395` |
| Missing input validation generally | `CWE-20` |
| Zip slip specifically | `CWE-22` with the archive detail in the description |

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "SQL injection via unparameterized ORDER BY in report builder",
  "description": "The source (which request field, at which entrypoint), the path it takes to the sink, the sink itself, and which neutralizers you checked and ruled out. Name the framework default if one exists and explain why it does not apply here.",
  "impact": "What the primitive yields (e.g., arbitrary read of the users table; command execution as the app user; theft of cloud instance credentials via metadata).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["SINK FIRST: src/reports/query.ts:88", "then the source: src/routes/reports.ts:19"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-89",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The safe pattern for this exact call, plus the reproduction recipe /ray-detonator should build: request shape, the parameter to vary, and the observable that distinguishes success from noise.",
  "vuln_class": "Optional. The docket class id, e.g. 'SQLI'.",
  "history": [
    {
      "stage": "crucible",
      "action": "created",
      "details": "Untrusted-input sweep finding recorded.",
      "pass_number": 1,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

The reproduction recipe in `mitigation` is the highest-leverage sentence in the
finding. Each docket section ends with a reproduction hint for its class — use
it, and prefer a differential observable (two inputs producing different
responses) over an error message, since errors are often swallowed.

______________________________________________________________________

## 6. Sink Ledger

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`; if missing or
   invalid, use `max` of the `findings_pass_N` / `loopN_findings` folders in
   `workspace/archive/` + 1, defaulting to `1`.
2. If `workspace/ledgers/ray-crucible.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-crucible_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-crucible.json`.

```json
{
  "skill": "ray-crucible",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "classes_requested": "ALL",
  "sources": ["src/routes/**: query, body, params", "src/webhooks/stripe.ts:12"],
  "classes": [
    {
      "id": "SQLI",
      "state": "ASSESSED | NO_SINKS | NOT_ASSESSED",
      "patterns_run": ["\\.raw\\(", "query\\(`", "execute\\(f\""],
      "sinks": [
        {
          "location": "src/reports/query.ts:88",
          "verdict": "REACHABLE_UNSAFE | NEUTRALIZED | UNREACHABLE | UNKNOWN",
          "neutralizer": null,
          "finding_id": "<uuid or null>"
        }
      ]
    }
  ],
  "dependencies": {
    "manifests": ["package.json", "package-lock.json"],
    "lockfiles_committed": true,
    "floating_versions": ["lodash: ^4.17.0"],
    "install_scripts_present": false,
    "automated_updates": "renovate.json"
  }
}
```

Every class in the docket appears exactly once. `NOT_ASSESSED` is valid only
when `--classes` excluded it, and must name that reason. `NO_SINKS` must list
`patterns_run` — without it, "no sinks" is indistinguishable from "did not
look", which is the whole failure the ledger exists to prevent.

Run the coverage self-check in `owasp_mapping.md` §5 before writing this file.
