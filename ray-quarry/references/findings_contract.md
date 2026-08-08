# Findings Contract — ray-quarry

How `ray-quarry` writes its findings. Read before the first finding of a run, and
again at Step 4. It reuses the standard Ray finding schema and the four computed
fields, adds the recon-specific fields, and stays consistent with the rest of the
pipeline so a recon finding is first-class — `ray-condenser` can merge it,
`ray-perimeter` can fold it into the threat model, and the report stages consume
it unchanged.

## Table of Contents

- [1. Evidence & Redaction Discipline](#1-evidence--redaction-discipline)
- [2. Finding vs. Footprint — what earns a finding](#2-finding-vs-footprint--what-earns-a-finding)
- [3. Severity Defaults for Exposure](#3-severity-defaults-for-exposure)
- [4. The Four Computed Fields](#4-the-four-computed-fields)
- [5. Recon-Specific Fields and the exposure_status Enum](#5-recon-specific-fields-and-the-exposure_status-enum)
- [6. CWE Set](#6-cwe-set)
- [7. Findings Schema](#7-findings-schema)

______________________________________________________________________

## 1. Evidence & Redaction Discipline

**Observed, never exploited.** Every recon finding is proven by an observation —
a resolved name, a certificate SAN, an extracted metadata field, a service
banner, a redacted secret match. A recon finding never carries an exploit; if
proving it would require breaking in, it is not a `ray-quarry` finding (hand the
host to `ray-siege`).

**Anchor at the leaking artifact.** `code_paths[0]` (or the recon locator) points
at *where the exposure lives*: `repo/path.py:88` for a committed secret, the
document URL for a metadata leak, `host:port` for an exposed service, the hostname
for a naming leak. A reviewer must be able to re-observe it from what you wrote.

**Redaction is mandatory for secrets.** A committed-credential finding records the
detector name, `file:line`, and only the first/last few characters of the match —
never the full secret, in the finding, the footprint, the evidence file, or chat.
A metadata leak records the exact field value (it is already public in the
document); a secret never is.

**In-scope only.** Every finding's asset resolved to the attestation (`recon_scope.md`
§3). An out-of-scope observation is not a finding — it is a single logged line in
the footprint and nothing more.

______________________________________________________________________

## 2. Finding vs. Footprint — what earns a finding

`workspace/recon/footprint.json` holds *everything* observed — including hosts and
services that are supposed to be public and are behaving correctly. A **finding**
is written only for an **exposure worth closing**:

- A service exposed to the internet that should not be (admin panel, database
  port, internal API, staging environment reachable externally).
- A software version whose exposure carries known-vulnerable surface.
- A document leaking internal identifiers — usernames, file paths, host/share
  names, tracked-change remnants.
- A committed secret that looks live.
- A naming leak that materially aids an attacker (a CT-log SAN advertising an
  internal host that then answers).

A host that is *meant* to be public and serves only what it should is
**informational** — it stays in the footprint, not a finding. Do not inflate the
finding count with correct, expected exposure.

______________________________________________________________________

## 3. Severity Defaults for Exposure

Set an honest discovery-stage severity; if a full pipeline runs, `ray-gauge`
applies the final caps. Exposure severity reflects **what the leak hands an
attacker**, not merely that a leak exists.

| Exposure | Default |
|---|---|
| Live-looking secret/credential committed or exposed; internet-facing datastore/admin with no auth | CRITICAL |
| Internet-exposed service that should be internal (staging, internal API, management port) with weak/unknown auth; a precise vulnerable software version exposed | HIGH |
| Document metadata leaking real usernames + internal paths (materially aids access); exposed service with auth but unnecessary internet reach | MEDIUM–HIGH |
| Naming/version leak with modest attacker value (a subdomain enumerated, a generic software banner) | LOW–MEDIUM |
| Informational public host serving what it should | not a finding |

`privileges_required`, `attacker_position`, and `user_interaction` describe the
position the exposure gives an **external** actor (recon is by definition
`attacker_position: EXTERNAL` unless the asset is an internal-only surface you
reached in-scope). Record what the observation actually showed.

______________________________________________________________________

## 4. The Four Computed Fields

Identical to every other Ray stage, so lineage and dedupe work across recon and
the rest of the pipeline.

**`cwe`** (optional) — from §6. Decide first; it feeds the signature.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:
- `normalized_title` = `title` lowercased, non-`[a-zA-Z0-9]` stripped; empty →
  first 16 hex of `sha256(<raw title as UTF-8>)`.
- `cwe_part` = the `cwe` value or the empty string.
- `primary_target` = first `code_paths` entry minus a trailing `:line`; if empty
  or a non-source locator (a URL, a `host:port`), hash over
  `sorted(code_paths).join(",")` instead.

Compute once at creation; never recompute.

**`lineage_id`** — inherit from an archived finding with the same `signature`
under `workspace/archive/findings_pass_*/`, highest wins; else a fresh UUIDv4.
This folds a re-run's recon finding onto its prior twin.

**`discovery_commit`** — for a repo-anchored finding (a committed secret), the
commit the secret was observed at. For a network/document finding with no repo
commit, use the ISO-8601 timestamp of the observation instead (recon measures a
moving external surface, so *when* is the analogue of *which build*).

______________________________________________________________________

## 5. Recon-Specific Fields and the exposure_status Enum

Added on top of the standard schema:

| Field | Meaning |
|---|---|
| `recon_class` | One of `naming` / `service` / `version` / `document_metadata` / `secret_leak`. |
| `recon_mode` | `passive` or `active` — how it was observed. Active items were run only against an `active_ok` host. |
| `asset` | The attested scope entry this resolved to (the audit tie-back). |
| `observation` | Object: `{ "method": "...", "source": "CT log | document URL | host:port | repo path", "observed": "the field/banner/redacted-match that proves it" }`. |
| `exposure_status` | See below. |

**`exposure_status`** (the state of the exposure):

- `exposed_confirmed` — the exposure was directly observed (a resolved host that
  answered, an extracted metadata field, a redacted secret match).
- `exposed_inferred` — strongly implied by passive data but not directly
  confirmed (a CT SAN for a host that did not resolve this run). Lower confidence;
  say so.
- `informational` — observed but not an exposure worth closing (kept in the
  footprint, not written as a finding; listed here for completeness of the enum).

A finding is written for `exposed_confirmed` or a meaningful `exposed_inferred`
only; `informational` never becomes a finding.

______________________________________________________________________

## 6. CWE Set

Common exposure CWEs: `CWE-200` (information exposure), `CWE-201` (info in sent
data), `CWE-538` (file/path info exposure — document metadata leaks),
`CWE-540`/`CWE-541` (source/secret in file), `CWE-798` (hard-coded/committed
credentials), `CWE-668` (exposure of resource to wrong sphere — internet-facing
internal service), `CWE-1327` (exposed management interface), `CWE-1104`
(unmaintained/known-vulnerable component version). Omit if none applies.

______________________________________________________________________

## 7. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Internal username and fileserver path leaked in published PDF metadata",
  "description": "The document (already public) carries dc:creator 'j.okafor' and a template path \\\\corp-fs01\\legal\\templates — a real account name and an internal host/share. States what an external actor learns and why the export should strip metadata.",
  "impact": "External attacker gains a valid-looking username (convention: first-initial.surname) and an internal hostname/share, seeding account attacks and internal-topology guesses without touching the network.",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE",
  "attacker_position": "EXTERNAL",
  "user_interaction": "NONE",
  "status": "VALID",
  "code_paths": ["https://example.com/docs/nda-template.pdf"],
  "discovery_commit": "2026-08-08T14:02:11Z (observation timestamp)",
  "cwe": "CWE-538",
  "signature": "16 hex chars, per §4.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "Strip document metadata on export/publish (org-wide policy or a build step); rotate the exposed username's exposure by treating the convention as known. Re-publish scrubbed copies.",
  "recon_class": "document_metadata",
  "recon_mode": "passive",
  "asset": "example.com",
  "observation": {
    "method": "ray_metadata.py PDF /Info + XMP extraction",
    "source": "https://example.com/docs/nda-template.pdf",
    "observed": "dc:creator='j.okafor'; template='\\\\corp-fs01\\legal\\templates\\nda.dotx'; Producer='Microsoft Word 16.0'"
  },
  "exposure_status": "exposed_confirmed",
  "history": [
    {"stage": "quarry-recon", "action": "observed", "details": "passive metadata extraction of in-scope published document", "timestamp": "<iso8601>"}
  ]
}
```

Use `"status": "VALID"` — a directly-observed exposure is not provisional. For an
`exposed_inferred` finding, say so in the description and prefer a lower severity.
The `history` stage is namespaced `quarry-recon` so a mixed pass keeps provenance.
A `secret_leak` finding follows the same schema with `code_paths: ["src/x.py:88"]`
and an `observation.observed` that is **redacted** (detector + first/last chars),
never the full secret.
