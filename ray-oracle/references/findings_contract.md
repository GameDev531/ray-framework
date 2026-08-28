# Findings Contract — ray-oracle

How this stage writes its output. Read it before writing the first finding of a
pass, and again when assembling the surface ledger. It reuses the standard schema
and four computed fields; the one thing to internalize is the probabilistic-
severity reality (docket final section) — it changes how you score every class.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults](#2-severity-defaults)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. CWE Set For This Domain](#4-cwe-set-for-this-domain)
- [5. Findings Schema](#5-findings-schema)
- [6. Surface Ledger](#6-surface-ledger)

______________________________________________________________________

## 1. Evidence Discipline

**Anchor at the boundary that fails.** Injection → the prompt-assembly line plus
the untrusted fragment's source. Output-handling → the sink plus the model-output
source. Agency → the tool definition and its dispatcher. Name what an attacker
controls at each hop.

**Judge injection by what the model can do, not by the injection alone.** A
prompt injection into a model with no tools and escaped output is low impact; the
same injection into a model that can call a "run SQL" tool is critical-adjacent.
Trace to AGENCY/OUTPUT before setting severity.

**Record the metering.** For every finding, note whether the model-calling path
is rate-limited, quota'd, and monitored — this is what `/ray-gauge`'s
`probabilistic_llm` rule keys on. An unmetered endpoint lifts the HIGH cap.

**Do not treat partial mitigations as neutralizers.** Delimiters, "ignore
injection" system lines, and spotlighting reduce but do not eliminate injection —
note them, do not clear the finding on them.

**Send no prompts to any model.** No jailbreak attempts, no live injection. The
probabilistic demonstration is `/ray-detonator`'s, in a controlled setting.

**Status.** Default `PROVISIONALLY_VALID` — LLM feasibility is inherently
probabilistic and `/ray-detonator`/`/ray-gauge` will calibrate. `NEEDS_RESEARCH`
where the prompt/tool wiring cannot be resolved statically.

______________________________________________________________________

## 2. Severity Defaults

Discovery-stage defaults; `/ray-gauge`'s `probabilistic_llm` cap (HIGH, often
lower) then applies unless the endpoint is unmetered.

| Situation | Default |
|---|---|
| Injection reaching a tool that performs a privileged/irreversible action with no independent authz | HIGH (CRITICAL only if unmetered + unauthenticated path) |
| Insecure output handling into an RCE/SQLi sink | HIGH |
| Insecure output handling into XSS/SSRF | MEDIUM–HIGH |
| Indirect / RAG-poisoning injection into a tool-enabled agent | HIGH |
| Direct injection into a tool-less, escaped-output assistant | LOW–MEDIUM |
| Secrets or cross-tenant data in the prompt | HIGH |
| Unsafe deserialization of a model artifact from an untrusted source | HIGH (cross-ref `/ray-crucible` `DESER`) |
| Unbounded consumption / denial-of-wallet on a `PAID` model route | MEDIUM |
| System-prompt leakage with no dependent control | LOW |

Reserve CRITICAL for a described, largely-deterministic path (unmetered ret/rate,
unauthenticated) to a privileged action or code execution.

______________________________________________________________________

## 3. The Four Computed Fields

**`cwe`** — set from §4. Decide first; it feeds the signature.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:
`normalized_title` = title lowercased, non-`[a-zA-Z0-9]` stripped (empty → first
16 hex of `sha256(raw title)`); `cwe_part` = the cwe or empty; `primary_target` =
first `code_paths` entry minus `:line` (empty/non-source LOCATOR → hash over
`sorted(code_paths).join(",")`). Order `code_paths` with the failing boundary
first (prompt-assembly, or the sink). Compute once; never recompute.

**`lineage_id`** — inherit from an archived finding with the same `signature`
under `workspace/archive/findings_pass_*/` (highest pass wins), basename-rename
fallback; else fresh UUIDv4. STATE-RELATIVE.

**`discovery_commit`** — snapshot id verbatim when pinned; **omit entirely** in
DEGRADED mode.

______________________________________________________________________

## 4. CWE Set For This Domain

| Class | CWE |
|---|---|
| `INJECTION` | `CWE-1427` (prompt injection), plus the downstream `CWE-77` family |
| `OUTPUT` | the sink's CWE: `CWE-79`/`89`/`78`/`918`/`94` |
| `AGENCY` | `CWE-250` / `CWE-862` (action without independent authorization) |
| `DISCLOSURE` | `CWE-200` / `CWE-201` / `CWE-522` |
| `CONSUMPTION` | `CWE-770` / `CWE-799` |
| `SUPPLY` | `CWE-502` (artifacts), `CWE-1395` (poisoned data/deps) |

(OWASP LLM Top 10 ids — LLM01…LLM10 — go in the description for the stakeholder;
the machine-readable field is the CWE.)

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Indirect prompt injection via retrieved docs reaches the run-SQL tool",
  "description": "Which untrusted fragment reaches the prompt (or which model output reaches which sink), the trust boundary that is missing, what the model can then do (the tool and its capability), and whether the model route is rate-limited/metered/monitored. Name the OWASP LLM id.",
  "impact": "What the attack yields (e.g., an attacker-planted document makes the agent run arbitrary SQL against the tenant DB).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["src/agent/prompt.py:52", "src/rag/retrieve.py:18", "src/tools/sql.py:9"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-1427",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The boundary to add (untrusted content in a data channel; least-agency tool scope; human-in-the-loop for the SQL tool; authorization in code) plus the reproduction recipe for /ray-detonator: the injected document, the query that retrieves it, the expected tool call.",
  "vuln_class": "Optional. The docket class id, e.g. 'INJECTION'.",
  "owasp_llm": "Optional. e.g. 'LLM01'.",
  "history": [
    { "stage": "oracle", "action": "created", "details": "LLM-integration security finding recorded.", "pass_number": 1, "timestamp": "<current_iso8601_timestamp>" }
  ]
}
```

______________________________________________________________________

## 6. Surface Ledger

1. Resolve `N` = `pass_number`; if missing, `max` archive pass folder + 1, else 1.
2. Copy any existing `workspace/ledgers/ray-oracle.json` to
   `workspace/archive/ledgers/ray-oracle_pass_${N}.json` (`mkdir -p` first).
3. Write the new ledger to `workspace/ledgers/ray-oracle.json`.

```json
{
  "skill": "ray-oracle",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "ai_surface": {
    "model_call_sites": ["src/agent/run.py:31"],
    "untrusted_prompt_fragments": ["end-user message", "RAG docs (src/rag/retrieve.py:18)"],
    "output_consumers": [{"sink": "src/render.tsx:44", "kind": "html"}, {"sink": "src/tools/sql.py:9", "kind": "sql-exec"}],
    "tools": [{"name": "run_sql", "capability": "arbitrary read/write DB", "human_in_loop": false, "authz_independent_of_model": false}],
    "metered": false
  },
  "classes": [
    { "id": "INJECTION", "state": "ASSESSED | NO_SINKS | NOT_ASSESSED", "finding_ids": [] }
  ]
}
```

Every class in the docket appears exactly once (`ASSESSED`/`NO_SINKS`/
`NOT_ASSESSED`). If the target has **no** LLM integration at all, record the whole
sweep `NOT_APPLICABLE` with that reason — do not manufacture AI findings for an
app that has no AI surface.
