# Findings Contract — ray-loupe

How this stage writes its output: findings, the review report, and the coverage
ledger. Read before writing findings and again at Step 5.

`ray-loupe` findings use the standard Ray schema so `/ray-condenser` and the rest
of the pipeline can consume them, plus a `category` field for the review
taxonomy. The extra deliverables are a human review report and a coverage ledger.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity and Category](#2-severity-and-category)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. Findings Schema](#4-findings-schema)
- [5. The Review Report](#5-the-review-report)
- [6. The Coverage Ledger](#6-the-coverage-ledger)

______________________________________________________________________

## 1. Evidence Discipline

The taxonomy file (`review_taxonomy.md`) carries the full discipline; the parts
that decide whether a finding is written at all:

- **Precision over recall.** Write a finding only when confident it is a real
  defect. Silence beats a false alarm.
- **Evidence, not names.** Cite the specific line and the specific fact
  (the unclosed handle, the missing guard, the broken contract). "Possible X" is
  not a finding.
- **On changed lines only**, with cross-file issues routed to the cross-file pass.
- **Survives the self-check.** A finding must not be droppable from the diff
  alone — if the falsify-don't-verify pass can prove it wrong without extra
  context, it should never have been written.
- **Security is triage** with a hand-off to the owning domain skill; no deep
  audit here.

______________________________________________________________________

## 2. Severity and Category

`category` ∈ `bug | security | performance | maintainability | test | style |
documentation | other`. `severity` ∈ `critical | high | medium | low`.

Defaults (calibrate to real consequence, not to how alarming it sounds):

| Situation | category / severity |
|---|---|
| Logic error that produces wrong output on a realistic input | `bug` / high |
| Unhandled error or nil/None deref on a reachable path | `bug` / high |
| Data race / concurrency bug with evidence of concurrency | `bug` / high |
| Off-by-one, boundary miss, resource leak | `bug` / medium–high |
| Plausible vulnerability (triage) | `security` / by class, hand off for depth |
| N+1, O(n²) on hot data, unbounded allocation | `performance` / medium–high |
| Duplicated logic, unclear naming, pattern violation | `maintainability` / low–medium |
| Missing test on critical/boundary logic; a test that can't fail | `test` / medium |
| Idiom/convention deviation | `style` / low |
| Missing/wrong doc on a public API or non-obvious invariant | `documentation` / low |

Rank findings severity-first, then category (bug/security before style/docs).

______________________________________________________________________

## 3. The Four Computed Fields

Same as every Ray stage, so findings fold across the pipeline.

**`cwe`** — set it only for `security`-category findings (from the owning domain
docket); omit for non-security categories. It feeds the signature when present.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:
`normalized_title` = title lowercased, non-`[a-zA-Z0-9]` stripped (empty → first
16 hex of `sha256(raw title)`); `cwe_part` = the cwe or empty; `primary_target` =
first `code_paths` entry minus `:line`. Order `code_paths` with the anchored line
first. Compute once; never recompute.

**`lineage_id`** — inherit from an archived finding with the same `signature`
(highest pass wins), basename-rename fallback; else fresh UUIDv4.

**`discovery_commit`** — the reviewed `--head`/`--commit` sha when reviewing a
committed ref; **omit the key** when reviewing an uncommitted working tree
(MODE-OFF), consistent with the DEGRADED-mode rule.

______________________________________________________________________

## 4. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "rows not closed on the error path in listInvoices",
  "description": "The specific defect and the evidence: the line, the fact (the deferred close is inside the err==nil block, so an early error leaks the connection), and the realistic input/state that triggers it.",
  "impact": "The concrete consequence (connection-pool exhaustion under errors; wrong total returned to the user; a test that never fails).",
  "category": "bug | security | performance | maintainability | test | style | documentation | other",
  "severity": "critical | high | medium | low",
  "code_paths": ["src/db/invoices.go:44"],
  "discovery_commit": "reviewed head sha, or omit the key for an uncommitted working-tree review",
  "cwe": "set only for security-category findings; omit otherwise",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The concrete change (move the defer above the error check; close explicitly on each return), plus a test that would encode it when the project has a suite.",
  "security_owner": "for security-category findings only: the domain skill that owns the depth, e.g. '/ray-turnstile'.",
  "confidence": "high | medium — reviewer's confidence; medium findings are the first to drop in the self-check.",
  "history": [
    { "stage": "loupe", "action": "created", "details": "Code-review finding recorded.", "pass_number": 1, "timestamp": "<current_iso8601_timestamp>" }
  ]
}
```

`security`-category findings keep `description` at triage depth and set
`security_owner`. Non-security findings omit `cwe` and `security_owner`.

______________________________________________________________________

## 5. The Review Report

Write `workspace/reviews/<run>/report.md` — the human packet:

- **Summary**: what was reviewed (target, files covered / in scope), counts by
  severity and category, and the headline (the few things that block).
- **Findings by file**, each grouped and severity-ranked, with the anchored line,
  the description, and the suggested change. Security findings show the hand-off
  target.
- **`--scan` only** — a project-level rollup: Top Issues, Module Hotspots,
  Cross-Cutting Concerns, Quick Wins.

Keep it scannable: a reviewer should see what blocks in the first screen.

______________________________________________________________________

## 6. The Coverage Ledger

`workspace/ledgers/ray-loupe.json` makes the review honest about what it actually
covered — the frozen denominator plus each file's terminal state.

```json
{
  "skill": "ray-loupe",
  "run_id": "<iso8601-or-uuid>",
  "target": "range main..feature | commit <sha> | working-tree | scan",
  "in_scope": ["src/db/invoices.go", "src/api/orders.ts", "test/orders_test.ts"],
  "excluded": [{ "path": "dist/bundle.js", "reason": "generated" }],
  "files": [
    { "path": "src/db/invoices.go", "language": "go", "state": "completed", "findings": 2 },
    { "path": "src/huge_generated.ts", "language": "ts", "state": "failed(size)", "findings": 0 }
  ],
  "cross_file": { "ran": true, "index_used": true, "findings": 1 },
  "self_check": { "reviewed": 14, "dropped": 3 },
  "terminal_state": "complete | partial"
}
```

Every in-scope file appears in `files` with a state: `completed`, `reused` (from
a prior `--scan` run), or `failed(<class>)` (`size`, `parse`, `timeout`). Test
files are in scope — never excluded as a class. If the run could not cover
everything, `terminal_state` is `partial` and the report says so plainly; a
partial review that claims completeness is the one thing this ledger exists to
prevent.
