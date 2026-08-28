# Review Taxonomy & Cross-Cutting Discipline

What `ray-loupe` reviews, and the rules every reviewer applies regardless of
language. Read this before dispatching, and the per-file reviewer reads it too.
The language dockets under `lang/` carry the specifics; this file carries the
categories and the discipline that keeps the review high-precision.

## Table of Contents

- [1. Categories and Severities](#1-categories-and-severities)
- [2. Precision Over Recall](#2-precision-over-recall)
- [3. Evidence Before Claim](#3-evidence-before-claim)
- [4. Deconflict With Tooling](#4-deconflict-with-tooling)
- [5. Scope Fencing](#5-scope-fencing)
- [6. Version and Ecosystem Awareness](#6-version-and-ecosystem-awareness)
- [7. Security: Triage and Hand Off](#7-security-triage-and-hand-off)
- [8. The Universal Checklist](#8-the-universal-checklist)

______________________________________________________________________

## 1. Categories and Severities

Every finding carries exactly one **category** and one **severity**.

**Categories:** `bug` · `security` · `performance` · `maintainability` · `test` ·
`style` · `documentation` · `other`.

**Severities:** `critical` · `high` · `medium` · `low`.

- **`bug`** — incorrect behavior: wrong logic, missing edge/boundary case,
  mishandled error, race, off-by-one, resource leak, contract violation.
- **`security`** — a potential vulnerability. **Triage only** here; hand depth to
  the domain suite (§7).
- **`performance`** — an algorithmic or resource problem with a real, evidenced
  consequence: N+1 query, O(n²) on hot data, unbounded allocation, redundant work
  in a loop.
- **`maintainability`** — clarity that will cost the next reader: unclear naming,
  duplicated logic, a leaky abstraction, a violation of the project's own
  established pattern.
- **`test`** — missing coverage of critical/boundary logic, or a defect *in* a
  test (a test that can't fail, a flaky sleep, an over-broad mock).
- **`style`** — idiom and convention. Non-blocking by default.
- **`documentation`** — a missing or wrong doc/comment where it materially helps.
- **`other`** — anything real that fits nothing above.

**Blocking discipline:** treat `bug` and `security` as blocking; `style` and
`documentation` as non-blocking suggestions. Rank findings severity-first, then
category, so the reader sees what matters first.

______________________________________________________________________

## 2. Precision Over Recall

The single rule that defines this skill: **only raise an issue when you are
confident it is a real defect; stay silent when the surrounding context is
unclear.** A false alarm costs more reviewer trust than a missed minor issue.

Consequences:

- When you are unsure whether something is a bug, gather the context (read the
  callers, the types, the tests) before commenting. If you still cannot confirm
  it, do not comment.
- Prefer a false negative on a *minor* issue to a false positive. This does not
  apply to `critical`/`high` `bug`/`security` — for those, a well-evidenced
  suspicion is worth raising with the uncertainty stated.
- Every language docket ends with a **"Do NOT report"** list. Honor it. Those are
  the patterns that look like defects but are not, and reporting them is exactly
  how a reviewer loses trust.

______________________________________________________________________

## 3. Evidence Before Claim

Do **not** infer a defect from a name or an import. Before a non-local claim,
establish the fact from the code:

- Do not claim a **concurrency** bug without evidence of concurrent invocation (a
  thread/goroutine/async spawn, a shared-state entry point, a handler).
- Do not claim **attacker control** without tracing the value to an untrusted
  source; a trusted constant is not tainted.
- Do not claim a **resource leak**, a **nil deref**, or a broken **error
  contract** from a function's name — read the ownership, the guard, the contract.
- Do not claim a **performance** problem without a reason it is hot (a loop over
  attacker/large data, a query in a request path) — micro-inefficiency on a cold
  path is noise.

A finding that names the specific evidence ("`rows` is never closed on the error
path at line 44; the deferred close is inside the `if err == nil` block") is one
that survives the self-check. A finding that says "possible leak" does not.

______________________________________________________________________

## 4. Deconflict With Tooling

Ray is not a linter. Do not duplicate what a compiler, type checker, formatter,
or standard linter reports reliably on its own (unused variables, formatting,
obvious type errors, `gofmt`/`prettier`/`black` output) — **unless** the change
shows a concrete, user-visible consequence those tools will not express. Assume
the project runs its linters; comment on what they miss: logic, contracts,
concurrency, design, and cross-file consequences.

______________________________________________________________________

## 5. Scope Fencing

Review the **changed lines** of the file in front of you. Context tools (reading
other files, the index) are for *understanding* the change, not for expanding the
review:

- Comment on newly added/changed code. Do not comment on unchanged code, or on
  deleted lines (they are reference context only).
- A real issue you notice in *another* file while gathering context is a
  **cross-file candidate** — surface it to the orchestrator's cross-file pass
  (Step 3), don't comment it in place. (This is where Ray exceeds per-file-only
  tools: the cross-file pass *does* act on these, using the AST index.)
- Do not comment on generated files, metadata, or tool markers.

______________________________________________________________________

## 6. Version and Ecosystem Awareness

Do not apply stale knowledge. Language and framework semantics change, and a
confident comment based on an old version is a false positive. Check the
version the project targets before flagging version-sensitive patterns — the
language dockets call out the specific traps (e.g. Go loop-variable capture
changed in 1.22; unstopped timers stopped leaking in 1.23; React and framework
idioms shift). When unsure of the version, either read it from the manifest or
soften the finding to name the assumption.

______________________________________________________________________

## 7. Security: Triage and Hand Off

`ray-loupe` is a general reviewer with a security-aware eye, not a security
auditor. When you see a plausible vulnerability:

1. Raise a `security` finding at **triage** depth — name the class and the line,
   state why it looks exploitable, keep it short.
2. Point at the domain skill that owns the depth: injection/XSS/SSRF/deser →
   `/ray-crucible`; authn/authz/IDOR/tenancy → `/ray-turnstile`; secrets/privacy
   → `/ray-custodian`; client-trust/CORS/errors → `/ray-seam`; rate-limit/
   webhooks → `/ray-sentry`; datastore/crypto → `/ray-vault`; infra/CI →
   `/ray-citadel`; memory-safety → `/ray-marrow`; LLM integration → `/ray-oracle`.
3. Do not attempt the full audit or a PoC here. Depth is the suite's job; your
   value is catching it in the flow of a general review and routing it.

______________________________________________________________________

## 8. The Universal Checklist

Applied to any file, on top of its language docket. Terse by design — the depth
is per-language.

**Correctness.** Is the logic right? Are boundary and empty/None cases handled?
Are errors handled (not swallowed, not lost)? Is it safe under the concurrency
the code actually has?

**Performance.** Any N+1, unbounded loop/allocation, or redundant work on a hot
path? Are resources released?

**Maintainability.** Is it clear? Do names express intent? Does it duplicate
existing logic, or violate the project's established pattern?

**Tests.** Do critical/boundary paths have tests? Are the changed tests
meaningful (can they fail; do they assert the right thing)?

**Docs.** Where a doc/comment materially helps a future reader (a non-obvious
invariant, a public API), is it present and correct?

Everything else — the language-specific traps, the "do not report" lists, the
idioms — is in `lang/<language>.md`. Read the one that matches the file.
