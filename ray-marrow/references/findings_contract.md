# Findings Contract — ray-marrow

How this stage writes its output. Read it before writing the first finding of a
pass, and again when assembling the sink ledger.

Like `/ray-crucible`, this stage feeds `/ray-detonator`, so the contract carries
an extra duty: a finding must name the sanitizer that would prove it and the
input to mutate. A memory-safety finding without a reproduction path is a
`NEEDS_RESEARCH`, not a HIGH.

## Table of Contents

- [1. Evidence Discipline](#1-evidence-discipline)
- [2. Severity Defaults](#2-severity-defaults)
- [3. The Four Computed Fields](#3-the-four-computed-fields)
- [4. CWE Set For This Domain](#4-cwe-set-for-this-domain)
- [5. Findings Schema](#5-findings-schema)
- [6. Sink Ledger](#6-sink-ledger)

______________________________________________________________________

## 1. Evidence Discipline

**Anchor at the sink, and include the provenance.** `code_paths[0]` is the sink
(the `memcpy`, the index, the free, the cast); add the site of the attacker-
influenced size/index/lifetime as a second entry, and for UAF add both the
freeing and the using site. A finding that names only a sink and not who controls
the size cannot be reviewed.

**State the bound or contract you ruled out.** "No check on `len` before the
`memcpy` at line 88; `len` is the 32-bit big-endian field decoded at
`parse.c:40`, attacker-controlled and unclamped" is what survives `/ray-arbiter`.

**Respect the allocator contract.** Before a HIGH OOB, confirm the access exceeds
the guaranteed physical allocation, not just the logical length (docket final
section). This is the dominant false positive.

**Hand `/ray-detonator` a real recipe.** Name the sanitizer (ASan/UBSan/TSan/
Miri), the input field to grow, the boundary value, and the expected signature.
A finding you cannot describe how to trigger is `NEEDS_RESEARCH`.

**Compile and run nothing here.** No sanitizer builds, no crashes triggered.
Static reasoning only; proof is the next stage's job.

**Status.** Default `PROVISIONALLY_VALID` — memory-safety feasibility often
depends on heap layout or timing the static read cannot settle, and
`/ray-arbiter`/`/ray-detonator` will confirm. Use `NEEDS_RESEARCH` for `UNKNOWN`
provenance (function pointers, inline asm, opaque FFI).

______________________________________________________________________

## 2. Severity Defaults

Discovery-stage defaults; `ray-gauge` applies the final caps (including the
static-confirmation cap when reproduction is only `statically_confirmed`).

| Situation | Default |
|---|---|
| Attacker-controlled OOB **write** reachable from an external input | CRITICAL (only with a described path; else HIGH) |
| Use-after-free / double-free reachable from input | HIGH |
| OOB **read** disclosing memory across a trust boundary | HIGH |
| Integer overflow feeding an allocation or a bound | HIGH (it is usually the root of an OOB) |
| Type confusion reachable from input | HIGH |
| Format string with a tainted, non-literal format | HIGH |
| Uninitialized read leaking memory to an output boundary | MEDIUM–HIGH |
| Systems data race corrupting shared state | MEDIUM–HIGH |
| `alloca`/VLA/recursion DoS with no memory corruption | MEDIUM |
| OOB read strictly within allocator padding | not a finding (`NEUTRALIZED`) |
| Safe-Rust panic (index out of range, no `unsafe`) | LOW (a DoS, not corruption) |

Reserve CRITICAL for a described path from an unauthenticated/external input to a
controlled write or code execution.

______________________________________________________________________

## 3. The Four Computed Fields

**`cwe`** — this stage should almost always set it (docket §4 names the CWE per
class). Decide first; it feeds the signature.

**`signature`** — first 16 hex of
`sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`:
- `normalized_title` = `title` lowercased, non-`[a-zA-Z0-9]` stripped; empty →
  first 16 hex of `sha256(<raw title as UTF-8>)`.
- `cwe_part` = the `cwe` value or the empty string.
- `primary_target` = first `code_paths` entry minus a trailing `:line`; if empty
  or a non-source LOCATOR, hash over `sorted(code_paths).join(",")`.

Order `code_paths` with the **sink first**, always, then the provenance/free
sites. Compute once at creation; never recompute — re-attack must not change it.

**`lineage_id`** — inherit from an archived finding with the same `signature`
under `workspace/archive/findings_pass_*/` (highest pass wins), with the
basename-rename fallback; else a fresh UUIDv4. STATE-RELATIVE paths.

**`discovery_commit`** — `active_snapshot.snapshot_id` verbatim when pinned;
**omit the key entirely** in DEGRADED mode.

`signature` and `lineage_id` are always computed; only `discovery_commit` is
mode-dependent.

______________________________________________________________________

## 4. CWE Set For This Domain

| Class | CWE |
|---|---|
| `OOB` | `CWE-125` (read), `CWE-787` (write), `CWE-193` (off-by-one) |
| `INTOVER` | `CWE-190`, `CWE-191`, `CWE-197`, `CWE-195` |
| `UAF` | `CWE-416`, `CWE-415`, `CWE-825` |
| `TYPECONF` | `CWE-843` |
| `FMTSTR` | `CWE-134` |
| `UNINIT` | `CWE-457`, `CWE-908` |
| `STACKOF` | `CWE-121`, `CWE-770` |
| `RACE` | `CWE-362`, `CWE-367`, `CWE-366` |
| `RUSTUNSAFE` | `CWE-119` (surfaced through `unsafe`/FFI) |

______________________________________________________________________

## 5. Findings Schema

One JSON object per file at `workspace/findings/<uuid>.json`, no text around it.

```json
{
  "id": "UUID for this finding; must match the filename.",
  "title": "Heap OOB write in tag parser via unchecked 32-bit length",
  "description": "The sink (the memcpy/index/free/cast), the provenance of the attacker-influenced size/index/lifetime and where it enters, the bound or allocator contract you checked and ruled out, and — for the allocator trap — why the access exceeds the guaranteed physical allocation.",
  "impact": "What the primitive yields (e.g., controlled heap write → potential RCE; cross-boundary memory disclosure; remote crash).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["SINK FIRST: src/tag.c:88", "provenance: src/parse.c:40"],
  "discovery_commit": "active_snapshot.snapshot_id, verbatim. Omit entirely in DEGRADED mode.",
  "cwe": "CWE-787",
  "signature": "16 hex chars, per §3.",
  "lineage_id": "UUIDv4 or inherited.",
  "mitigation": "The safe pattern for this call (check len before the copy; use a checked-mul before the malloc), plus the reproduction recipe for /ray-detonator: sanitizer, the input field to grow, the boundary value, and the expected sanitizer signature.",
  "vuln_class": "Optional. The docket class id, e.g. 'OOB'.",
  "history": [
    { "stage": "marrow", "action": "created", "details": "Memory-safety sweep finding recorded.", "pass_number": 1, "timestamp": "<current_iso8601_timestamp>" }
  ]
}
```

______________________________________________________________________

## 6. Sink Ledger

1. Resolve `N` = `pass_number` from `workspace/.ray_state.json`; if missing or
   invalid, use `max` of the `findings_pass_N` / `loopN_findings` folders in
   `workspace/archive/` + 1, defaulting to `1`.
2. If `workspace/ledgers/ray-marrow.json` exists, `mkdir -p
   workspace/archive/ledgers/` and COPY it to
   `workspace/archive/ledgers/ray-marrow_pass_${N}.json`.
3. Write the new ledger to `workspace/ledgers/ray-marrow.json`.

```json
{
  "skill": "ray-marrow",
  "pass_number": 1,
  "snapshot_id": "<snapshot_id or 'UNPINNED'>",
  "classes_requested": "ALL",
  "native_languages": ["c", "c++", "rust-unsafe"],
  "sources": ["src/parse.c: header length/count fields", "argv in src/main.c:20"],
  "classes": [
    {
      "id": "OOB",
      "state": "ASSESSED | NO_SINKS | NOT_ASSESSED",
      "patterns_run": ["memcpy\\(", "\\[i\\]", "buf\\s*\\+"],
      "sinks": [
        { "location": "src/tag.c:88", "verdict": "REACHABLE_UNSAFE | NEUTRALIZED | UNREACHABLE | UNKNOWN", "bound": null, "finding_id": "<uuid or null>" }
      ]
    }
  ]
}
```

Every class in the docket appears exactly once. `NOT_ASSESSED` is valid only when
`--classes` excluded it, and must name that reason. `NO_SINKS` must list
`patterns_run`. Record `native_languages` = which native/unsafe languages were
actually present; if none, the whole sweep is `NOT_APPLICABLE` and the ledger
should say so plainly (a pure-Python/JS/Go-without-cgo target has almost no
surface here — defer to `/ray-crucible` and `/ray-loupe`).
