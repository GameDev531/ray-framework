# C / C++ review docket

Read the taxonomy first (`../review_taxonomy.md`). Note: deep memory-safety is
`/ray-marrow`'s job — this docket is for general review, so **triage** memory
issues and hand them off, and focus your own findings on correctness, resource,
and idiom.

## Correctness

- Off-by-one on array/buffer bounds; signed/unsigned comparison surprises; integer
  overflow before use; uninitialized variable read; missing `break` in a `switch`;
  operator precedence (`&` vs `&&`, shift vs add).
- Return value of an allocation / `read`/`write`/`snprintf` ignored where it
  matters (short read, truncation).

## Resources (C++)

- RAII: a raw `new`/`malloc` whose `delete`/`free` is not on every path — prefer a
  smart pointer / container. A resource acquired without a guard.
- Rule of three/five/zero violations; a copy where a move is intended; a dangling
  reference/iterator (container mutated during iteration).
- `const` correctness where it expresses a real contract; `auto` that obscures a
  costly copy (`auto x = bigVec[i]` copying).

## Memory-safety (triage → /ray-marrow)

`memcpy`/`strcpy`/`sprintf` with an unclear length, use-after-free/double-free,
type confusion, format string, `alloca`/VLA sized by input — raise a short
`security`/`bug` triage finding and hand the depth (sink, provenance, sanitizer)
to `/ray-marrow`. Do not do the full memory-safety analysis here.

## Do NOT report

- Anything `clang-tidy`/`cppcheck`/the compiler with `-Wall -Wextra` reports
  reliably, absent a concrete consequence.
- A `new`/`malloc` whose cleanup is correctly handled by an owning RAII wrapper.
- An OOB "read past the buffer" that lands inside a documented over-allocation
  (padding) — that is `/ray-marrow`'s allocator-contract trap; do not flag it.
