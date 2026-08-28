# Marrow Docket — marrow

Vulnerable→safe patterns for `ray-marrow`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## Out-of-bounds read/write — CWE-125 / CWE-787 · memory-corruption
- **Broken:** index/length from untrusted input used without a bounds check; off-by-one
  on the terminator; a check on one path but not the error path; `memcpy`/`strcpy`
  with an attacker-influenced size.
- **Safe:** bounds validated against the actual allocation on every path; `memcpy_s`/
  bounded copies; length re-checked after any transformation.

## Use-after-free / double-free — CWE-416 / CWE-415 · memory-corruption
- **Broken:** pointer used after `free`/`realloc`/`drop`; freed on two paths; a stored
  raw pointer outliving its owner; iterator invalidated by a concurrent mutation.
- **Safe:** null-after-free discipline, ownership/RAII/smart pointers, Rust borrow
  rules kept inside `unsafe` too.

## Integer overflow/underflow → allocation/copy — CWE-190 / CWE-191
- **Broken:** `len * size` or `a + b` overflowing before `malloc`/bounds check; signed↔
  unsigned confusion; truncation to a narrower type.
- **Safe:** checked/saturating arithmetic, overflow checks before allocation, explicit
  width handling.

## Type confusion — CWE-843
- **Broken:** a union/tag mismatch, a downcast without a check, reinterpreting bytes as
  a wrong-width type.
- **Safe:** tag checked before access; validated deserialization.

## Uninitialized / format string — CWE-457 / CWE-134
- **Broken:** reading a struct/buffer before it is fully written; `printf(user)`.
- **Safe:** zero-init or fully-populate before use; `printf("%s", user)`.

## FFI boundary — CWE-111
- **Broken:** the safe side passes a slice/len the unsafe side dereferences without
  re-checking; assuming null-termination; ownership transferred ambiguously.
- **Safe:** the boundary re-validates lengths and null-termination; ownership documented
  and enforced.

## What is NOT a finding here

- An OOB access mathematically contained within a documented global allocation padding
  (e.g. `row_bytes + 16`, SIMD tails) — by design (ray-arbiter rule 11).
- A bug reachable only via `assert()`/debug-abort that `NDEBUG` strips in release
  (coordinate with ray-magistrate — NON_VIABLE).
- Safe-language code with no `unsafe`/FFI — not this skill's surface.
