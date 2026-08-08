# Memory-Safety Docket — Class Procedures

One section per class. Each carries: the sink patterns to grep, the safe pattern,
the false-positive traps that decide most disputes, and the reproduction hint to
hand `/ray-detonator` (which sanitizer, what evidence).

Grep patterns are starting points, not membership decisions. Read the
surrounding code — and above all trace *who controls the size, index, or
lifetime* — before recording a verdict, and record `UNKNOWN` rather than
guessing. Memory-safety findings are decided by provenance, not by the sink alone.

## Table of Contents

- [OOB — Out-of-Bounds Read/Write](#oob--out-of-bounds-readwrite)
- [INTOVER — Integer Overflow, Narrowing, Sign](#intover--integer-overflow-narrowing-sign)
- [UAF — Use-After-Free and Double-Free](#uaf--use-after-free-and-double-free)
- [TYPECONF — Type Confusion](#typeconf--type-confusion)
- [FMTSTR — Format String](#fmtstr--format-string)
- [UNINIT — Uninitialized Read](#uninit--uninitialized-read)
- [STACKOF — Stack Overflow, alloca, VLA, Deep Recursion](#stackof--stack-overflow-alloca-vla-deep-recursion)
- [RACE — Systems Data Races and Low-Level TOCTOU](#race--systems-data-races-and-low-level-toctou)
- [RUSTUNSAFE — Rust unsafe and FFI Boundaries](#rustunsafe--rust-unsafe-and-ffi-boundaries)
- [The Allocator-Contract Trap (read before any OOB verdict)](#the-allocator-contract-trap-read-before-any-oob-verdict)

______________________________________________________________________

## OOB — Out-of-Bounds Read/Write

**CWE-125** (read), **CWE-787** (write), **CWE-193** (off-by-one).

### Grep

```
memcpy|memmove|memset|bcopy|strcpy|strcat|sprintf|vsprintf|stpcpy
strncpy|strncat|snprintf|memcpy_s        # bounded — still check the bound's provenance
\[[a-z_]*\+\+\]|\[[a-z_]*--\]|\[i\]|\[idx\]|\[off\]|\[len\]   # index expressions
->data\s*\+|buf\s*\+|ptr\s*\+            # pointer arithmetic
read\(|recv\(|fread\(|pread\(            # sizes coming off the wire/disk
```

### Safe pattern

The destination size bounds the copy, and the bound is checked against the source
length before the copy — not after:

```c
if (len > sizeof(dst)) return -1;      // check BEFORE
memcpy(dst, src, len);
```

### False-positive traps

- A `memcpy` with a **constant** length, or a length derived only from
  `sizeof(dst)`, is not OOB. Check the third argument's provenance.
- `strncpy` does **not** null-terminate when the source is longer — a following
  `strlen`/`printf` then over-reads. The bounded API can still be the sink.
- An index that a preceding `if (i < n)` guards is safe **only if `n` is the real
  allocation count** and `i` cannot be negative (signed index + attacker value =
  negative index = OOB below the buffer).
- Respect the allocator contract (see the dedicated section below) before
  reporting an over-read into padding.

### Reproduction hint

ASan build (`-fsanitize=address -fno-omit-frame-pointer`). Grow the
attacker-controlled length/index field past the bound; expect
`ERROR: AddressSanitizer: heap-buffer-overflow` (or `stack-`/`global-`) naming
the sink frame. Name the exact input field to mutate.

______________________________________________________________________

## INTOVER — Integer Overflow, Narrowing, Sign

**CWE-190** (overflow), **CWE-191** (underflow), **CWE-197** (narrowing),
**CWE-195** (signed/unsigned). Usually the *root cause* of an OOB — report the
integer bug where it happens, and note the downstream sink.

### Grep

```
malloc\(|calloc\(|realloc\(|alloca\(|new\[\]        # allocation sizes
\*\s*sizeof|count\s*\*|n\s*\*|len\s*\*|\*\s*len      # multiplied sizes
\(int\)|\(short\)|\(char\)|\(uint8_t\)|\(size_t\)    # narrowing casts
- 1\]|len\s*-|size\s*-|n\s*-                         # subtraction underflow
```

### Safe pattern

Overflow-checked arithmetic before allocation/use:

```c
if (count > SIZE_MAX / size) return -1;   // or __builtin_mul_overflow
buf = malloc(count * size);
```

### False-positive traps

- The classic bug: `malloc(n * size)` where `n * size` **wraps** to a small value,
  the allocation succeeds small, and a later loop writes `n` elements. The
  `malloc` line looks fine; the multiplication is the finding.
- Signed→unsigned: a negative `int` length becomes a huge `size_t` at the
  `memcpy`. Trace signedness across the assignment chain.
- `int` truncation of a 64-bit length on LP64: a length that fits in `size_t`
  truncates when stored in an `int` counter, then the counter is used as the real
  bound.
- Not every overflow is exploitable — one on a value that is subsequently
  re-clamped is `NEUTRALIZED`. Cite the clamp.

### Reproduction hint

UBSan (`-fsanitize=undefined`, and note UBSan defaults to recover-mode / exit 0,
so scan stdout for `runtime error: ... overflow` regardless of exit code). For
the resulting OOB, ASan. Provide the field whose value forces the wrap and the
boundary value (e.g. `0x100000001`).

______________________________________________________________________

## UAF — Use-After-Free and Double-Free

**CWE-416** (UAF), **CWE-415** (double-free), **CWE-825** (dangling).

### Grep

```
free\(|delete\b|delete\[\]|kfree\(|g_free\(|release\(|dealloc
->ref|refcount|ref_count|put_|get_       # refcount lifecycle
```

### Safe pattern

Free once, null immediately, and never use after; or a checked refcount whose
final `put` frees. In C++, prefer RAII / smart pointers so lifetime is scoped.

### False-positive traps

- A UAF needs a **free on one path and a use reachable after it** — trace the
  control flow, not just co-occurrence. If the pointer is nulled and every use is
  null-guarded, it is `NEUTRALIZED`.
- **Refcount bugs** are the subtle ones: an early `put` on an error path, a
  missing `get` before storing a pointer, a race between `put` and `get` (also a
  `RACE`). Follow the ownership, not the `free` keyword.
- Callback/async: an object freed in one callback and used in a later one — the
  free and use can be in different files.
- Iterator invalidation (C++ `vector` realloc during iteration; erasing while
  iterating) is a UAF class the grep above misses — check container mutation
  inside loops over the same container.

### Reproduction hint

ASan (`heap-use-after-free` / `double-free`, with allocation and free
backtraces). Give the sequence of operations that frees then uses.

______________________________________________________________________

## TYPECONF — Type Confusion

**CWE-843**.

### Grep

```
reinterpret_cast|static_cast<.*\*>|\(struct\s+\w+\s*\*\)|union\b
dynamic_cast|->type|->kind|->tag|downcast|as_<        # tag-checked dispatch
```

### Rule

A value is read as a type it was not created as, reachable from input: a union
whose wrong arm is read, a downcast without checking the runtime tag, a `void*`
re-cast to the wrong struct, a deserializer that trusts a type field. The safe
pattern checks the tag/type before the cast and treats the tag as untrusted.

### Traps

- A `static_cast` in a context where the static type is provably correct is safe;
  the danger is a cast whose correctness depends on an **input-controlled** tag.
- Union access is only a bug if the arm read differs from the arm last written
  *and* an attacker controls which.

### Reproduction hint

ASan often catches the resulting OOB; UBSan `-fsanitize=vptr` catches bad C++
downcasts. Describe the input that sets the wrong tag.

______________________________________________________________________

## FMTSTR — Format String

**CWE-134**.

### Grep

```
printf\(|fprintf\(|sprintf\(|snprintf\(|syslog\(|err\(|warn\(|vprintf
```

### Rule

The format argument must be a **literal**, never a variable that carries
attacker input. `printf(user)` is the bug; `printf("%s", user)` is safe. Flag any
`*printf`/`syslog` whose format parameter is not a string literal and whose value
can reach input.

### Reproduction hint

A crash or read via `%n`/`%s`; ASan or a controlled harness. In practice, flag on
sight — this class is unambiguous once the format is non-literal and tainted.

______________________________________________________________________

## UNINIT — Uninitialized Read

**CWE-457** (uninitialized use), **CWE-908** (uninitialized resource).

### Grep

```
malloc\(|alloca\(|char\s+\w+\[|struct\s+\w+\s+\w+;    # allocations not zeroed
                                                       # (vs calloc / = {0})
```

### Rule

A stack buffer or heap allocation read before every byte on the path is written —
often on an error path that returns a partially-filled struct, or a `switch` that
misses a case. Leaks stack/heap contents (info disclosure) or drives control on
garbage.

### Traps

- `malloc` + full overwrite before read is safe; the bug is a path where a field
  is read without being set. Trace per-field, not per-struct.
- Padding bytes in a struct copied to output can leak even when every named field
  is set — relevant for structs written to a network/IPC boundary.

### Reproduction hint

MSan — but only on a fully instrumented build including libc; a naive
`-fsanitize=memory` yields bogus traces (note this to `/ray-detonator`). Often
easier to prove by the info-leak observable (garbage bytes in output).

______________________________________________________________________

## STACKOF — Stack Overflow, alloca, VLA, Deep Recursion

**CWE-121** (stack buffer overflow), **CWE-770** (unbounded allocation).

### Grep

```
alloca\(|char\s+\w+\[[a-z_]|__builtin_alloca|VLA       # attacker-sized stack alloc
recursion|recurse|_r\(|parse_.*parse_                   # unbounded recursion
```

### Rule

An `alloca`/VLA whose size is attacker-controlled, or a recursive parser with no
depth limit, exhausts the stack — a crash at minimum, exploitable at worst. The
safe pattern caps the size/depth or uses the heap with a bound.

### Reproduction hint

ASan stack-overflow detection or a SIGSEGV; feed a large size/deeply-nested
input. Note the depth/size that triggers it.

______________________________________________________________________

## RACE — Systems Data Races and Low-Level TOCTOU

**CWE-362** (race), **CWE-367** (TOCTOU), **CWE-366** (race on shared var).
This is *systems* concurrency that corrupts memory or state — distinct from
`/ray-turnstile`'s money-flow TOCTOU.

### What to look for

| Pattern | Shape |
|---|---|
| Data race on shared mutable state | A field read/written from two threads with no lock/atomic; a `check-then-act` on a shared flag |
| Lock held across I/O or a callback | Blocking under a lock invites deadlock and widens the race window |
| Lock-ordering inversion | Two locks acquired in different orders on two paths → deadlock |
| Atomicity violation | A compound update (`x = x + 1`, `if (p) use(p)`) that is not atomic under contention |
| Signal-handler reentrancy | A handler touching non-`sig_atomic_t` state or calling non-async-signal-safe functions |
| Refcount race | Concurrent `get`/`put` without atomics → UAF (also `UAF`) |
| Filesystem TOCTOU | `access()` then `open()`, `stat()` then use — the path changes in between |

### Traps

Only flag concurrency where there is **evidence of concurrent invocation** —
a thread spawn, a thread pool, an async runtime, a signal handler, or shared
global state reached from multiple entry points. Do not infer a race from a
function name. A field protected by a documented single-threaded invariant is
`NEUTRALIZED` — cite the invariant.

### Reproduction hint

TSan (`-fsanitize=thread`, a separate build from ASan). Data races are
probabilistic — do NOT dismiss one for low per-attempt odds if it can be
automated and repeatedly attempted (the `/ray-arbiter` rule preserves this).
Describe the two schedules that collide.

______________________________________________________________________

## RUSTUNSAFE — Rust unsafe and FFI Boundaries

**CWE-119** family, surfaced through `unsafe`.

### Grep

```
unsafe\s*\{|unsafe\s+fn|get_unchecked|from_raw_parts|transmute
\.offset\(|\.add\(|MaybeUninit|ptr::|mem::transmute|extern\s+"C"
```

### Rule

Safe Rust is memory-safe by construction; the audit surface is `unsafe` blocks,
FFI (`extern "C"`), and the invariants they must uphold. Check that
`from_raw_parts` gets a valid pointer and a correct length, that `get_unchecked`
indices are provably in-bounds, that `transmute` respects size/validity, and that
an FFI callee cannot violate an assumption the Rust side makes (aliasing,
lifetime, null). A safe-slice index is a panic (DoS), not corruption — the sink
is the `unsafe`/FFI, not the `[]`.

### Reproduction hint

ASan on the built binary (Rust supports `-Zsanitizer=address` on nightly), or
Miri for UB in `unsafe`. Describe the input that violates the `unsafe` block's
stated invariant.

______________________________________________________________________

## The Allocator-Contract Trap (read before any OOB verdict)

This is the single most common false positive in memory-safety review, and the
one `/ray-arbiter` rule 11 will bounce. Before reporting an out-of-bounds access,
check whether the access lands inside a **deliberate over-allocation** that the
library's own contract guarantees:

- Image/codec libraries routinely over-allocate rows: `png_malloc(rowbytes + 48)`,
  `+ FF_INPUT_BUFFER_PADDING_SIZE`, `+ AV_INPUT_BUFFER_PADDING_SIZE`.
- SIMD/vector code reads in 16/32/64-byte lanes and pads allocations to the lane
  width, so a read a few bytes past the logical length is inside the physical
  allocation by design.
- Arena/slab allocators round up to a size class; an access within the rounded
  size is not OOB of the *allocation* even if it is past the *logical* object.

If the access is within the allocator's guaranteed padding, it is `NEUTRALIZED` —
record the contract and the `file:line` of the over-allocation. Only when the
access exceeds the guaranteed physical allocation is it a finding. Getting this
wrong wastes a `/ray-detonator` attempt and trains reviewers to distrust the
stage.
