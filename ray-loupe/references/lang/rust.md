# Rust review docket

Read the taxonomy first (`../review_taxonomy.md`). Rust-specific checklist. Note
that memory-safety of `unsafe`/FFI is `/ray-marrow`'s depth — triage it here.

## Errors and panics

- `.unwrap()`/`.expect()`/`panic!`/indexing (`v[i]`) on a path reachable from
  input or in a library API — a panic is a DoS for a server. Flag where the input
  is not provably in-range; a `.unwrap()` on a just-checked `Some` is fine.
- `?` that discards useful context (prefer `.context()`/`.map_err`); an error type
  that erases the cause.
- `Result` ignored (`let _ =` on a fallible call that matters).

## Ownership, lifetimes, idiom

- Needless `.clone()` in a hot path where a borrow works; a `Vec`/`String`
  allocation per iteration; collecting into a `Vec` only to iterate once (use the
  iterator).
- A `Mutex`/`RwLock` held across an `.await` (deadlock/contention); blocking calls
  inside async; `RwLock` write where read suffices, or vice versa.

## Concurrency and async

- Shared mutable state without the right sync; cancellation safety — a future that
  leaves state inconsistent if dropped at an `.await` point.
- `unsafe { }` blocks: triage for `/ray-marrow` (validity of `from_raw_parts`,
  `get_unchecked` bounds, `transmute`, FFI invariants). Do not do the memory-safety
  proof here.

## Do NOT report

- Anything `cargo clippy`/`rustfmt`/the compiler reports reliably.
- `.clone()` where it is genuinely necessary or cheap (a `Copy` type, a cold
  path).
- An index/`unwrap` where the value is provably in-range from a preceding check.
- A safe-Rust panic characterized as "memory unsafe" — it is a DoS, not
  corruption.
