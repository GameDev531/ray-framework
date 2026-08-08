# Java review docket

Read the taxonomy first (`../review_taxonomy.md`). Java-specific checklist.

## Correctness

- NPE patterns: unchecked return of a nullable, autoboxing a `null` `Integer`,
  `.equals` called on a possibly-null receiver (prefer `Objects.equals` or
  constant-first).
- Boundary/index errors; boolean operator precedence and short-circuit mistakes;
  a misplaced `return`/`break`/`continue`.
- `switch` fall-through: a missing `break`, **and** an intentional fall-through
  with no explanatory comment (flag both — one is a bug, one is unreadable).
- `==` on objects (String/Integer) where `.equals` is meant; `Integer` cache
  making `==` work by luck up to 127.

## Resources and concurrency

- A resource (stream, connection, lock) not closed — prefer try-with-resources.
- Thread safety: unsynchronized access to shared mutable state; a check-then-act
  on a shared field; a non-thread-safe collection shared across threads;
  `SimpleDateFormat` shared; double-checked locking without `volatile`.

## Performance

- A DB query inside a loop / N+1; loading an unpaginated large dataset; nested
  loops that are O(n²) on real data; building strings with `+` in a loop (use
  `StringBuilder`).

## Do NOT report (thread-safety exclusions especially)

Do **not** flag "not thread-safe" for any of these — they are safe by
construction and reporting them is the classic Java-review false positive:

- Method-local variables (each call has its own).
- Code that runs in a single-threaded context (a request-scoped bean, a `main`,
  a single-threaded executor).
- Read-only operations on immutable objects; already-`synchronized`/`Concurrent*`
  code; a Builder or other object documented as single-threaded-per-instance.

Also do not report anything Checkstyle/SpotBugs/the compiler reports reliably,
or style the project's own config governs.
