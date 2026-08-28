# Go review docket

Read the taxonomy first (`../review_taxonomy.md`). This is the Go-specific
checklist on top of it. Favor precision: only raise what you can evidence, and
honor the "Do NOT report" list at the end.

## Errors, panics, contracts

- Ignored errors: `_ = f()` or a missing error check where the error is
  meaningful. But an intentionally ignored error on a best-effort call (a
  `Close()` in a defer on a read-only handle) is fine — cite intent.
- `%v` vs `%w`: an error wrapped with `%v` loses the chain that callers
  `errors.Is`/`errors.As` on. Flag only where the chain is actually used.
- A deferred cleanup that clobbers the primary return error
  (`defer func(){ err = cleanup() }()` overwriting a real error).
- `panic` in a request/library path where an error return is the contract.

## Nil, interfaces, value semantics

- Typed nil in an interface: returning a `(*T)(nil)` as an `error`/interface is
  non-nil at the interface — a classic "why is my `err != nil`" bug.
- Copying a struct that contains a `sync.Mutex`/`sync.WaitGroup` (copies the
  lock). Value receivers that mutate and expect persistence.
- `sync.Once` that does not retry after a failed init.

## Context, goroutines, cancellation

- `context.Background()`/`context.TODO()` where a request context should flow.
- A `context.Context` stored in a struct field (should be passed).
- A `cancel` from `context.WithCancel/Timeout` never called (leak).
- A goroutine that outlives its owner with no cancellation/`WaitGroup`, or one
  that writes to a channel no one drains.
- **Version-sensitive:** loop-variable capture in a goroutine is a bug **before
  Go 1.22** and fine at/after it — check the module's `go` directive before
  flagging.

## Channels, locks, shared state

- Check-then-act on shared state without holding the lock across both.
- A lock held across I/O or a blocking call (widens contention/deadlock window).
- `RLock` while mutating; multiple closers of one channel; `WaitGroup.Add` inside
  the goroutine it counts.

## Resource lifecycle

- `rows`/`resp.Body`/files opened and not closed on every path; a `defer Close()`
  placed after the error check so an early-error path leaks.
- `defer` inside an unbounded loop (defers stack until the function returns).
- Missing `rows.Err()` after iterating `sql.Rows`.
- **Version-sensitive:** do not report a missing `timer.Stop()` purely as a GC
  leak on **Go 1.23+** (unreferenced unstopped timers are collected).

## Slices, numbers, boundaries

- Subslice aliasing that retains a huge backing array, or `append` aliasing a
  shared slice.
- Integer overflow/narrowing/signed-unsigned when a size/length crosses widths.
- `copy` return value ignored when the copied count matters.

## Do NOT report

- Anything `gofmt`/`goimports`/`go vet`/`staticcheck` reports reliably, unless the
  change shows a concrete consequence they won't express.
- Missing `Stop()` on a timer on Go 1.23+ (see above).
- Loop-var capture on Go 1.22+ (see above).
- A best-effort `defer x.Close()` on a read path presented as an ignored error.
- Style preferences the project has clearly chosen (receiver names, error string
  casing) unless they violate a stated project rule.
