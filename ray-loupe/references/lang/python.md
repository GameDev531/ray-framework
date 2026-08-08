# Python review docket

Read the taxonomy first (`../review_taxonomy.md`). Python-specific checklist.

## Correctness and edge cases

- Mutable default arguments (`def f(x=[])`, `={}`) shared across calls; class-level
  mutable attributes shared across instances; loop-variable closures capturing the
  final value.
- Empty input, off-by-one, `None` where a value is assumed, float `==` equality,
  integer `//` truncation, `ZeroDivisionError`, dict access by missing key
  (`d[k]` vs `d.get`).
- Identity vs equality: `is` against literals/strings/ints (works by luck of
  interning, breaks silently).

## Errors

- Bare `except:` or over-broad `except Exception:` that swallows; a silent `pass`
  in an except; losing the traceback (`raise NewError()` instead of
  `raise NewError() from err`); an over-wide `try` covering more than the risky
  call.
- `assert` used for validation — stripped under `python -O`, so it is not a check.

## Resources and concurrency

- A file/socket/lock acquired without `with`.
- Blocking calls (sync I/O, `time.sleep`, CPU-bound work) inside `async def`; an
  unawaited coroutine/task; `asyncio` gather without handling exceptions.
- GIL reality: threads do not speed up CPU-bound work — flag a `ThreadPool` used
  for CPU-bound loops as a performance defect.

## Performance

- `+=` string building in a loop (use `"".join`); membership test against a
  `list` where a `set` is meant; building a full list where a generator suffices;
  loop-invariant work not hoisted; eager f-string interpolation passed into
  `logging` (use `logger.info("%s", x)`).

## Security (triage → hand off)

- `eval`/`exec`/`pickle.loads`/`yaml.load` (non-safe)/`subprocess(..., shell=True)`
  /SQL string concatenation → triage and hand to `/ray-crucible`. `md5`/`sha1` for
  passwords → `/ray-turnstile`. Secrets in logs → `/ray-custodian`.

## Do NOT report

- Anything `ruff`/`flake8`/`black`/`mypy` reports reliably, absent a concrete
  consequence.
- Typos at *reference* sites (a real undefined name is a runtime error caught
  elsewhere); do flag a typo'd keyword argument or attribute at a *declaration*
  that silently does nothing.
- A broad `except Exception` that is deliberately re-raised or logged with the
  traceback preserved.
