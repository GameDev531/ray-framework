# Default review docket (any language without its own file)

Read the taxonomy first (`../review_taxonomy.md`). Use this when the file's
language has no dedicated docket under `lang/`. Apply the universal checklist
(taxonomy §8) plus the general traps below, and lean harder on precision because
you have fewer language-specific certainties.

## Correctness

- Boundary and empty cases; off-by-one; a condition that is inverted or has the
  wrong operator precedence; a `null`/nil/None/undefined not handled on a
  reachable path; float/decimal equality; integer division/overflow.
- Error handling: an error swallowed, ignored, or logged-and-continued where it
  should stop; an over-broad catch; a lost cause/traceback.
- Concurrency **only where there is evidence of it** (a thread/async spawn, shared
  state, a handler): check-then-act, unguarded shared mutation, a lock across I/O.

## Resources

- Anything acquired (file, socket, connection, lock, handle) and not released on
  every path, including error paths. A cleanup registered inside a loop or after
  the error check.

## Performance (only with evidence it is hot)

- A query or expensive call inside a loop (N+1); an unbounded allocation or
  result set; redundant work not hoisted out of a loop; a linear scan where a set/
  map lookup is meant — but only when the data is realistically large or the path
  is hot.

## Maintainability

- Duplicated logic that should be shared; naming that misleads; a function doing
  too much; a violation of a pattern the rest of the module clearly follows;
  a magic value that wants a name.

## Tests

- Critical or boundary logic with no test; a changed test that cannot fail, over-
  mocks, or asserts the wrong thing.

## Security (triage → hand off)

Anything that looks like injection, missing authz, a secret, unsafe
deserialization, SSRF, or weak crypto — raise a short `security` triage finding
and route to the owning domain skill (`review_taxonomy.md` §7). No deep audit
here.

## Do NOT report

- Anything the project's formatter/linter/compiler reports reliably.
- A style preference the project has clearly chosen for itself.
- A "possible" issue you cannot ground in a specific line and fact — without a
  language docket to back you, an unevidenced guess is especially likely to be a
  false positive. Stay silent instead.
