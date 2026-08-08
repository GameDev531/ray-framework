# TypeScript / JavaScript review docket

Read the taxonomy first (`../review_taxonomy.md`). TS/JS-specific checklist,
including React/frontend.

## Correctness

- `==`/`!=` instead of `===`/`!==` (coercion bugs); truthiness bugs on `0`/`""`/
  `NaN`; `null` vs `undefined` confusion; missing `await` on a Promise (a floating
  promise, an unhandled rejection); `for..in` over arrays.
- Number pitfalls: float equality, `parseInt` without radix, integer precision
  past `Number.MAX_SAFE_INTEGER`.
- `any` that erases a real type contract; a non-null assertion `!` masking a real
  nullable.

## Async

- Independent awaits run sequentially where `Promise.all` is meant; a `try/catch`
  that swallows; an async function whose rejection no one handles; a race between
  two awaited state updates.

## React / frontend (when present)

- Hooks called conditionally or in a loop (rules of hooks); `useEffect` missing a
  dependency, or missing a cleanup for a subscription/timer; state derived from
  props stored in state (stale); a component declared *inside* another component
  (remounts every render); side effects in render; over- or under-memoization
  (`useMemo`/`useCallback` cargo-culted, or a genuinely expensive value not
  memoized). **Framework versions shift these idioms — check the version.**
- `dangerouslySetInnerHTML` / `innerHTML` with unsanitized data → `security`
  triage → `/ray-crucible`.

## Maintainability

- Duplicated logic; hardcoded business strings/URLs/config; nested ternaries;
  a magic number that wants a named constant.

## Security (triage → hand off)

- `eval`/`new Function`/string-`setTimeout`, prototype-pollution-prone merges,
  exposed keys in client code, `innerHTML` → `/ray-crucible` or `/ray-seam`.

## Do NOT report

- Anything ESLint/Prettier/`tsc` reports reliably.
- `var` / `==` / `any` where the project's own config already forbids or allows
  them — defer to the project's lint config, don't relitigate it.
- Missing `rel="noopener"` on `target="_blank"` in modern bundlers/browsers that
  default to it (see `/ray-seam` for the security nuance).
- Memoization suggestions without evidence the value is expensive or the
  re-render is real.
