# Target profile: library

For a published library/SDK with no long-running service of its own. Selected with
`/ray-conductor --profile=library`.

## Domain skills to run

`ray-prospector` (floor) + the domain skills matching the library's surface
(`ray-crucible` for parsers, `ray-marrow` for native, `ray-vault` for a crypto
library, `ray-oracle` for an agent/LLM SDK) + `ray-manifest` for its own deps.

## Review Overrides (ray-arbiter)

```
Review Overrides:
- IN_SCOPE: intrinsic_only   # emphasize intrinsic flaws (rule 08): a broken primitive or an unsafe default is VALID even with no current caller, because callers are out-of-tree
```

## Calibration Overrides (ray-gauge)

```
Calibration Overrides:
- (none) — but note: a library's callers are unknown, so exposure defaults to the
  declared/default multiplier; do not down-weight on "no caller in this repo".
```

Deployment intent is easy to misread as SAMPLE_OR_TEST for a library — ray-perimeter
must write `Intent: PRODUCTION` when the package is published/installable.
