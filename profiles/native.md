# Target profile: native

For C/C++/Rust-unsafe/Zig, kernel/driver, parsers, decoders, runtimes/JITs, and
firmware. Selected with `/ray-conductor --profile=native`.

## Domain skills to run

`ray-prospector` (floor) + `ray-marrow` (memory safety is the headline) +
`ray-crucible` (parsers/format-string/command paths) + `ray-vault` (crypto/secrets)
+ `ray-manifest` (native deps). Skip the web-only skills (`ray-seam`,
`ray-custodian`) unless the target also serves HTTP.

## Review Overrides (ray-arbiter)

```
Review Overrides:
- IN_SCOPE: resource_exhaustion   # a DoS in a parser/decoder whose job is to survive hostile input IS in scope (rule 07 exception)
```

## Calibration Overrides (ray-gauge)

```
Calibration Overrides:
- (none by default — the memory-corruption caps are already correct for native code)
```

Dynamic confirmation matters most here: prefer building a minimal harness and
reproducing under a sanitizer (ASan/UBSan/MSan) — `ray-detonator` will demand it.
