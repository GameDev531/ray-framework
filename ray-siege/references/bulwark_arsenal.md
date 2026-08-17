# Bulwark Arsenal — the defensive tools, driven honestly

The tools `ray-bulwark` reaches for to **find the root cause** of a proven
break-in and **verify the patch actually closes it** — not just blocks the one
payload the reaver happened to send. Same hybrid model as the offensive side: Ray
drives the real binary (semgrep, gitleaks, tfsec) when present, via the gated
`ray_arsenal.py` helper (`ray_arsenal_list` / `ray_arsenal_run`), and falls back
to a bundled Ray tool or a manual technique when it is absent.

This is the blue-team counterpart to `reaver_arsenal.md`. It binds to the same
`siege_protocol.md` §1 gate. The bulwark's job and its limits are in
`agents/ray-bulwark.md`; this file is the tool catalog.

## Table of Contents

- [0. The rule that binds the defensive arsenal](#0-the-rule-that-binds-the-defensive-arsenal)
- [1. Offense → defense pairing](#1-offense--defense-pairing)
- [2. The tools](#2-the-tools)
- [3. Already covered by a Ray tool](#3-already-covered-by-a-ray-tool)
- [4. Making the fix stick — shift-left (CI gates)](#4-making-the-fix-stick--shift-left-ci-gates)

______________________________________________________________________

## 0. The rule that binds the defensive arsenal

**Verify the cause is gone, not that the string is blocked.** A defensive tool
earns its place only if it tells you something about the *root cause*. Use SAST to
find every sibling of the proven sink (the one the reaver hit is rarely the only
one); use a secret scanner to confirm the patch left no credential behind; use the
IaC scanner to confirm the misconfig the app exposed is actually closed. A fix
that merely blocks the reaver's literal payload will be bypassed by the re-attack
variants (`live_exploitation.md` §5), and correctly so. The tools here exist to
push you toward the cause — they do not replace reading the sink and its framework
idiom (the mapped domain docket states the correct pattern).

Absent-tool honesty is the same as the offensive side: if `ray_arsenal_list`
shows a tool is not installed, use its fallback; never claim a scan you did not run.

______________________________________________________________________

## 1. Offense → defense pairing

For each thing the reaver proved, the blue-team counterpart that finds the cause
and verifies the close:

| Reaver proved (offense) | Bulwark counterpart (defense) | What the counterpart proves about the fix |
|---|---|---|
| SQLi / command inj / SSTI (`sqlmap`, manual) | `semgrep` over the sink's class | every sibling sink is parameterized/escaped, not just the one hit |
| Auth bypass / IDOR / JWT forgery (`jwt_tool`) | `semgrep` authz rules + read the middleware | the query is scoped to the principal / the token verified properly, app-wide |
| Secret / key exposure | `gitleaks` over the tree | the patch introduced no hardcoded secret and none remains reachable |
| IaC/infra misconfig the app exposed | `tfsec` (fallback `ray_iac_scan`) | the open ingress / wildcard IAM / public store is actually closed |
| Vulnerable dependency reachable | `ray_sbom_generate` (ray-manifest) | the bumped/repinned version clears the advisory |
| Memory-safety break-in (native target) | ASan/UBSan build + `ray-detonator` re-run | the fix removes the UB, not just the crashing input |
| Regression risk on any fix | the project's own test runner | a test encodes the closed hole so a later refactor can't reopen it |

______________________________________________________________________

## 2. The tools

### `semgrep` — find the root cause and its siblings (SAST)

The primary blue-team tool. After the reaver proves a sink, run semgrep over the
codebase for that **class**, so you patch every sibling, not just the proven one.

- Drive: `ray_arsenal_run(tool="semgrep", target="<path>", args=[…])`. `--config
  auto` pulls rules from the registry (needs network); offline, pass a local
  ruleset in `args` (`--config <dir>`).
- Proves: the fix is applied to the whole class, so the re-attack's alternate-
  ingress variant has nothing to reach.
- Fallback: grep the sink pattern from the mapped domain docket
  (`ray-crucible` injection_docket for injection, `ray-turnstile` identity_docket
  for authz) across the tree to enumerate siblings by hand.

### `gitleaks` — secret hygiene on the patch

- Drive: `ray_arsenal_run(tool="gitleaks", target="<repo path>")` (runs
  `detect --redact`).
- Proves: your fix added no hardcoded credential, and none remains in the tree
  that the exposure finding could still surface.
- Fallback: `ray_metadata.py` harvests leaked secrets from build artifacts; for
  source, grep high-entropy assignments to confirm the patch left none.

### `tfsec` — verify an infra misconfig is closed

When the break-in rode on infrastructure the running app exposed (a debug port, a
public store, an over-privileged role), harden the IaC and re-scan.

- Drive: `ray_arsenal_run(tool="tfsec", target="<iac path>")`.
- Proves: the specific misconfig the reaver reached is gone.
- Fallback: `ray_iac_scan` (the bundled `ray_iac.py` / MCP tool) runs the
  bounded, dependency-free IaC scan — always available, no install needed.

______________________________________________________________________

## 3. Already covered by a Ray tool

The defensive arsenal is deliberately small because Ray already *owns* several
blue-team jobs with bundled tools — use those directly, don't reach for an
external duplicate:

- **Dependency remediation** → `ray_sbom_generate` (ray-manifest): parses the
  lockfile, flags the vulnerable version, and re-checks after the bump. `npm audit
  fix` / re-lock is the manual complement.
- **Memory-safety fixes** → `ray-detonator` + `ray-marrow`: the sanitizer build
  and PoC re-run are the verification loop for native break-ins; the bulwark
  re-runs the reaver's PoC under ASan/UBSan to confirm the UB is gone.
- **Regression durability** → the project's own test suite: the single most
  important "tool" is a test that encodes the closed hole, added in the same
  commit (charter rule 5). No external tool substitutes for it.

The result is a blue team that drives real SAST/secret/IaC scanners for the cause,
leans on Ray's own tools for SCA and memory safety, and always leaves a test
behind — inside the same minimal, one-finding-one-commit charter.

______________________________________________________________________

## 4. Making the fix stick — shift-left (CI gates)

A fix the bulwark commits closes one hole today; a **gate** keeps it closed and
catches the next one. When the finding warrants it (a class the project keeps
re-introducing), the durable remediation is a pipeline gate, not just the patch.
Same tools, moved to CI. (Compiled with the Apache-2.0 DevSecOps corpus in
`CREDITS.md`.)

| Class of finding | The gate that keeps it fixed |
|---|---|
| Injection / the sink's class | `semgrep --config <ruleset> --error` in CI (SAST) — fail the build on the pattern; a custom rule for the exact sink shape the reaver hit |
| Running-app regressions | `zap-baseline` / the arsenal's own DAST re-run against the ephemeral app in CI |
| Leaked secret | `ray_secrets.py --strict` + `gitleaks` as a pre-commit hook **and** a required CI check (see `ray-cloak` docket §7) |
| Vulnerable dependency | `ray_sbom_generate` / `osv-scanner` / `trivy` as a CI step that fails on a known-vulnerable version (`ray-manifest`) |
| IaC / image misconfig | `trivy config` + `trivy image` in the pipeline (`ray-terrain` §5) |

Two rules keep the gate honest, mirroring the offensive gate's discipline:
**fail closed** (the check blocks the merge; never `continue-on-error` a security
gate green), and **least-privilege the pipeline itself** (pin third-party actions
to a SHA, source secrets from the CI manager, minimal token scope) — a scanner
running inside an injectable, over-privileged workflow is a weak gate. Proposing a
gate is in charter as part of a fix's `mitigation`; wiring the whole CI is the
user's call, not a silent expansion of the one-finding diff.
