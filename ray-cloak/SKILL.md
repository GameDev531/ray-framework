---
name: ray-cloak
description: >-
  Prevents an assistant from leaving real secrets in a codebase: database connection strings, API keys, payment-gateway and SMTP keys, tokens, and private keys — in source, tests, JSON/YAML config, Markdown docs, notebooks, SQL dumps, or CI files. A write-time guard, not a pipeline audit stage.
  Use SEMPRE / ALWAYS while writing, editing, or reviewing any file in a project that has a database, an API, or credentials — and as a final sweep before finishing a task or committing.
  Don't use for datastore privilege/exposure hardening (use ray-vault), deep entropy/history secret scanning (drive gitleaks/trufflehog), or live exploitation (use ray-siege).
---

# Cloak (/ray-cloak)

## System Goal

**Secret-Leak Preventer.** A single hardcoded credential in a large project is a
full compromise waiting to happen. This skill's job is to make sure the assistant
never *writes* a real secret into a file it saves or commits, and to catch one if
it slipped in — before it reaches a repository, where "delete it later" is already
too late.

This is a real, recurring failure mode of AI coding assistants, not a
hypothetical. The characteristic leak is **not** an obvious `password = "..."` in
`app.py` — it is the credential the assistant left in a *support* artifact:

- a step-by-step **Markdown** doc ("here's how to fix it") that pastes the DB
  connection string next to the project's admin URL;
- a **throwaway test script** written to check one function, then committed
  instead of deleted;
- a **`config.json` / `serviceAccount.json`** with the live value in it;
- a `process.env.DB_URL || "postgres://user:pass@host"` "convenient" fallback.

**The real-world case this guards against.** A public GitHub repo carried a
Markdown file with the database connection string and the project URL in the same
document. An attacker read the doc, connected straight to the database, opened the
users table, and — even though the passwords were hashed — simply computed fresh
bcrypt hashes and overwrote them, taking over accounts across the customers'
systems. Everything the DB held (users, sessions, legal, accounting documents…)
was exposed. The whole chain started with **one credential in one Markdown file.**
Treat every database URL and gateway key as radioactive: locked away, sourced from
the environment, never in a committed file.

## Command Definition

- **Command:** `/ray-cloak`
- **Description:** A write-time secret-leak guard: an absolute rule for what never
  gets written literally, a high-risk-file checklist, the throwaway-test
  lifecycle, and an evidence-backed sweep (`ray_secret_scan` / `ray_secrets.py`)
  that redacts every value it reports.
- **Arguments (optional):**
  - `--path` / `PATH`: file or directory to sweep (default: the working tree).
  - `--strict`: fail the sweep if any CRITICAL/HIGH secret is present (pre-commit
    gate). Absent → report only.

## The absolute rule

**Never write a real value for any of these into a file:** database / cache /
broker connection strings (`postgres://`, `mysql://`, `mongodb+srv://`,
`redis://`, `amqp://`), passwords, API keys, JWT/OAuth/bearer tokens,
payment-gateway keys (Stripe `sk_live`/`pk_live` and equivalents), SMTP
credentials, cloud keys (AWS `AKIA…`, Google `AIza…`), GitHub/Slack tokens,
webhooks that carry a token, and private keys (`-----BEGIN … PRIVATE KEY-----`,
`.pem`/`.key`).

**Always instead:** read from the environment (`process.env.X`,
`os.environ["X"]`, the framework's config layer) and, in examples and docs, use a
placeholder like `<SUA_CHAVE>` / `<YOUR_KEY>`. There is **no** "just for now" or
"it's only a local/test value" exception — local values leak into commits, and
test values are often real.

## Workflow

1. **Guard as you write (default, always on).** Before saving or committing any
   file, run the absolute rule above against what you are about to write. If a
   value would be literal, replace it with an env-var read + a placeholder in any
   example. This is the cheap step that prevents the leak in the first place.
2. **Apply the high-risk-file checklist.** The file types that leak most are in
   `references/secret_hygiene_docket.md` §1 — `.env`, tests, JSON/YAML, Markdown,
   notebooks, SQL, CI. Read the row for the file type you are touching; each says
   exactly what must never appear and what to do instead.
3. **Honor the throwaway-test lifecycle.** If you create a temporary script to
   exercise a function, treat it as disposable: **create → run → delete →
   confirm the deletion.** Never leave a scratch/test file with a real credential
   in the tree. The docket §2 has the rule and the confirmation step.
4. **Sweep before you finish.** As the last step of any task that wrote or edited
   files, run the scanner over the working tree:
   - `ray_secret_scan(path=<root>)` (MCP), or
     `python3 <plugin>/scripts/ray_secrets.py <root> --json`.
   - It redacts every matched value, so reading the result never re-leaks the
     secret. Treat any CRITICAL/HIGH as blocking.
   - For a hard gate (e.g. pre-commit), add `--strict` / `strict: true` — it exits
     non-zero when a CRITICAL/HIGH secret exists.
5. **Verify `.gitignore` coverage.** The sweep reports whether `.gitignore` covers
   `.env*` (keep a committed `.env.example` with names only), `*.pem`, `*.key`,
   `credentials*`, `serviceAccount*`. Add any missing entry so a secret can never
   be staged.
6. **If a secret is found — or was ever committed — rotate it.** Report the
   file and line to the user, replace the value with an env var, and tell them to
   **rotate the credential immediately (assume it is compromised).** Removing it
   from git history is housekeeping, not remediation — once pushed, it has leaked.
   Never repeat the secret's value back in your reply.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/secret_hygiene_docket.md` | before touching a high-risk file, and at the final sweep | The high-risk-file taxonomy (what never appears in each, and the safe form), the throwaway-test lifecycle, the grep/scanner pattern set, `.gitignore` coverage, the rotation + git-history rule, and when to escalate to gitleaks/trufflehog |

## What powers the sweep

`ray_secrets.py` (exposed over MCP as `ray_secret_scan`) is dependency-free and
**redacts every value it reports** — the point is to surface *where* a secret is,
never to echo the secret. It is high-signal and bounded: it will not find a secret
that was base64'd into a blob. For deep, entropy-based scanning across the whole
git history, drive `gitleaks` or `trufflehog` (available through the ray-siege
arsenal, `ray_arsenal_run`); this scanner is the always-available first line that
needs no install.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| Writing/leaving a secret in a file (prevention) | `/ray-cloak` (this skill) |
| Datastore privileges, exposure, encryption, credential *sourcing/rotation* policy | `/ray-vault` |
| Application secrets/identity/tenancy design | `/ray-turnstile` |
| Deep entropy/history secret scanning | `gitleaks` / `trufflehog` via `/ray-siege` arsenal |
| Leaked metadata in built documents (PDF/Office/images) | `ray_metadata_extract` (FOCA method) |

`ray-vault` audits whether the datastore's credentials are *sourced and rotated*
correctly as a design control; `ray-cloak` is the write-time guard that stops the
credential from being typed into a file at all. They meet on the rotation rule —
both say a committed credential is compromised and must be rotated.
