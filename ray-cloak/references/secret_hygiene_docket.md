# Secret Hygiene Docket — where secrets leak, and how to not leak them

The full reference behind `ray-cloak`. §1 is the high-risk-file taxonomy (what
must never appear in each type, and the safe form). §2 is the throwaway-test
lifecycle. §3 is the pattern set the scanner uses. §4 is `.gitignore` coverage.
§5 is the rotation + git-history rule. §6 is when to escalate.

The scanner (`ray_secrets.py` / `ray_secret_scan`) automates §1, §3, §4; this
docket is the reasoning and the parts a scanner cannot enforce (the lifecycle, the
rotation call, the judgement).

## Table of Contents

- [1. High-risk files — what never appears, and the safe form](#1-high-risk-files--what-never-appears-and-the-safe-form)
- [2. The throwaway-test lifecycle](#2-the-throwaway-test-lifecycle)
- [3. The pattern set](#3-the-pattern-set)
- [4. .gitignore coverage](#4-gitignore-coverage)
- [5. If a secret is found: rotate, don't just delete](#5-if-a-secret-is-found-rotate-dont-just-delete)
- [6. When to escalate to a deep scanner](#6-when-to-escalate-to-a-deep-scanner)

______________________________________________________________________

## 1. High-risk files — what never appears, and the safe form

| File type | What must NEVER be literal in it | The safe form |
|---|---|---|
| **`.env`, `.env.*`** | any real value | Never commit it. Ensure `.gitignore` covers `.env*`. Commit only a `.env.example` with **names**, no values (`DB_URL=`). |
| **Tests** (`test_*`, `*.test.*`, `*.spec.*`, temp scripts) | real credentials, real connection strings, real user data | Fake fixtures/mocks. If a temp script needs a credential, it is disposable — see §2 (create → run → delete → confirm). |
| **JSON / YAML / TOML** (`config.json`, `firebase.json`, `serviceAccount*.json`, `credentials.json`, `docker-compose.yml`, `settings.yml`) | any key, token, password, or connection string | Reference an env var; keep the real file out of the repo and in `.gitignore`. |
| **Markdown** (`README`, `TODO`, `NOTES`, `SETUP`, "step-by-step fix" docs) | a connection string, a password, an admin/DB URL — and **especially never creds + the project URL together** | Explanations use placeholders (`<YOUR_KEY>`). This is the highest-value leak: see the real-world case in `SKILL.md`. |
| **Source code** | hardcoded secrets, and dangerous fallbacks like `process.env.DB_URL \|\| "postgres://user:pass@host"` | Env-var read with **no** secret default — fail closed if the var is missing. |
| **Logs / debug** | `console.log(process.env)`, logging headers/tokens/`Authorization` | Log names or booleans ("DB_URL present: true"), never values. |
| **Dockerfile / CI** (`.github/workflows/*`, `.gitlab-ci.yml`) | hardcoded secrets in `ENV`/`ARG`/`run:` steps | The CI's secret manager (`${{ secrets.X }}`), injected at runtime. |
| **SQL dumps / seeds / migrations** | real passwords, real user data | Synthetic data; parameterized/placeholder credentials. |
| **Notebooks (`.ipynb`)** | secrets in cells **and in saved outputs** | Env vars in cells; clear all outputs before saving. |

The scanner treats a secret in a **Markdown file that also contains a URL** as
CRITICAL, and a secret in a **test file** as HIGH (tests are meant to be
throwaway, so a committed one is a double failure). An `.env.example` /
`*.example` file is expected to hold placeholders and is not flagged for them.

______________________________________________________________________

## 2. The throwaway-test lifecycle

Assistants routinely write a small script to exercise a function, then leave it in
the tree — sometimes with a real credential in it. The rule:

1. **Create** the temp script (name it obviously disposable — `tmp_`, `scratch_`,
   `debug_` — the scanner flags these so they can't hide).
2. **Run** it to verify the function.
3. **Delete** it completely — `rm` the file.
4. **Confirm** the deletion out loud: list the file and show it is gone (`ls`
   returns "No such file"), so there is proof it did not get committed.

A temporary test is finished only when it no longer exists. If it needed a
credential to run, deleting the file is also what removes that credential from the
tree — do not skip step 4.

______________________________________________________________________

## 3. The pattern set

The scanner greps every text file for these (values are redacted in output). When
scanning by hand where the tool is unavailable, these are the patterns to check:

- **Connection strings:** `postgres://`, `postgresql://`, `mysql://`,
  `mongodb://`, `mongodb+srv://`, `redis://`, `rediss://`, `amqp://` — CRITICAL
  when they carry `user:pass@`.
- **Cloud / provider keys:** `AKIA…` (AWS), `AIza…` (Google), `ghp_`/`gho_`/
  `github_pat_` (GitHub), `xox[baprs]-` (Slack), `sk_live_`/`pk_live_` (Stripe),
  `sk-…` (OpenAI-style), Slack webhook `hooks.slack.com/services/…`.
- **Tokens:** `Bearer <token>`, JWT `eyJ….eyJ….<sig>`.
- **Private keys:** `-----BEGIN … PRIVATE KEY-----`.
- **Generic assignments:** `password=`, `passwd`, `secret`, `api_key`/`apikey`,
  `access_key`, `secret_key`, `auth_token`, `client_secret`, `db_url`,
  `connection_string` set to a real-looking value.
- **Dangerous fallbacks:** an env-var read `|| "…"` / `, "…"` with a real default.

A match is ignored (not a leak) when the value is an env reference
(`process.env`, `os.environ`, `${…}`, `getenv`, `secretKeyRef`), a placeholder
(`<…>`, `{{…}}`, `CHANGEME`, `your_…`, `example.com`, `xxx`, `***`), or empty.

______________________________________________________________________

## 4. .gitignore coverage

Prevention beats detection: if a secret file can never be *staged*, it can never
be pushed. Confirm `.gitignore` covers, at minimum:

- `.env*` (but allow `!.env.example`),
- `*.pem`, `*.key`,
- `credentials*`, `serviceAccount*` (and any provider-specific credential file).

The scanner reports which of these are missing (and flags the absence of a
`.gitignore` entirely). Add them before the first commit of a project.

______________________________________________________________________

## 5. If a secret is found: rotate, don't just delete

A committed secret is a **compromised** secret. Removing it from the file, or even
rewriting git history, does not un-leak it — anyone who cloned or mirrored the repo
(and automated scrapers watch public pushes within seconds) already has it.

So, in order:

1. **Tell the user** the file and line (never the value).
2. **Replace** the literal with an env-var read.
3. **Rotate** the credential immediately — issue a new key/password, revoke the
   old one. State this as required, not optional.
4. **Then** clean history if desired (housekeeping).

Never repeat the secret's value in your response — that leaks it again, into the
transcript.

______________________________________________________________________

## 6. When to escalate to a deep scanner

`ray_secrets.py` is the always-available, zero-install first line. It is
high-signal and bounded — it matches known shapes in the current tree. Escalate
when you need more:

- **Whole git history** (a secret added then removed in an old commit) → drive
  `gitleaks` or `trufflehog` via the ray-siege arsenal
  (`ray_arsenal_run(tool="gitleaks", target="<repo>")`).
- **Entropy-based detection** of high-randomness strings that match no known
  prefix → `trufflehog`'s entropy mode.
- **Built-document metadata** (a secret in a PDF/Office/image artifact, not in
  source) → `ray_metadata_extract` (the FOCA method).

The first-line scanner and the deep scanners are complementary: run the bundled
one every task (it costs nothing), reach for the heavy ones when the surface is
the whole history or the risk is high.
