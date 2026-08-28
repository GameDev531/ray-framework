# Crucible Docket — crucible

Vulnerable→safe patterns for `ray-crucible`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## SQL / NoSQL injection — CWE-89 / CWE-943 · A03:2021
- **Broken:** string-built queries (`"... WHERE id=" + x`, f-strings, `sql.raw`,
  dynamic identifiers/ORDER BY, `$where`/`$regex` from user input, `.raw()` escape
  hatches).
- **Safe:** parameterized queries / bound placeholders; ORM query methods (not
  `.raw`); allow-listed column/table names; typed IDs.
- **Push:** every `raw`, dynamic identifier, search/FTS path, and any code path that
  bypasses the query builder.

## Cross-site scripting — CWE-79 · A03:2021
- **Broken:** `innerHTML`/`dangerouslySetInnerHTML`/`v-html` with user data,
  unescaped template interpolation, reflecting input into a `<script>` or attribute
  context, `document.write`, building DOM from `location`/`postMessage`.
- **Safe:** framework auto-escaping left intact, context-aware encoding, a vetted
  sanitizer (DOMPurify) for rich text, CSP as defense-in-depth.
- Reflected vs stored vs DOM — trace which; stored XSS firing for all users is the
  severe one.

## Command injection — CWE-78 · A03:2021
- **Broken:** `os.system`, `exec`/`shell=True`, backticks, `child_process.exec`,
  concatenated shell strings with user data.
- **Safe:** argument-vector APIs (`execve`/`spawn` with an args array, `shell=False`),
  no shell interpretation, allow-listed commands.

## SSTI / template injection — CWE-1336 · A03:2021
- **Broken:** user input concatenated into a template *source* (`render_template_string(user)`),
  Jinja/Twig/Freemarker/EL with attacker-controlled template text.
- **Safe:** user data passed as *data* to a fixed template; logic-less templates.

## XXE — CWE-611 · A05:2021
- **Broken:** XML parser with external entities / DTD enabled on untrusted XML.
- **Safe:** entities and DOCTYPE disabled (`defusedxml`, `FEATURE_SECURE_PROCESSING`).

## Unsafe deserialization — CWE-502 · A08:2021
- **Broken:** `pickle`/`yaml.load`/`Marshal`/native Java/PHP deserialization of
  attacker bytes; type metadata honored from the wire.
- **Safe:** data-only formats (JSON), `yaml.safe_load`, schema-validated,
  signed+verified payloads.

## SSRF — CWE-918 · A10:2021
- **Broken:** server fetches a user-supplied URL (webhooks, previews, importers,
  image proxies) without allow-listing; validation before a redirect; DNS rebinding.
- **Safe:** allow-list of hosts/schemes, block link-local/metadata (169.254.169.254),
  re-validate after each redirect, no raw user URL to the fetcher.

## Path traversal — CWE-22 · A01:2021
- **Broken:** user filename joined to a base dir without canonicalization;
  `../`, encoded traversal, null bytes, symlinks.
- **Safe:** canonicalize then assert the resolved path is within the base; allow-list
  names; never trust the client-supplied path.

## Prototype pollution — CWE-1321
- **Broken:** recursive merge/`set`/`assign` of user JSON touching `__proto__`,
  `constructor`, `prototype`.
- **Safe:** block those keys, null-proto objects, `Map`, schema validation.

## HTTP request smuggling / HPP · CWE-444
- **Broken:** custom HTTP parsing where two parsers disagree on Content-Length vs
  Transfer-Encoding; duplicate params resolved differently by layers.
- **Safe:** one authoritative parser, reject ambiguous framing, canonical param
  handling. (Protocol-layer targets → ray-seam / ray-sentry.)

## What is NOT a finding here

- Parameterized queries / ORM filters without extra "validation" (see doctrine's
  framework-mitigated table).
- Auto-escaped template output where the framework's escaping is intact.
- A sink fed exclusively by server config, env vars, or compile-time constants.
- "Missing input validation" where a correct downstream transformation already
  neutralizes the value for its sink — that is defense-in-depth, not injection.
