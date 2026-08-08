# Injection Docket — Class Procedures

One section per vulnerability class. Each carries: the sink patterns to grep,
the safe pattern, the false-positive traps that decide most disputes, and the
reproduction hint to hand `/ray-detonator`.

Grep patterns are starting points, not membership decisions. Read the
surrounding code before recording a verdict, and record `UNKNOWN` rather than
guessing.

## Table of Contents

- [SQLI — SQL and NoSQL Injection](#sqli--sql-and-nosql-injection)
- [CMDI — Command Injection](#cmdi--command-injection)
- [XSS — Cross-Site Scripting](#xss--cross-site-scripting)
- [SSTI — Server-Side Template Injection](#ssti--server-side-template-injection)
- [CSRF — Cross-Site Request Forgery](#csrf--cross-site-request-forgery)
- [SSRF — Server-Side Request Forgery](#ssrf--server-side-request-forgery)
- [DESER — Insecure Deserialization](#deser--insecure-deserialization)
- [XXE — XML External Entities](#xxe--xml-external-entities)
- [TRAV — Path Traversal](#trav--path-traversal)
- [UPLOAD — Unrestricted File Upload](#upload--unrestricted-file-upload)
- [REDIR — Open Redirect](#redir--open-redirect)
- [PROTO — Prototype Pollution](#proto--prototype-pollution)
- [TIMING — Non-Constant-Time Secret Comparison](#timing--non-constant-time-secret-comparison)
- [REDOS — Catastrophic Regular Expressions](#redos--catastrophic-regular-expressions)
- [CSVI — Formula Injection In Exports](#csvi--formula-injection-in-exports)
- [DEPS — Vulnerable And Malicious Dependencies](#deps--vulnerable-and-malicious-dependencies)

______________________________________________________________________

## SQLI — SQL and NoSQL Injection

**CWE-89** (SQL), **CWE-943** (NoSQL/data-query). OWASP A05:2025 Injection.

### Grep

```
db\.query\(|execute\(|executemany\(|cursor\.execute
\.raw\(|sequelize\.query|knex\.raw|createQueryBuilder|literal\(
f"SELECT|f'SELECT|"SELECT .*" \+|`SELECT.*\$\{|\.format\(.*SELECT
ORDER BY \$\{|ORDER BY '\s*\+|sort.*req\.(query|body)
\$where|\$expr|\$function|mapReduce|\$regex.*req\.
```

### Safe pattern

```js
db.query('SELECT * FROM users WHERE email = $1', [email]);          // placeholders
```

```python
cur.execute("SELECT * FROM users WHERE email = %s", (email,))       # NOT %-format
```

For identifiers that cannot be parameterized (table, column, `ORDER BY`
direction), the safe pattern is an **allowlist**:

```js
const SORTABLE = { created: 'created_at', name: 'display_name' };
const col = SORTABLE[req.query.sort] ?? 'created_at';               // never the raw value
```

### False-positive traps

- A query built by concatenation from **constants only** is not injectable —
  check every interpolated fragment's provenance before reporting.
- ORM query builders parameterize by default; the defect is the escape hatch
  (`.raw`, `literal`, `whereRaw`, `Sequelize.literal`, `text()`) or a builder
  fed a pre-built string.
- A "parameterized" call that concatenates first and passes the finished string
  as the only argument is not parameterized. Read the argument, not the API name.
- Numeric coercion (`parseInt`) is a real, if fragile, neutralizer — record it
  as NEUTRALIZED with a note rather than as a finding, unless the coercion can
  be bypassed (e.g. `parseInt` on an array, or a value used before coercion).
- NoSQL: an operator-injection defect needs the input to reach the query **as an
  object**. If the framework coerces the value to a string (or the code calls
  `String(...)`), operator injection does not apply — but `$where`/`$expr` with
  any interpolation still does.

### Reproduction hint for `/ray-detonator`

Name the endpoint, the parameter, and an observable that distinguishes success
from noise: a boolean-differential (`' OR '1'='1` vs `' OR '1'='2` returning
different row counts), an error-based signal, or a timing differential
(`pg_sleep`, `SLEEP`, `WAITFOR DELAY`). Prefer a differential over an error —
errors may be swallowed.

______________________________________________________________________

## CMDI — Command Injection

**CWE-78**. OWASP A05:2025.

### Grep

```
child_process|exec\(|execSync|spawn\(.*shell|\bsh -c\b
os\.system|subprocess\.(run|call|Popen).*shell\s*=\s*True
Runtime\.getRuntime\(\)\.exec|ProcessBuilder
`.*\$\{|popen\(|passthru|shell_exec|system\(
ffmpeg|imagemagick|convert |gs |pdftk|wkhtmltopdf|git .*\+
```

### Safe pattern

Pass an argument vector and no shell:

```js
execFile('/usr/bin/convert', [inputPath, '-resize', '100x100', outputPath]);
```

```python
subprocess.run(["git", "clone", url], shell=False, check=True)
```

Plus: validate the input against an allowlist where it selects a mode or a
filename, and use `--` to end option parsing where the tool supports it.

### False-positive traps

- `spawn(cmd, args)` **without** a shell is safe for metacharacters, but an
  input-controlled first argument still lets the caller choose the binary, and
  an input-controlled argument can still be an option (`--upload-pack=`,
  `-o ProxyCommand=`) — argument injection is a real finding even without a
  shell.
- Media and document toolchains are the common real path: filenames flowing
  into ImageMagick, ffmpeg, ghostscript, or LaTeX.
- A constant command with a constant argument list is not a finding no matter
  how alarming the API name looks.

### Reproduction hint

A benign, observable side effect only: writing a file to a sandbox temp path, or
a measurable sleep. Never a network callback, never a destructive command.

______________________________________________________________________

## XSS — Cross-Site Scripting

**CWE-79**. OWASP A05:2025. Note `ray-gauge`'s `strict_xss` rule caps this class
aggressively — default MEDIUM, HIGH only for stored XSS with zero-click
execution in a critical admin context. Score accordingly rather than fighting
the cap downstream.

### Grep

```
dangerouslySetInnerHTML|v-html|\[innerHTML\]|bypassSecurityTrust
innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|document\.write
\|\s*safe|\{\{\{|mark_safe|raw\(|html_safe|HtmlString|@Html\.Raw
eval\(|new Function\(|setTimeout\(\s*['"`]|srcdoc=
location\s*=|location\.href\s*=|window\.open\(
```

### Context table (this is what decides most XSS disputes)

| Where the value lands | Correct neutralization | HTML-escaping alone is |
|---|---|---|
| HTML text node | HTML entity encoding | sufficient |
| HTML attribute (quoted) | HTML entity encoding, attribute always quoted | sufficient |
| HTML attribute (unquoted) | encoding + quoting | insufficient |
| `href` / `src` / `action` | scheme allowlist (`http`, `https`, relative) | insufficient — `javascript:` and `data:` survive escaping |
| Inline `<script>` block | JSON-encode with `<`/`>`/`&` escaped, or do not inline at all | insufficient |
| Event handler attribute (`onclick`) | do not build these from input | insufficient |
| CSS / `style` | strict allowlist | insufficient |
| `srcdoc` / `sandbox`-less iframe | do not build from input | insufficient |

### Safe pattern

Let the framework interpolate (React `{value}`, Vue `{{ value }}`, Django/Jinja
autoescaping, Rails `<%= %>`). When user HTML genuinely must render, sanitize
with a maintained library configured for the context:

```js
element.innerHTML = DOMPurify.sanitize(userHtml);   // and keep DOMPurify current
```

### False-positive traps

- Framework interpolation is safe; only the explicit opt-outs are sinks.
- A sanitizer applied **and then** the result modified, decoded, or concatenated
  is not protection.
- Server-side sanitization followed by client-side re-parsing (mutation XSS) can
  reintroduce the bug — note it rather than asserting it.
- A CSP does not make an XSS a non-finding; it lowers exploitability. Say so in
  the description and let `ray-gauge` handle the arithmetic.
- Markdown renderers with raw-HTML passthrough enabled are sinks; check the
  renderer's options, not its reputation.

### Reproduction hint

Give the exact injection point, the context, and a non-destructive proof
payload that produces an observable DOM effect in a headless browser. Note
whether it is reflected, stored, or DOM-based, and whether authentication or a
victim interaction is needed.

______________________________________________________________________

## SSTI — Server-Side Template Injection

**CWE-1336**. Frequently RCE, so worth separating from XSS.

### Grep

```
Template\(|render_template_string|Jinja2|new Handlebars|compile\(
Twig|Velocity|Freemarker|Thymeleaf|ejs\.render\(|pug\.compile\(
render\(.*req\.(body|query|params)
```

### Rule

Input may be a template **context value**; it must never be part of the template
**source**. Any code that concatenates request data into a template string, or
lets a user supply a template (email templates, report templates, "custom
formats"), is a finding — the impact is usually RCE, not XSS.

### Safe pattern

Precompiled templates, values passed as context. Where users truly need
templating, use a sandboxed, logic-less engine with no object access, and treat
it as an untrusted execution boundary.

______________________________________________________________________

## CSRF — Cross-Site Request Forgery

**CWE-352**. Applies **only** where the browser attaches credentials
automatically (cookies, HTTP auth, client certificates).

### Applicability check (run this first)

| App shape | Vulnerable to classic CSRF? |
|---|---|
| Cookie session, form or JSON POST | Yes |
| `Authorization: Bearer` set by JavaScript | No — do not report |
| Cookie session + `SameSite=Strict/Lax` | Reduced, not eliminated: `Lax` still allows top-level `GET` navigation, so a state-changing `GET` is still reachable; sibling-subdomain attacks remain possible |
| Mobile client with a token header | No |

### Grep

```
csrf|xsrf|csurf|CsrfViewMiddleware|@csrf_exempt|SameSite
app\.(post|put|patch|delete)\(|@PostMapping|@app\.route.*methods
```

### What to check

1. A token exists **and is verified** — a token rendered into a form but never
   compared server-side is a common, invisible failure.
2. The token is bound to the session and unpredictable.
3. Exemptions (`@csrf_exempt`, `csurf` skipped on a route) are deliberate and
   justified; enumerate every one.
4. No state change on `GET`/`HEAD` — that bypasses every token scheme.
5. `Origin`/`Referer` checked on sensitive endpoints as a second layer.
6. JSON endpoints: relying on "browsers cannot send JSON cross-origin" is not a
   control if the endpoint also accepts form encoding.

### Reproduction hint

A minimal auto-submitting HTML page hosted in the sandbox that triggers the
state change while a session cookie is present, and the state assertion that
proves it fired.

______________________________________________________________________

## SSRF — Server-Side Request Forgery

**CWE-918**. In OWASP Top 10 2025 this rolls up under **A01 Broken Access
Control**; keep the CWE precise regardless.

### Grep

```
axios|fetch\(|request\(|got\(|http\.get|httpx|requests\.(get|post)
urllib|curl_exec|HttpClient|WebClient|RestTemplate|net/http
webhook|callback_url|image_url|avatar_url|import_url|fetch_url|preview
proxy|redirect_to.*http|url=|link=|src=
```

### Where it hides

Webhook registration, URL import ("import from URL", "fetch my avatar"), link
preview/unfurling, PDF and screenshot generators (headless browsers are
notorious — they follow redirects and can read `file://`), image processors,
XML parsers with external entities, SSO metadata fetchers, and any
"proxy this request" endpoint.

### Safe pattern

1. Scheme allowlist (`https` only; explicitly reject `file`, `gopher`, `dict`,
   `ftp`, and internal schemes).
2. Domain allowlist where the use case permits one.
3. Resolve DNS, reject private, loopback, link-local, and reserved ranges
   (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `::1`, `fc00::/7`,
   `fe80::/10`, `0.0.0.0/8`), and **connect to the validated IP** — validating a
   hostname and then handing the URL to an HTTP client re-resolves it and
   reopens DNS rebinding.
4. Disable or bound redirects, and re-validate every hop.
5. Egress firewall, and IMDSv2 required on AWS so a bare `GET` to
   `169.254.169.254` cannot mint credentials.
6. Short timeouts and a response size cap.

### False-positive traps

- A URL from configuration or from a fixed provider list is not a source.
- A regex or `startsWith('https://')` check is not a control — say so explicitly
  in the finding; that is precisely the pattern teams believe is sufficient.
- Blind SSRF (no response returned) is still a finding: it reaches internal
  services and can trigger state changes.

### Reproduction hint

Point the sandboxed target at a local listener inside the sandbox and assert the
connection. Never at a third-party host, never at a real metadata endpoint of a
system you do not own.

______________________________________________________________________

## DESER — Insecure Deserialization

**CWE-502**. OWASP A08:2025 Software and Data Integrity Failures.

### Grep

```
pickle\.loads|cPickle|dill\.loads|joblib\.load|torch\.load|numpy\.load.*allow_pickle
yaml\.load\((?!.*SafeLoader)|yaml\.unsafe_load
unserialize\(|ObjectInputStream|readObject|XMLDecoder|BinaryFormatter
Marshal\.load|ActiveSupport::MessageVerifier|node-serialize|funcster
```

### Rule

Any executable serialization format reached by request data is a HIGH finding on
sight — no exploit chain needs to be demonstrated for the class to be real,
though naming a gadget source strengthens it.

### Safe pattern

JSON (or another data-only format) plus schema validation (zod, pydantic, JSON
Schema). For ML artifacts, prefer safetensors or a format without code
execution; where `torch.load` is unavoidable, load only artifacts whose
integrity you verify.

### Traps

- `JSON.parse` itself is safe; the danger is what happens to the parsed object
  (see PROTO).
- `yaml.safe_load` is safe; `yaml.load` with a `SafeLoader` is safe; bare
  `yaml.load` is not.
- Signed serialized payloads (`MessageVerifier`, signed cookies) are only as
  safe as the signing key — a leaked or default key turns them into a
  deserialization sink; cross-reference `/ray-turnstile` `SEC-02`.

### Gadget-chain catalog (to strengthen a finding, not required for the class)

The class is HIGH on the sink alone, but naming a plausible **gadget chain** — the
sequence of existing classes whose side effects, triggered during
deserialization, reach code execution — turns a "this is dangerous" finding into
a reproducible one for `/ray-detonator`. Note which chain the target's dependency
set makes available; do not fabricate a chain you cannot ground in a present
library.

| Ecosystem | Sink | Common gadget sources (check the lockfile for presence/version) |
|---|---|---|
| Java | `ObjectInputStream.readObject` | `ysoserial` families: Commons-Collections (`InvokerTransformer`), Commons-Beanutils, Spring, Groovy, Rome, Hibernate; JNDI/RMI/LDAP `LDAPRefServer` for `log4shell`-style lookups |
| Python | `pickle.loads`, `__reduce__` | `os.system`/`subprocess` via `__reduce__`; `pandas`/`numpy` `allow_pickle`; `PyYAML` `!!python/object/apply`; `jsonpickle` |
| PHP | `unserialize` | POP chains via `__wakeup`/`__destruct`/`__toString`; framework chains (Laravel, Symfony, Monolog, Guzzle); `phpggc` catalogs them |
| .NET | `BinaryFormatter`, `LosFormatter`, `Json.NET` `TypeNameHandling` | `TypeConfuseDelegate`, `ObjectDataProvider`, `WindowsIdentity`; `ysoserial.net` families |
| Ruby | `Marshal.load`, `YAML.load` | Universal RCE gadget via `Gem::*`/`Psych`; Rails secret-key-based cookie chains |
| Node | `node-serialize`, `funcster`, `serialize-javascript` misuse | IIFE `_$$ND_FUNC$$_` immediate-invoke; prototype-pollution → gadget (see `PROTO`) |

**How to demonstrate for `/ray-detonator`:** name the sink, confirm a gadget
source is in the resolved dependency tree (grep the lockfile), and describe the
serialized payload shape — the reproduction builds the gadget with the matching
tool (`ysoserial`/`phpggc`/`ysoserial.net`) in the sandbox and observes the benign
marker command. Never build or run a weaponized gadget outside the sandbox.

______________________________________________________________________

## XXE — XML External Entities

**CWE-611**.

### Grep

```
DocumentBuilderFactory|SAXParser|XMLReader|xml\.etree|lxml\.etree
libxml_disable_entity_loader|simplexml_load|XmlDocument|XmlTextReader
resolveEntity|DTD|DOCTYPE
```

### Safe pattern

Disable DTDs and external entities explicitly, rather than relying on defaults:
`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`,
`XMLParser(resolve_entities=False)`, `defusedxml`, or
`XmlReaderSettings { DtdProcessing = Prohibited }`. Modern runtimes often
default safely — verify the version and the configuration rather than assuming.

### Where it hides

SOAP endpoints, SAML assertions, XML import features, SVG upload processing,
Office document parsing, RSS/sitemap ingestion.

______________________________________________________________________

## TRAV — Path Traversal

**CWE-22**, plus **CWE-23**/**CWE-36**.

### Grep

```
path\.join\(.*req\.|os\.path\.join\(.*request|Paths\.get\(.*param
readFile|createReadStream|sendFile|res\.download|send_file|serve_static
open\(.*request|fopen|File\(|new FileInputStream
zipfile|tarfile|extractall|unzip|AdmZip|extract\(
```

### Safe pattern

```js
const base = path.resolve('/srv/uploads');
const full = path.resolve(base, userInput);
if (!full.startsWith(base + path.sep)) throw new Error('invalid path');
// better still: never accept a filename — map an opaque id to a stored path
```

For archives, validate every entry name **before** writing (zip slip), reject
absolute paths and `..` segments, reject symlink entries, and cap total
extracted size and entry count (zip bomb).

### Traps

- Checking the raw input for `..` before decoding misses `%2e%2e%2f`, double
  encoding, and UTF-8 overlongs. Validate after full decoding and resolution.
- `path.join` does not prevent traversal; `path.resolve` + prefix check does.
- On systems with symlinks, the prefix check must be against the resolved real
  path.
- An absolute path supplied by the user replaces the base entirely in most
  join implementations.

______________________________________________________________________

## UPLOAD — Unrestricted File Upload

**CWE-434**.

### Checklist

| Control | Failing shape |
|---|---|
| Type validated by content (magic bytes / sniffing library) | Extension-only or client `Content-Type` checks |
| Extension allowlist (not denylist) | A denylist of `.php`, `.jsp`… — always incomplete (`.phtml`, `.php5`, `.cshtml`) |
| Stored under a generated random name | Original filename preserved → traversal, overwrite, and null-byte tricks |
| Stored outside the webroot / in object storage | Written into a directory the web server will execute or serve as active content |
| Served from a separate origin, with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` | Served from the app origin → stored XSS via HTML or SVG |
| SVG treated as active content (rejected, rasterized, or strictly sanitized) | SVG accepted as "an image" — it carries scripts |
| Size and count limits | Unbounded upload → disk exhaustion |
| Image processing sandboxed and libraries current | ImageMagick/ffmpeg invoked on untrusted files with a permissive policy |
| Archives expanded with the TRAV protections above | `extractall` on an uploaded zip |
| Malware scanning where the file is shared with other users | Absent in a file-sharing feature |

### Reproduction hint

Upload the smallest artifact that proves the class (an HTML file that the app
then serves inline with `Content-Type: text/html`), and assert the served
response headers — not a live payload.

______________________________________________________________________

## REDIR — Open Redirect

**CWE-601**. Usually LOW alone; it becomes serious when chained with an OAuth
flow (`redirect_uri` theft) or used to lend a phishing page your domain.

### Grep

```
res\.redirect\(|redirect\(|sendRedirect|Location:|HttpResponseRedirect
next=|returnUrl=|redirect_uri=|continue=|callback=|url=|dest=
```

### Safe pattern

Accept **relative paths only** (reject anything containing `//`, `\`, a scheme,
or a leading `//`), or match against an exact allowlist of absolute URLs. Note
the classic bypasses when judging a control: `//evil.com`, `https:/\evil.com`,
`https://trusted.com@evil.com`, `https://trusted.com.evil.com`, and
backslash/whitespace variants that browsers normalize differently from parsers.

______________________________________________________________________

## PROTO — Prototype Pollution

**CWE-1321**. JavaScript/TypeScript only.

### Grep

```
merge\(|deepMerge|extend\(|Object\.assign\(.*req\.|defaultsDeep
lodash|_\.merge|deepmerge|qs\.parse|query-string|set\(.*path
__proto__|constructor\.prototype|\[key\]\s*=
```

### Safe pattern

Reject `__proto__`, `constructor`, and `prototype` as keys; validate the input
with a schema before merging; use `Object.create(null)` for map-like objects;
use `Map` instead of an object where keys are user-controlled; keep merge
libraries current.

### Traps

- A merge over a **schema-validated** object with a closed key set is not
  exploitable — check for `.strict()`/`additionalProperties: false`.
- Impact ranges from a changed default flag to RCE depending on what the polluted
  property reaches. State the concrete gadget you found, or describe the impact
  as "depends on downstream property reads" rather than asserting RCE.
- Server-side pollution in a long-lived process persists across requests, which
  makes it a cross-user defect, not a per-request one — say so.

______________________________________________________________________

## TIMING — Non-Constant-Time Secret Comparison

**CWE-208**.

### Grep

```
===\s*token|==\s*signature|!=\s*secret|\.equals\(.*token
apiKey\s*===|hmac\s*==|digest\(\)\s*===|compare.*password
```

### Safe pattern

```js
crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));   // equal lengths required
```

```python
hmac.compare_digest(a, b)
```

### Traps

- Comparing **hashes** of secrets is far less exploitable than comparing the
  secrets themselves, because the attacker cannot steer the hash — note the
  distinction and score it lower.
- Over a noisy network the signal may be impractical; the finding is still valid
  as defense in depth, but do not claim a practical remote attack you have not
  measured. This is a LOW–MEDIUM class in most deployments.
- `timingSafeEqual` throws on unequal lengths — a naive wrapper that returns
  early on a length mismatch leaks length. Note it, do not overstate it.

______________________________________________________________________

## REDOS — Catastrophic Regular Expressions

**CWE-1333**. Also audited by `/ray-seam` as an availability defect.

### Grep

```
new RegExp\(|re\.compile\(|\.match\(|\.test\(|Pattern\.compile
\(\w\+\)\+|\(\w\*\)\*|\(\.\*\)\+|\(a\|aa\)\+
validator|email.*regex|sanitize.*regex
```

### Rule

Nested quantifiers over an overlapping alternation (`(a+)+`, `(a|aa)+`,
`(\s*\w+)*`) applied to input the caller controls, with no length cap, is a
finding. So is a **user-supplied** regex compiled by the server.

### Safe pattern

Cap input length before matching; avoid nested quantifiers; use a linear-time
engine (RE2, `re2` bindings, Rust `regex`) for input-facing patterns; add a
match timeout where the runtime supports one.

______________________________________________________________________

## CSVI — Formula Injection In Exports

**CWE-1236**.

Any export path (CSV, XLSX) that writes user-controlled text into a cell is a
sink: a cell beginning with `=`, `+`, `-`, `@`, tab, or carriage return is
interpreted as a formula by spreadsheet applications, and can exfiltrate data or
launch commands on the *recipient's* machine.

**Safe pattern:** prefix such cells with a single quote, or reject/escape the
leading character; prefer a real XLSX writer that marks the cell as text.

Grep: `csv\.writer|createObjectCsvWriter|to_csv|StringIO.*csv|xlsx|exceljs`.

______________________________________________________________________

## DEPS — Vulnerable And Malicious Dependencies

**CWE-1395** (dependency on vulnerable third-party component). OWASP **A03:2025
Software Supply Chain Failures**.

### Assessable without network access

| Check | Failing shape |
|---|---|
| Lockfile committed | No lockfile, or one in `.gitignore` |
| Versions pinned | `^`, `~`, `*`, `latest` on runtime dependencies |
| No direct git/URL dependencies | `git+https://…` or a tarball URL, unpinned to a commit |
| No suspicious install scripts | `postinstall` running a network fetch or a shell script |
| Typosquat check | Package names one edit away from a popular package; scoped-package confusion |
| Update mechanism configured | No Dependabot/Renovate config |
| CI audit step | No `npm audit` / `pip-audit` / `govulncheck` / `cargo audit` in the pipeline |
| Registry pinning | No `.npmrc`/`pip.conf` restricting the registry; dependency-confusion exposure for internal package names |
| Vendored copies | A checked-in copy of a library, frozen at an old version, invisible to every scanner |

### Severity rule

Reachability decides. A CVE in a package whose vulnerable code path the
application never invokes is LOW by `ray-gauge`'s `third_party_reachability`
rule. Trace the call path, or state plainly that you did not — never assert
reachability you have not checked, and never invent CVE identifiers, CVSS
scores, or advisory text.
