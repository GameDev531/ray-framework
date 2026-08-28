# Hunting Doctrine — how to find bugs, and the bar to report one

Shared by `ray-prospector` and every domain auditor. `attack-classes.md` says
*what* to hunt and *who* owns it; this file says *how* to hunt and *when* a
finding is allowed to be written. It is the generation-side complement to
`ray-arbiter`'s 13 disproof rules and `ray-gauge`'s 27 caps.

## Think like an attacker, not a reviewer

Don't check whether a defense exists — try to break it. Read the code at depth:
follow the data from entry point through validation, transformation, storage,
retrieval, and output. Bugs live in the gaps between layers.

### The twelve angles

1. **The happy path is defended — attack the sad path.** Error handlers, catch
   blocks, fallbacks, timeouts, retries, cleanup. Does a failed validation leave
   state half-modified? Does an error path fall back to *no* security?
2. **Boundaries.** Empty, max-length, null vs undefined vs missing, zero,
   negative, Unicode edge cases, first/last item, one past the maximum, exactly
   at the rate limit, the instant a token expires.
3. **What do components assume about each other?** Does storage assume the API
   validated? Does the renderer assume content was sanitized on write? Find where
   trust is implicit and test whether it is justified.
4. **Wrong order.** Call step 3 before step 1. Delete during create. Send the
   callback before the request. Replay a completed flow.
5. **Concurrency.** Two requests to one resource. Modify while reading. Two users
   claiming the same unique resource. Check-then-act that is not atomic.
6. **Two parsers disagree.** Input accepted by the schema but rejected by the DB.
   URL parsed one way by the router, another by app code. Extension vs MIME vs
   magic bytes. This is the source of smuggling, filter bypass, and SSRF-via-parser.
7. **What survives a round trip?** Stored then retrieved — same value? Does
   encoding change, escaping double up, a relative path resolve differently on
   read vs write?
8. **What does configuration control?** Missing/default config, an env var that
   overrides a control, a feature flag that disables validation, the posture
   during first-run/setup before config is complete.
9. **Follow the privilege.** For every state change: who authorized this? Trace
   back to the permission check. Is it the *right* check, on the *right*
   resource, via the *right* mechanism? Is there a parallel path that checks
   differently or not at all?
10. **Leaked context.** Errors revealing internal paths, stack traces in prod,
    timing/size/status differences that reveal existence, debug endpoints that
    survived to production.
11. **Parameters that override safe defaults.** A default is safe but a
    user-supplied parameter flips it; check the override is gated by permission.
12. **Unverified claims driving trust.** Self-declared identity, capability, or
    metadata influencing an access decision without independent verification.

Your assigned class is your focus, not a fence: if while tracing injection you
spot a broken permission check, report it. Attackers don't respect categories.

## Confirm dynamically when you can

A claim you can execute beats one you can only argue. Where the target is locally
buildable — a parser, a library, a CLI — extract the suspect code into a minimal
harness and test the hypothesis directly, or build and run it. That reproduced
result is what `ray-detonator` will demand later; capturing it now (as a
`repro_hint`) shortens the pipeline. Where confirmation needs infrastructure you
don't have (a live cache, a proxy chain, production auth), say "requires
deployment testing" and do NOT report it as confirmed.

## The bar — clear ALL of these before writing a finding

A domain auditor writes a finding to `workspace/findings/<uuid>.json` (Findings
Schema in `ray-prospector/SKILL.md`) ONLY when:

1. **Concrete attack.** You can state exact inputs / requests / an action
   sequence. "An attacker could theoretically…" is not a finding.
2. **Meaningful impact.** The attack achieves real damage — not "learn a field
   name" or "cause an error". If you need the word *potentially* or
   *theoretically*, you have not researched enough.
3. **No earlier layer already stops it.** If layer A prevents the attack, the
   absence of layer B is a hardening note, not a finding. Report defense-in-depth
   gaps separately and never inflate their severity.
4. **Attacker controls the source.** Cite the file:line where untrusted data
   enters (the ingress point) and flows to the sink. Server-controlled config,
   env vars, and compile-time constants are NOT attacker-controlled (this is the
   dominant false-positive class — see the framework-mitigated table below).
5. **Parser/runtime claims are verified.** If your exploit depends on how a
   parser or runtime interprets something, cite the spec or test it. The most
   convincing false positives come from reasoning "the parser will treat this
   as…" without checking.
6. **Not a designed behavior.** Understand the trust model first. If admins are
   fully trusted by design, admin-does-admin-things is not a finding.

If it doesn't clear the bar, either drop it or record it as an
`INFORMATIONAL`/hardening note — never pad a report with LOWs to look thorough.
Three real MEDIUMs beat ten LOWs.

## Framework-mitigated patterns — usually NOT vulnerabilities

Check the language/framework before flagging. Common false positives:

| Pattern | Why usually safe |
|---|---|
| Django/Jinja `{{ var }}`, React `{var}`, Vue `{{ var }}` | Auto-escaped by default (XSS) |
| `Model.objects.filter(id=x)`, parameterized queries, query builders | ORM/driver parameterizes (SQLi) |
| `settings.X`, `os.environ[...]`, config files, hardcoded constants | Server-controlled, not attacker-controlled |
| Rate limiting at the CDN/gateway layer | A valid architecture; not every app needs app-level limits |
| `json.loads`, `defusedxml`, parameterized templates | Safe stdlib usage without extreme paranoia is not a bug |

The exception that overrides "server-controlled": an **intrinsic** flaw — MD5/SHA1
for security, a hardcoded secret, ECB mode, a broken signature check — is VALID
even with no attacker-controlled input and even if uncalled (mirrors
`ray-arbiter` rule 08). Those go to `ray-vault`/`ray-cloak`.

## Anti-patterns that make a report useless

1. Listing every OWASP deviation as a finding — OWASP is a checklist, not a bug list.
2. Rating defense-in-depth gaps HIGH/CRITICAL.
3. Ignoring the deployment model.
4. Treating designed behavior as a bug.
5. Padding with LOWs.
6. "Potential" findings without proof.
7. Ignoring what the codebase does well — say it, it builds trust in the real findings.
8. Building exploits on unverified parser/runtime assumptions.
9. Skipping business logic and creative attacks — that is the manual auditor's whole edge.
10. Giving up at the first defense ("uses parameterized queries, so no SQLi") — check every `raw()`, dynamic identifier, and bypass path.
