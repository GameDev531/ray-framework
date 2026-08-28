# Attack Classes — Ray master catalog & router

This is the catalog `ray-prospector` and every domain auditor consult to decide
**what to hunt for** and **which skill owns it**. Ray's pipeline was strong at
*validating* findings and weak at *generating* them; this file, plus each domain
skill's docket, is the generation half.

Pick classes by what the target actually is (from `ray-perimeter`'s threat model
and `ray-prism`'s digests). Not every class applies to every codebase. For a
class a dedicated domain skill owns, `ray-prospector` may raise a lightweight
pointer and let that skill go deep; `ray-prospector` itself is the generalist
floor that must never skip a file just because "a domain skill will get it".

## Routing table — class → owning skill

| Concern | Owner | Classes |
|---|---|---|
| Untrusted input reaching a sink | **ray-crucible** | SQL/NoSQL injection, XSS (reflected/stored/DOM), command injection, SSTI, XXE, unsafe deserialization, SSRF, path traversal, prototype pollution, HTTP request smuggling, type juggling, HTTP parameter pollution, LDAP/XPath injection |
| Identity & access | **ray-turnstile** | Broken auth, credential storage, session fixation/rotation, JWT/OAuth/OIDC/SAML flaws, MFA bypass, password reset/invite abuse, IDOR/BOLA, BFLA, tenant isolation, OWASP API Top 10 |
| Client/server trust boundary | **ray-seam** | Missing/weak input validation, mass assignment, CORS misconfig, cache poisoning, host-header injection, clickjacking, weak/missing CSP, open redirect |
| Abuse & observability | **ray-sentry** | Missing rate limiting, resource-exhaustion abuse, exposed internal/debug endpoints, unsigned webhooks, shadow/undocumented APIs, verbose errors |
| Datastore exfiltration | **ray-vault** | Over-broad DB privileges, unreachable-from-app-but-exposed data, missing encryption at rest, crypto-primitive misuse (ECB, static IV, weak KDF, MD5/SHA1, nonce reuse), PQC readiness |
| Deployed architecture | **ray-citadel** | Flat network / missing isolation, secrets management at scale, service-to-service trust, lateral movement |
| Privacy & web surface | **ray-custodian** | TLS/HSTS/headers, cookie flags (HttpOnly/Secure/SameSite), consent, data retention, data-subject rights, PII in logs/URLs |
| Native/unsafe memory | **ray-marrow** | OOB read/write, use-after-free, double-free, integer overflow/underflow, type confusion, uninitialized memory, FFI boundary, format string |
| The app's own AI feature | **ray-oracle** | Prompt injection (direct/indirect), MCP tool poisoning, insecure output handling, excessive agency, model/data extraction, OWASP LLM Top 10 2025, MITRE ATLAS |
| Dependencies | **ray-manifest** | Known-vulnerable versions (CVEs), SBOM (CycloneDX), typosquats, unpinned/rug-pullable deps, malicious postinstall |
| IaC / cloud / containers | **ray-terrain** | Terraform/CloudFormation/K8s/Docker misconfig, over-permissive IAM, public buckets, image hardening, privileged containers |
| Maintenance over time | **ray-steward** | Dependency EOL, patch cadence, backup+restore integrity, DR readiness, key/secret rotation |

**Generalist floor (`ray-prospector`):** business-logic flaws, state-machine
violations, race conditions with business impact, chained attacks across
components, and anything none of the above owns. Business logic is where scanners
are blind and manual audit earns its keep — never skip it.

## The video-guide's seven doors — where each lives

The concepts most non-experts (and the linked walkthrough) start from, mapped so
none is dropped:

| Door | Owner(s) |
|---|---|
| Autenticação (login) | ray-turnstile |
| Autorização (admin vs comum, rota protegida) | ray-turnstile (BFLA/BOLA) |
| Validação de input / SQL injection | ray-crucible + ray-seam |
| CORS | ray-seam |
| Secrets / `.env` / `.gitignore` / git history | ray-cloak (write-time) + ray-manifest + git-history sweep in ray-vault/ray-ledger |
| Rate limit | ray-sentry |
| IDOR | ray-turnstile |

## Severity-owner boundary

Domain skills DISCOVER and write findings with a proposed `severity`, `cwe`, and
`owasp` tag. The final numeric score and priority are still owned by `ray-gauge`
and its 27 caps — a domain skill never sets `ray_risk_score`. A domain skill MAY
set `severity` from the class's inherent impact; `ray-gauge` reconciles it.

See `hunting-doctrine.md` (in this directory) for *how* to hunt each class and
the bar every finding clears before it is written.
