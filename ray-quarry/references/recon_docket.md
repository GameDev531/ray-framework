# Recon Docket — Techniques, Tools, Fallbacks, and What Each Yields

The technique encyclopedia for `ray-quarry`. Read the section for a class before
running it; don't re-derive method. Every technique here is bound by
`recon_scope.md` §1 — passive unless the asset is `active_ok`, never mass,
never destructive, never evasive, never exploitation.

Each class states: **what it yields**, **how to drive the tool that does it**
(only if installed — inventory first), **the dependency-free fallback** (so the
class is never skipped for want of a tool), **what counts as evidence**, and the
**downstream skill** that consumes the result.

Inventory installed tools once, at the start (Step 1), e.g.
`command -v amass subfinder dnsx nmap nuclei gitleaks trufflehog whois openssl
python3`. For every capability whose tool is absent, use the fallback. A bare
environment with only `python3`, `curl`/`openssl`, and `dig`/`nslookup` can still
complete every passive class.

## Table of Contents

- [1. Naming & Edge — DNS, subdomains, certificate transparency, WHOIS](#1-naming--edge--dns-subdomains-certificate-transparency-whois)
- [2. Published-Document Metadata — the FOCA method](#2-published-document-metadata--the-foca-method)
- [3. Leaked Secrets in Your Own Repos](#3-leaked-secrets-in-your-own-repos)
- [4. Bounded Active Enumeration (active_ok hosts only)](#4-bounded-active-enumeration-active_ok-hosts-only)
- [5. From Footprint to Downstream Skill](#5-from-footprint-to-downstream-skill)

______________________________________________________________________

## 1. Naming & Edge — DNS, subdomains, certificate transparency, WHOIS

**Yields**: the hostnames that name the estate — including forgotten ones — the
IPs behind them, the registrar/org data, and the certificates that quietly
enumerate internal names. All passive.

**Certificate transparency (highest signal, fully passive).** Public CT logs
record every issued certificate; their SANs routinely name `staging.`, `vpn.`,
`internal-api.` hosts nobody meant to advertise.
- Tool: query a CT-log aggregator over HTTPS (crt.sh-style JSON) with `curl`,
  filtered to the in-scope apex. Or `subfinder`/`amass` which fold CT in.
- Fallback (no tool): pull the leaf/chain of a known in-scope host with
  `openssl s_client -connect host:443 -servername host </dev/null 2>/dev/null |
  openssl x509 -noout -text` and read the **Subject Alternative Name** list — each
  SAN is a candidate host to resolve back through §3 scope resolution.
- Evidence: the SAN entry and the issuing cert's fingerprint/serial.

**DNS & subdomains.**
- Tool: `dnsx`/`amass`/`subfinder` for enumeration; `dig`/`nslookup` for records
  (A/AAAA/CNAME/MX/TXT/NS). TXT records leak SaaS verification tokens and SPF
  includes (which name your mail/marketing/support vendors → surface).
- Fallback: `dig +short <name> A AAAA CNAME MX TXT NS`, iterated over the
  CT-derived candidate hosts. Do **not** brute-force with a large wordlist against
  the target — that is closer to mass-probing; expand from evidence (CT, records)
  instead.
- Evidence: the record and the resolver answer.

**WHOIS / RDAP.**
- Tool: `whois <domain>` / RDAP over HTTPS.
- Fallback: RDAP JSON via `curl https://rdap.org/domain/<domain>`.
- Evidence: registrant org, name servers, creation/expiry — confirms ownership
  and names related infrastructure. Cross-check against the attestation's
  `authorization_basis`; a mismatch (the domain isn't registered to who you think)
  is itself worth surfacing.

Every discovered name/IP runs through `recon_scope.md` §3 before any further
lookup. An out-of-scope discovery is logged once and dropped.

______________________________________________________________________

## 2. Published-Document Metadata — the FOCA method

The quiet goldmine. Office documents, PDFs, and images an organization publishes
carry metadata that names the people, software, and internal filesystem behind
them. This is the classic FOCA technique, done passively and dependency-free.

**Yields**, per document:
- **Usernames / author names** — `Author`, `Creator`, `Last Modified By`,
  `dc:creator`. These are often real account names → your username convention,
  and seeds for later password-spray *modeling* (modeled, never executed here).
- **Software & versions** — `Producer`, `Application`, `AppVersion`,
  `pdf:Producer`, EXIF `Software`. A precise version of the tool that built a
  public PDF hints at the internal software estate and its patch level.
- **Internal paths & hosts** — template paths, `\\fileserver\share\...`, local
  drive letters, printer names, and tracked-change/revision remnants embedded in
  the file. These map internal structure without touching the network.
- **Device/geo (images)** — EXIF camera/software, and GPS if present (a physical
  location leak from a published photo).

**How to run it:** call the bundled extractor — no external dependency, no FOCA:

```
python3 <plugin>/scripts/ray_metadata.py <file-or-dir> [--json]
```

It handles:
- **PDF** — the `/Info` dictionary (Author/Creator/Producer/CreationDate) and the
  XMP packet (`dc:creator`, `xmp:CreatorTool`, `pdf:Producer`).
- **Office OOXML** (`.docx/.xlsx/.pptx`) — reads the zip's `docProps/core.xml`
  (`dc:creator`, `cp:lastModifiedBy`, revision) and `docProps/app.xml`
  (`Application`, `AppVersion`, `Company`, `Template`).
- **Images** (`.jpg/.jpeg/.tiff`) — the EXIF IFD (`Make`, `Model`, `Software`,
  `Artist`, and GPS IFD if present).
- It also runs a **leak harvester** over the extracted strings: UNC/Windows paths,
  POSIX home paths, email addresses, and internal hostnames — surfaced separately
  as `leaks` so a path buried in a template field is not missed.

**Where the documents come from:** either supplied via `--docs`, or reached
through in-scope public sources (a document linked from an in-scope site). The
skill does not crawl out-of-scope hosts to find documents.

**Evidence**: the extracted field + its source document URL/path (the document is
already public). A leaked internal username or path is a finding; benign metadata
(e.g. "made with LibreOffice") goes in the footprint as informational.

**Downstream**: usernames/paths feed `ray-perimeter` (attacker profile: what an
external actor already knows) and `ray-turnstile` (username convention → account
attack surface). Software versions feed the version-exposure check in §4/§5.

______________________________________________________________________

## 3. Leaked Secrets in Your Own Repos

**Yields**: credentials, API keys, and tokens committed into a working tree you
own (`--repo_root`) — what you leak in source. Scanning your **own** repo is
passive (§4 of recon_scope): nothing is sent to any target.

- Tool: `gitleaks detect --no-banner --redact -s <repo>` or
  `trufflehog filesystem <repo>` — both redact by default.
- Fallback (no tool): scan tracked files for high-signal patterns and
  high-entropy strings:
  - Patterns: `AKIA[0-9A-Z]{16}` (AWS), `gh[pousr]_[A-Za-z0-9]{36,}` (GitHub),
    `xox[baprs]-` (Slack), `-----BEGIN [A-Z ]*PRIVATE KEY-----`, `AIza[0-9A-Za-z_\-]{35}`
    (Google), generic `(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['"][^'"]{8,}['"]`.
  - Entropy: flag base64/hex strings ≥20 chars with Shannon entropy above ~4.0
    bits/char that are not obviously hashes-of-public-data.
  - Scan the working tree; if history matters, `git log -p` piped through the same
    patterns (bounded — recent history first).
- Evidence: **redacted** match — detector/pattern name, `file:line`, and the first
  and last 2–4 characters only. Never write the full secret into the footprint,
  the finding, or chat.
- Downstream: a live-looking secret is a finding anchored at `repo/path:line`;
  `ray-turnstile`/`ray-vault` own the blast radius (what the credential unlocks).

______________________________________________________________________

## 4. Bounded Active Enumeration (active_ok hosts only)

Run **only** for `--mode=active`, **only** against hosts marked `active_ok` in the
scope file, rate-limited and non-destructive. This is *observation with packets*,
not attack.

**Service & port discovery.**
- Tool: `nmap` — a bounded, polite scan: top-N common TCP ports, service/version
  detection, no aggressive timing. E.g.
  `nmap -sV --top-ports 100 -T2 --max-retries 2 <host>` (adjust to stay gentle).
  No `-T5`, no full 65k sweep across many hosts, no OS-fingerprint flood.
- Fallback: a small, sequential TCP connect check over a short curated port list
  with a Python `socket` connect-and-read-banner, one host at a time, with a delay
  between connects. Bounded ports, bounded rate.
- Evidence: `host:port`, state, and banner/service.

**Technology & version fingerprinting.**
- Tool: `whatweb`/`httpx` if present; else a single `curl -sI https://host` to
  read `Server`, `X-Powered-By`, framework cookies, and security-header presence.
- Evidence: the header values and inferred stack/version.

**Template-based exposure observation (`--depth=enumerate`).**
- Tool: `nuclei` restricted to **non-exploit** templates — exposures,
  misconfigurations, default-page and version detections that *confirm* a
  condition without exploiting it. Never run intrusive/fuzzing/exploit templates
  here; that crosses into `ray-siege` territory. Rate-limit
  (`-rate-limit`) and scope to the single `active_ok` host.
- Fallback: targeted single requests for well-known exposure paths that are safe
  to *observe* (e.g. a `Server`/version header, presence of a login page) — no
  fuzzing, no wordlist spray.
- Evidence: the template id / the observed condition and the response line that
  shows it.

**The hard line**: if a check would submit a credential, send a payload intended
to trigger a vulnerability, bypass a control, alter state, or generate load that
could degrade the service, it is **not** an `active_ok` check — stop and note it
as "belongs to ray-siege (local instance)". `ray-quarry` never crosses from
observe to exploit.

______________________________________________________________________

## 5. From Footprint to Downstream Skill

Every footprint item names the skill that acts on it, so recon feeds the pipeline
instead of ending in a report:

| Footprint item | Feeds |
|---|---|
| Host/subdomain/service inventory, attacker knowledge | `ray-perimeter` (threat model: real surface + attacker profile) |
| An in-scope running host you can stand up locally | `ray-siege` (attack a local copy and prove it) |
| Exposed datastore / admin service | `ray-vault` (reachability, privileges), `ray-sentry` (should-not-be-exposed) |
| Software/version exposure with a known-vulnerable surface | `ray-prospector` + the matching domain skill |
| Leaked username convention / internal identifiers | `ray-turnstile` (identity/account surface) |
| Committed secret | a finding now; `ray-turnstile`/`ray-vault` for blast radius |

A footprint item that is *supposed* to be public and is serving exactly what it
should stays informational in `footprint.json` — it is not a finding. A finding
is an **exposure worth closing**: something the surface reveals that it should
not, or a service/version/secret that hands an attacker leverage.
