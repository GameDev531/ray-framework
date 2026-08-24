# Reaver Arsenal — the offensive tools, driven honestly

The tools `ray-reaver` reaches for, per class, and how to drive each **through the
gate**. Ray does not embed nmap, sqlmap, or garak — it *drives* the real binary
when present and falls back to a manual technique when absent. The
`ray_arsenal.py` helper (MCP tools `ray_arsenal_list` / `ray_arsenal_run`) is the
one gated path that runs any of them.

This file is the *catalog*. The attack theory per class lives in the mapped
domain docket; the live evidence standard lives in `live_exploitation.md` §2.
Everything here operates under `siege_protocol.md` §1 — nothing below overrides it.

## Table of Contents

- [0. Two rules that bind the whole arsenal](#0-two-rules-that-bind-the-whole-arsenal)
- [1. How to drive a tool](#1-how-to-drive-a-tool)
- [2. The tools, by class](#2-the-tools-by-class)
- [3. Deliberately excluded — and what to do instead](#3-deliberately-excluded--and-what-to-do-instead)
- [4. Reference corpora — payloads, wordlists, technique catalogs](#4-reference-corpora--payloads-wordlists-technique-catalogs)
- [5. Where your break-in sits in the kill chain](#5-where-your-break-in-sits-in-the-kill-chain-think-like-the-full-attacker)

______________________________________________________________________

## 0. Two rules that bind the whole arsenal

**A scanner seeds; a canary proves.** nmap, nuclei, nikto, sqlmap, arjun — every
tool here produces *candidates*, not findings. A finding for `ray-siege` exists
only when you have a **live canary proof** per `live_exploitation.md` §2. A
scanner's "VULNERABLE" line is a lead to verify by hand, never a break-in on its
own. `ray_arsenal_run` restates this in every result's `note` field; honor it.
This is the same "manual over scanners" line already in `live_exploitation.md` §0.

**The gate is not yours to relax.** `ray_arsenal_run` enforces
`siege_protocol.md` §1 before it runs anything: the target must be loopback, no
argument may carry a non-loopback host, and escalation/exfil/destructive switches
are refused. If it refuses, the invocation was out of scope — fix the invocation,
never route around the helper by shelling out to the raw binary to dodge the gate.
Driving the raw binary directly is allowed only for a tool the helper does not
carry, and the same §1 rules still bind you by hand.

______________________________________________________________________

## 1. How to drive a tool

1. **RECALL capability first.** Before the first attack, call `ray_arsenal_list`
   (once). It tells you which tools are actually installed on this host. If a tool
   is absent, you use its fallback — you do **not** claim output you never got.
   This is the anti-hallucination step: no `list` entry, no tool run.
2. **Drive it through the gate.** `ray_arsenal_run(tool=…, target=<loopback URL>,
   args=[…])`. Read the returned `stdout` as candidate signal.
3. **Verify to a canary.** Turn any candidate into a scripted, re-runnable attack
   under `workspace/reproducers/siege/` that captures the §2 canary evidence.
   Only then write the finding (`findings_contract.md`).
4. **On absence, fall back.** If `status: not_installed`, run the manual technique
   in the tool's `fallback` (also shown by `ray_arsenal_list`). The fallbacks are
   dependency-free (curl / a small Python socket sweep / base64url by hand), so a
   bare host never blocks the siege.

______________________________________________________________________

## 2. The tools, by class

Each row: what it is for, the safe invocation the helper builds, the canary that
turns its output into a finding, and the domain docket with the full theory. The
banned-switch column is what the gate refuses (and what you must never add by hand).

### Recon / fingerprint

| Tool | Drives | Canary that makes it a finding | Docket |
|---|---|---|---|
| `nmap` | `-sV -Pn -T3 --top-ports 1000` against the loopback host | none by itself — feeds every other class; open port + service is a lead | `ray-citadel` architecture_baseline |
| `httpx` | title + tech-detect + status against the loopback URL | none by itself — the stack it reveals selects the next attack | `ray-custodian` web_surface_baseline |

Banned here: mass timing floods (`-T5`, `--max-rate`) — bounded scans only.

### Web discovery (seed only)

| Tool | Drives | Canary | Docket |
|---|---|---|---|
| `ffuf` | fuzz a wordlist into the URL (`FUZZ` marker; pass `-w` in `args`) | a discovered endpoint is a lead; the break-in on it needs its own §2 proof | `ray-seam` seam_docket |
| `nuclei` | bounded template scan (`-rl 50 -c 10`) | **never proof on its own** — hand-verify every hit to a canary | `ray-custodian` web_surface_baseline |
| `nikto` | server-misconfig sweep (`-maxtime 120s`) | the sensitive artifact actually served to an unauthorized caller | `ray-citadel` architecture_baseline |

### Injection

| Tool | Drives | Canary | Docket |
|---|---|---|---|
| `sqlmap` | `--batch --level 2 --risk 1 --technique BEUST` on the URL | the **seeded canary row** surfaces, or a stable boolean/time differential | `ray-crucible` injection_docket (SQLI) |
| `dalfox` | XSS discovery (reflected/DOM) on a parameterized URL | a unique inert marker **executing** in headless Chromium — never cookie theft | `ray-crucible` injection_docket (XSS) |
| `tplmap` | SSTI detection on the URL (evaluation proof only) | a unique arithmetic/marker **evaluated** in the response (`{{7*7}}`→`49`) | `ray-crucible` injection_docket (SSTI) |

Banned here (hard): for `sqlmap` — `--os-shell`, `--os-cmd`, `--os-pwn`,
`--sql-shell`, `--file-write`, `--file-dest`, `--dump-all`, `--all`; for `tplmap` —
`--os-cmd`, `--os-shell`, `--reverse`, `--bind-shell`, `--upload`, `--download`.
Prove a write with **one** canary insert by hand, XSS with a browser marker, SSTI
with the evaluated arithmetic — never the write/exec/shell primitives.

### API / identity

| Tool | Drives | Canary | Docket |
|---|---|---|---|
| `arjun` | hidden-parameter discovery on the URL | a hidden param that unlocks a break-in (mass-assignment, IDOR) — proven on that param | `ray-seam` seam_docket |
| `jwt_tool` | offline token surgery: alg:none, HS/RS key-confusion, claim tamper (pass the captured token + flags in `args`) | a protected `200` for an identity the forged token should not have | `ray-turnstile` identity_docket |

`jwt_tool` operates on a token you already captured — no network target. If you
use its request mode (`-t`), the gate forces that URL to be loopback too.

### Transport

| Tool | Drives | Canary | Docket |
|---|---|---|---|
| `testssl.sh` | TLS posture of the loopback endpoint | a weak protocol/cipher/cert the local app actually negotiates (only if it serves TLS) | `ray-custodian` privacy_docket |

### Intel (offline)

| Tool | Drives | Canary | Docket |
|---|---|---|---|
| `searchsploit` | offline exploit-DB lookup by product+version (terms in `args`) | none — it maps a fingerprint to known exploits to try; the exploit needs its own §2 proof | `ray-citadel` architecture_baseline |

### LLM red-team (the differentiator — casa com `ray-oracle`)

| Tool | Drives | Canary | Docket |
|---|---|---|---|
| `garak` | LLM vulnerability probes; point its REST generator's **config** at the loopback LLM route | the inert marker appears in the model output, or the model calls a tool it must not | `ray-oracle` llm_security_docket |
| `promptfoo` | red-team eval; its provider config points at the loopback endpoint | same — a jailbreak/injection that lands the canary marker | `ray-oracle` llm_security_docket |

These two take a config file, so the gate cannot read the endpoint from argv —
pointing the generator at the **loopback** LLM route is charter you uphold, exactly
as with every other tool. Never aim them at a hosted model API.

______________________________________________________________________

## 3. Deliberately excluded — and what to do instead

The arsenal is curated to the reaver's real target (a local web/API/LLM app under
the non-destructive gate). These are left out on purpose:

- **`hydra` / high-rate brute-forcers.** They invite flooding, which the charter
  forbids. Prove a *missing* rate limit with a small bounded burst (≈20 requests
  in a curl loop) per `live_exploitation.md` §3 — enough to show no throttle, never
  enough to degrade the service.
- **`interactsh` / Burp Collaborator / public OOB.** They exfil the callback to a
  third-party server on the internet — a direct violation of §1.2. Prove SSRF
  against the **siege's own local listener** (seeded in Setup Step 4), never a
  public collaborator.
- **`hashcat` / `john` offline crackers.** Rarely the siege's path (they need a
  captured hash + a wordlist and prove little about the running app). If a weak
  hashing scheme matters, report it from the code (`ray-turnstile`/`ray-vault`),
  don't grind hashes.
- **AD / wireless / C2 / RE frameworks** (CrackMapExec, aircrack, Sliver, Ghidra).
  Out of the local-only, single-app charter by construction — a different kind of
  engagement with a human-in-the-loop gate, which `ray-siege` is not.

Reporting tools are excluded too, but for the opposite reason: `ray-gauge` and
`ray-chronicle` already own findings output — the arsenal feeds them, it does not
duplicate them.

______________________________________________________________________

## 4. Reference corpora — payloads, wordlists, technique catalogs

The *tools* above execute; these *corpora* are where you get the payload, the
wordlist, or the technique detail to feed them. They are references to consult,
not binaries to run, and the same gate binds anything you build from them (loopback
target, non-destructive, canary proof). Cited by name/URL; licenses vary — see
`CREDITS.md`.

| Corpus | Use it for | Maps to |
|---|---|---|
| **PayloadsAllTheThings** (github.com/swisskyrepo/PayloadsAllTheThings) | The canonical per-class payload + technique reference. Its top-level dirs map almost 1:1 to your classes: `SQL Injection`, `NoSQL Injection`, `XSS`, `Server Side Template Injection`, `XXE`, `Insecure Deserialization`, `Server Side Request Forgery`, `Command Injection`, `Directory Traversal`, `JSON Web Token`, `OAuth`, `GraphQL Injection`, `CORS Misconfiguration`, `Type Juggling`, `Prototype Pollution`, `Request Smuggling`, `Upload Insecure Files`. Read the class folder before hand-crafting a payload. | every §2 class + the injection docket |
| **SecLists** (github.com/danielmiessler/SecLists) | Wordlists to feed the tools: `Discovery/Web-Content/*` for `ffuf`/`nikto` content discovery, `Fuzzing/*` for parameter/format fuzzing (`arjun`), `Passwords/*` and `Usernames/*` for a **bounded** credential-stuffing proof (≈20 tries, never a flood), `Payloads/*` for injection primitives. | `ffuf`, `arjun`, bounded auth burst |
| **OWASP Cheat Sheet Series** (github.com/OWASP/CheatSheetSeries) | The attacker-relevant "what the control should be" — read the class cheat sheet to know exactly which check to try to bypass. (The blue team reads the same series for the fix — `bulwark_arsenal.md`.) | every class |
| **The Hacker Recipes** (thehacker.recipes) | Deep technique writeups; the **web/API** sections are in-charter. Its AD/network sections are **not** — ignore them, they belong to the excluded categories (§3). | web/API classes only |

**Tooling corpora already covered by the arsenal:** `nuclei`, `httpx`, `nmap`,
`ffuf`, `sqlmap`, `dalfox`, `tplmap`, `garak`, `promptfoo` are all §2 entries —
drive them via `ray_arsenal_run`, don't re-derive. **OWASP ZAP** is a heavier DAST
alternative to the §2 web tools; if it is installed, it can seed candidates the
same way `nuclei` does — a scanner still only seeds, a canary still proves (§0).

**More web/API tools worth reaching for if installed** (not in the runnable
registry, but in-charter — drive them by hand under the same gate):

| Tool | For | Note |
|---|---|---|
| `schemathesis` | Property-based API fuzzing from an OpenAPI/GraphQL schema | Powerful, but it exercises **mutating** operations (POST/DELETE) broadly — only run it against the siege's disposable, re-seeded DB (`siege_protocol.md` REBUILD resets state each round), never a target whose data must survive. Filter to safe methods when unsure. |
| `kiterunner` | API route/endpoint discovery (finds undocumented routes) | Feeds the API-authz classes (`ray-turnstile` BOLA/BFLA); a discovered route is a lead, not a finding. |
| `dirsearch` / `wfuzz` | Content discovery | Alternatives to `ffuf`; same wordlists (SecLists). |
| `WPScan` / `droopescan` / `joomscan` | CMS-specific scans | Only when the local target **is** WordPress/Drupal/Joomla; a version/plugin lead still needs its own canary proof. |
| `mitmproxy` | Intercept + replay + tamper HTTP(S) | Useful to capture a request and mutate it for IDOR/mass-assignment/JWT tests; the loopback-only rule still binds every replayed request. |

**Recon corpora route elsewhere.** `subfinder`, `amass`, and passive
attack-surface OSINT are **`ray-quarry`'s** job, not the siege's — the reaver
attacks the single loopback target the orchestrator stood up, it does not enumerate
external infrastructure. If external recon is wanted, invoke `ray-quarry` under its
own scope-attestation gate.

**Still excluded (same reason as §3).** Metasploit, Impacket, BloodHound,
CrackMapExec, Responder, Evilginx2, Mimikatz, WinPEAS — AD / C2 / network-lateral /
phishing / Windows-credential post-exploitation. They break the local-only,
non-destructive, single-app charter by construction. **LinPEAS** is the one edge
case: as a *local privilege-escalation enumerator on the disposable target*, its
checklist can inform an in-container escalation after a proven RCE
(`live_exploitation.md` §4) — consult its checks, but keep the host-canary,
non-destructive proof discipline; never run it against a host you did not stand up.

______________________________________________________________________

## 5. Where your break-in sits in the kill chain (think like the full attacker)

Think like the whole adversary, act only within your charter. Your proven web/API
break-in is **Initial Access** (ATT&CK TA0001); your escalation on the disposable
target is **Execution** (TA0002) and local **Privilege Escalation** (TA0004,
including container-escape, `live_exploitation.md` §4). That is the slice you
*perform* — a local, non-destructive, single-app engagement.

Everything a real adversary would do **next** — Persistence, Credential Access,
Lateral Movement, C2, Defense Evasion, Exfiltration, Impact — you **report as
`impact`, you do not perform.** Naming what an attacker would do from this foothold
sharpens the finding's severity and gives the blue team its detection targets
(`ray-warden` `analyst_playbooks.md` §11), which is the whole point of the
red/blue asymmetry: you think through the full chain, you execute only the local
links. Concretely, in a finding's `impact`:

- "This RCE is Initial Access; from here an adversary would establish **persistence**
  (a cron/service), harvest **credentials** from the app's config/env, and move
  **laterally** to the DB host." — *reported*, from static reasoning, not carried out.
- Never plant a real backdoor, never dump real credentials, never pivot to another
  host, never build a C2 channel or anti-forensics. Those are off-charter by
  construction (`siege_protocol.md` §1.2) and belong to a different, human-gated
  engagement model that `ray-siege` is not (`docs/coverage-map.md`).

The asymmetry, stated for you: **red performs the local slice and reasons about the
rest; blue detects the rest.** Reasoning about the full chain is in charter —
executing past Initial Access + local escalation is not.
