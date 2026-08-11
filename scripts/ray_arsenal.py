#!/usr/bin/env python3
"""
ray_arsenal.py — the reaver/bulwark arsenal, discovered and driven honestly.

The `ray-siege` red team (`ray-reaver`) and blue team (`ray-bulwark`) do not
re-implement nmap, sqlmap, semgrep, or garak — nobody should. They *drive* the
real binary when it is installed, and fall back to a documented manual technique
when it is not. This helper is the thin, gated adapter that makes both halves
honest:

  * `list` probes which arsenal tools are actually present (`shutil.which`) and
    their version. This is un-fakeable capability discovery: if `list` says
    sqlmap is absent, an agent cannot then claim to have read sqlmap output.

  * `run` is a *gated dispatcher*. Before it executes anything it enforces the
    same invariants as `ray-siege/references/siege_protocol.md` §1 — the primary
    target must resolve to loopback, no argument may smuggle a non-loopback
    URL/host, and a small banned-flag list blocks the escalation/exfil switches
    that would take a tool outside the non-destructive charter. If a gate cannot
    be *proven* satisfied, it refuses (fail-closed, non-zero exit). If the tool
    is not installed it returns `status: not_installed` plus the fallback note,
    never a fabricated result.

The helper embeds no offensive binaries. It is a dependency-free (stdlib-only)
registry + gate; the capability lives in whatever the host has installed.

Usage:
  python3 ray_arsenal.py list [--json] [--side offense|defense]
  python3 ray_arsenal.py run  --tool <name> [--target <url|host|path>] [--json] \
                              [-- <extra tool args>]

Exit codes for `run`: 0 = ran or not_installed (informative); 2 = unknown tool /
bad usage; 3 = a gate refused the invocation.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

try:  # urlsplit lives here on py3; keep the import defensive.
    from urllib.parse import urlsplit
except ImportError:  # pragma: no cover - py2 fallback, never hit in this repo
    from urlparse import urlsplit  # type: ignore

RUN_TIMEOUT = 240          # hard ceiling on any driven tool
OUTPUT_CAP = 20000         # truncate captured output so a scanner can't flood context
VERSION_TIMEOUT = 6

# --------------------------------------------------------------------------- #
# The gate — loopback-only, no smuggled remote targets, no escalation switches.
# Mirrors siege_protocol.md §1: only 127.0.0.0/8, ::1, and localhost are in
# scope, by construction. There is no override.
# --------------------------------------------------------------------------- #

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# An argument "looks like a network target" if it carries a scheme, or a
# host:port, or is a bare IP literal. Bare filesystem paths and plain flags do
# not match, so wordlists / --config values are not mistaken for targets.
_URL_LIKE = re.compile(r"^(?:https?|ftp|gopher|ws|wss)://", re.IGNORECASE)
_HOSTPORT = re.compile(r"^\[?[\w.\-:]+\]?:\d{1,5}(?:/|$)")


def _host_is_loopback(host):
    """True only for the exact loopback set siege_protocol.md §1 allows.

    Deliberately does NOT resolve arbitrary names over DNS (a network call in a
    security gate, and a name can point anywhere): only localhost, ::1, and the
    127.0.0.0/8 literals qualify. 0.0.0.0 is all-interfaces, not loopback.
    """
    if not host:
        return False
    h = host.strip().strip("[]").lower()
    if h in ("localhost", "::1", "127.0.0.1"):
        return True
    if h.startswith("127.") and _IPV4.match(h):
        return True
    return False


def _extract_host(value):
    """Pull the hostname out of a URL, host:port, or bare host. None if absent."""
    if not value:
        return None
    v = value.strip()
    if "://" in v:
        return urlsplit(v).hostname
    # No scheme: re-split with a synthetic one so urlsplit finds the host:port.
    try:
        return urlsplit("//" + v).hostname
    except ValueError:
        return None


def _looks_like_network_target(arg):
    if _URL_LIKE.match(arg):
        return True
    if _HOSTPORT.match(arg):
        return True
    # A bare IPv4 literal on its own is a target; a bare word (a flag, a path
    # segment) is not.
    return bool(_IPV4.match(arg.strip("[]")))


# Escalation / exfil / destructive switches that take a tool outside the
# non-destructive, on-host charter. Matched case-insensitively as whole tokens
# anywhere in the extra args, for every tool.
_BANNED_GLOBAL = [
    "--os-shell", "--os-cmd", "--os-pwn", "--sql-shell", "--priv-esc",
    "--file-write", "--file-dest", "--file-upload", "--dump-all",
    "--flood", "--dos", "--all-tables",
]


class GateRefusal(Exception):
    """Raised when an invariant cannot be proven; carries the plain reason."""


def _enforce_gate(spec, target, extra):
    """Run every §1 check. Raise GateRefusal(reason) on the first failure."""
    kind = spec["arg_kind"]

    # 1. Primary target must be loopback for any tool that hits the network.
    if kind in ("loopback_url", "loopback_host"):
        if not target:
            raise GateRefusal(
                "tool '{}' needs a --target loopback URL/host to attack".format(spec["_name"]))
        host = _extract_host(target)
        if not _host_is_loopback(host):
            raise GateRefusal(
                "target host {!r} is not loopback; the arsenal drives tools only "
                "against a local disposable instance (127.0.0.0/8, ::1, localhost)".format(host))
    elif kind in ("path", "cwd_path"):
        if not target:
            raise GateRefusal(
                "tool '{}' needs a --target filesystem path to inspect".format(spec["_name"]))

    # 2. No argument may smuggle a non-loopback target past check #1.
    for arg in extra:
        if _looks_like_network_target(arg):
            host = _extract_host(arg)
            if not _host_is_loopback(host):
                raise GateRefusal(
                    "argument {!r} points at non-loopback host {!r}; refused".format(arg, host))

    # 3. No escalation/exfil/destructive switches (global + per-tool).
    banned = _BANNED_GLOBAL + spec.get("banned", [])
    low = [a.lower() for a in extra]
    for bad in banned:
        if bad.lower() in low:
            raise GateRefusal(
                "argument {!r} is banned for the arsenal (escalation/exfil/destructive); "
                "it is out of the non-destructive charter".format(bad))


# --------------------------------------------------------------------------- #
# The curated registry. One entry = one binary. Scope is the reaver's real
# target: a local web / API / LLM app. Tools that only fit off-charter targets
# (AD, wireless, C2), that invite flooding (hydra), or that exfil to a public
# OOB service (interactsh) are intentionally absent — see reaver_arsenal.md for
# why and what to do instead.
#
# Fields:
#   side       offense | defense
#   category   short grouping for `list`
#   binary     the executable probed and driven
#   arg_kind   loopback_url | loopback_host | path | cwd_path | none
#   argv       template; "{TARGET}" is replaced by the (transformed) target
#   version    args to read a version line ([] => don't try)
#   banned     extra tool-specific banned switches
#   fallback   the dependency-free manual technique when the tool is absent
#   docket     the Ray domain docket that owns this class
#   purpose    one line
# --------------------------------------------------------------------------- #

REGISTRY = {
    # ---- offense: recon / fingerprint -------------------------------------
    "nmap": {
        "side": "offense", "category": "recon", "binary": "nmap",
        "arg_kind": "loopback_host",
        "argv": ["nmap", "-sV", "-Pn", "-T3", "--top-ports", "1000", "{TARGET}"],
        "version": ["--version"], "banned": ["-T5", "--max-rate"],
        "fallback": "Probe ports with a bounded socket sweep in Python "
                    "(connect_ex over the ports you care about) and read Server/"
                    "X-Powered-By from `curl -sI`.",
        "docket": "ray-citadel/references/architecture_baseline.md",
        "purpose": "Service/version discovery on the local instance.",
    },
    "httpx": {
        "side": "offense", "category": "recon", "binary": "httpx",
        "arg_kind": "loopback_url",
        "argv": ["httpx", "-silent", "-title", "-tech-detect", "-status-code",
                 "-no-color", "-u", "{TARGET}"],
        "version": ["-version"], "banned": [],
        "fallback": "`curl -sI {target}` and inspect Server, X-Powered-By, "
                    "Set-Cookie, and framework-specific headers.",
        "docket": "ray-custodian/references/web_surface_baseline.md",
        "purpose": "HTTP tech fingerprint of the running app.",
    },
    # ---- offense: web content / vuln surface ------------------------------
    "ffuf": {
        "side": "offense", "category": "web-discovery", "binary": "ffuf",
        "arg_kind": "loopback_url",
        "argv": ["ffuf", "-u", "{TARGET}", "-mc", "200,204,301,302,307,401,403",
                 "-noninteractive"],
        "version": ["-V"], "banned": [],
        "fallback": "Loop a small builtin path list (/admin,/api,/debug,/.env,"
                    "/actuator) with `curl -s -o /dev/null -w '%{http_code}'`.",
        "docket": "ray-seam/references/seam_docket.md",
        "purpose": "Content/endpoint discovery (needs `-w <wordlist>` in extra; "
                   "put FUZZ in the URL).",
    },
    "nuclei": {
        "side": "offense", "category": "web-discovery", "binary": "nuclei",
        "arg_kind": "loopback_url",
        "argv": ["nuclei", "-silent", "-nc", "-rl", "50", "-c", "10", "-u", "{TARGET}"],
        "version": ["-version"], "banned": [],
        "fallback": "No fallback — nuclei only *seeds* candidates; hand-verify "
                    "each hit with a canary before it becomes a finding.",
        "docket": "ray-custodian/references/web_surface_baseline.md",
        "purpose": "Template scan to SEED candidates (never proof on its own).",
    },
    "nikto": {
        "side": "offense", "category": "web-discovery", "binary": "nikto",
        "arg_kind": "loopback_url",
        "argv": ["nikto", "-h", "{TARGET}", "-ask", "no", "-nointeractive",
                 "-maxtime", "120s"],
        "version": ["-Version"], "banned": [],
        "fallback": "Request /server-status, /.git/HEAD, default files, and "
                    "verbose-error triggers by hand with curl.",
        "docket": "ray-citadel/references/architecture_baseline.md",
        "purpose": "Server misconfig sweep to SEED candidates.",
    },
    # ---- offense: injection ------------------------------------------------
    "sqlmap": {
        "side": "offense", "category": "injection", "binary": "sqlmap",
        "arg_kind": "loopback_url",
        "argv": ["sqlmap", "-u", "{TARGET}", "--batch", "--level", "2",
                 "--risk", "1", "--technique", "BEUST"],
        "version": ["--version"],
        "banned": ["--os-shell", "--os-cmd", "--os-pwn", "--sql-shell",
                   "--file-write", "--file-dest", "--dump-all", "--all"],
        "fallback": "Send a boolean pair (' OR '1'='1  vs  ' OR '1'='2) and a "
                    "canary-targeted extraction by hand; prove with the seeded "
                    "canary row (siege_protocol §1.3).",
        "docket": "ray-crucible/references/injection_docket.md",
        "purpose": "SQLi detection/extraction against the local app "
                   "(read/boolean/time only; never --os-*/--file-write).",
    },
    # ---- offense: API / identity ------------------------------------------
    "arjun": {
        "side": "offense", "category": "api", "binary": "arjun",
        "arg_kind": "loopback_url",
        "argv": ["arjun", "-u", "{TARGET}"],
        "version": [], "banned": [],
        "fallback": "Diff responses while fuzzing a small candidate param list "
                    "(id, user, admin, debug, next, redirect) with curl.",
        "docket": "ray-seam/references/seam_docket.md",
        "purpose": "Hidden HTTP parameter discovery.",
    },
    "jwt_tool": {
        "side": "offense", "category": "api", "binary": "jwt_tool",
        "arg_kind": "none",
        "argv": ["jwt_tool"],
        "version": [], "banned": [],
        "fallback": "Decode the JWT header/payload with base64url, then re-forge "
                    "by hand: alg:none, HS/RS key-confusion (sign with the public "
                    "key as the HMAC secret), and role/tenant claim tampering.",
        "docket": "ray-turnstile/references/identity_docket.md",
        "purpose": "JWT tampering: alg:none, key-confusion, claim forgery. Pass "
                   "the captured token + flags as extra; any -t URL must be loopback.",
    },
    # ---- offense: transport ------------------------------------------------
    "testssl.sh": {
        "side": "offense", "category": "transport", "binary": "testssl.sh",
        "arg_kind": "loopback_host",
        "argv": ["testssl.sh", "--quiet", "--color", "0", "{TARGET}"],
        "version": ["--version"], "banned": [],
        "fallback": "`openssl s_client -connect {host}:{port}` and inspect the "
                    "protocol/cipher/cert; only relevant if the local app serves TLS.",
        "docket": "ray-custodian/references/privacy_docket.md",
        "purpose": "TLS posture of the local endpoint (if it speaks TLS).",
    },
    # ---- offense: intel (offline) -----------------------------------------
    "searchsploit": {
        "side": "offense", "category": "intel", "binary": "searchsploit",
        "arg_kind": "none",
        "argv": ["searchsploit"],
        "version": [], "banned": [],
        "fallback": "Map the fingerprinted product+version to known CVEs from the "
                    "ray-manifest SBOM / OSV data instead.",
        "docket": "ray-citadel/references/architecture_baseline.md",
        "purpose": "Offline exploit-DB lookup by product/version (pass search "
                   "terms as extra). Local DB only — no network target.",
    },
    # ---- offense: LLM red-team (the differentiator) -----------------------
    "garak": {
        "side": "offense", "category": "llm", "binary": "garak",
        "arg_kind": "none",
        "argv": ["garak"],
        "version": ["--version"], "banned": [],
        "fallback": "Fire the ray-oracle prompt-injection/jailbreak corpus at the "
                    "local LLM route by hand and assert the canary marker in the "
                    "model output / a tool it should not have called.",
        "docket": "ray-oracle/references/llm_security_docket.md",
        "purpose": "LLM vulnerability scan. Point its REST generator at the "
                   "LOOPBACK LLM endpoint (config file) — that binding is charter, "
                   "held by the reaver.",
    },
    "promptfoo": {
        "side": "offense", "category": "llm", "binary": "promptfoo",
        "arg_kind": "none",
        "argv": ["promptfoo"],
        "version": ["--version"], "banned": [],
        "fallback": "Same as garak's fallback — drive the ray-oracle corpus manually.",
        "docket": "ray-oracle/references/llm_security_docket.md",
        "purpose": "LLM red-team eval (config points its provider at the loopback "
                   "endpoint). Pass `redteam`/`eval` + config as extra.",
    },

    # ---- defense: SAST / root cause ---------------------------------------
    "semgrep": {
        "side": "defense", "category": "sast", "binary": "semgrep",
        "arg_kind": "path",
        "argv": ["semgrep", "--quiet", "--config", "auto", "{TARGET}"],
        "version": ["--version"], "banned": [],
        "fallback": "Grep the sink pattern from the mapped domain docket across "
                    "the codebase to find every sibling of the proven sink.",
        "docket": "ray-crucible/references/injection_docket.md",
        "purpose": "Find the root-cause pattern and its siblings (--config auto "
                   "needs network for rules; pass a local ruleset in extra offline).",
    },
    "gitleaks": {
        "side": "defense", "category": "secret-hygiene", "binary": "gitleaks",
        "arg_kind": "path",
        "argv": ["gitleaks", "detect", "--no-banner", "--redact", "--source", "{TARGET}"],
        "version": ["version"], "banned": [],
        "fallback": "ray_metadata.py harvests leaked secrets from artifacts; for "
                    "source, grep high-entropy assignments to confirm the patch left none.",
        "docket": "ray-vault/references/datastore_hardening.md",
        "purpose": "Confirm the fix (and the tree) leaks no secret.",
    },
    "tfsec": {
        "side": "defense", "category": "iac", "binary": "tfsec",
        "arg_kind": "path",
        "argv": ["tfsec", "--no-color", "--soft-fail", "{TARGET}"],
        "version": ["--version"], "banned": [],
        "fallback": "ray_iac_scan (the ray_iac.py helper / MCP tool) runs the "
                    "bounded dependency-free IaC scan.",
        "docket": "ray-terrain (ray_iac.py)",
        "purpose": "Deep IaC misconfig scan when hardening infra the app exposed.",
    },
}

for _n, _s in REGISTRY.items():
    _s["_name"] = _n


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #

def _tool_version(spec, binpath):
    if not spec.get("version"):
        return None
    try:
        proc = subprocess.run([binpath] + spec["version"],
                              capture_output=True, text=True, timeout=VERSION_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = (proc.stdout or proc.stderr or "").strip().splitlines()
    return out[0][:120] if out else None


def cmd_list(args):
    tools = []
    for name, spec in sorted(REGISTRY.items()):
        if args.side and spec["side"] != args.side:
            continue
        binpath = shutil.which(spec["binary"])
        entry = {
            "name": name, "side": spec["side"], "category": spec["category"],
            "binary": spec["binary"], "installed": bool(binpath),
            "purpose": spec["purpose"], "docket": spec["docket"],
        }
        if binpath:
            entry["path"] = binpath
            entry["version"] = _tool_version(spec, binpath)
        else:
            entry["fallback"] = spec["fallback"]
        tools.append(entry)
    installed = sum(1 for t in tools if t["installed"])
    report = {
        "arsenal": tools, "total": len(tools), "installed": installed,
        "absent": len(tools) - installed,
        "note": "Absent tools are not a failure — each carries a dependency-free "
                "fallback. Ray drives real binaries; it never embeds them.",
    }
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("Arsenal: {} tools, {} installed, {} absent\n".format(
            report["total"], installed, report["absent"]))
        for t in tools:
            mark = "✓ " + (t.get("version") or "installed") if t["installed"] else "· absent"
            print("  [{}/{}] {:<13} {}".format(t["side"], t["category"], t["name"], mark))
            print("       {}".format(t["purpose"]))
            if not t["installed"]:
                print("       fallback: {}".format(t["fallback"]))
    return 0


def _build_argv(spec, target):
    kind = spec["arg_kind"]
    if kind == "loopback_host":
        tval = _extract_host(target) or target
    else:
        tval = target
    argv = []
    for tok in spec["argv"]:
        argv.append(tval if tok == "{TARGET}" else tok)
    return argv


def cmd_run(args):
    spec = REGISTRY.get(args.tool)
    if spec is None:
        sys.stderr.write("unknown tool: {}. Known: {}\n".format(
            args.tool, ", ".join(sorted(REGISTRY))))
        return 2

    extra = args.extra or []
    try:
        _enforce_gate(spec, args.target, extra)
    except GateRefusal as refusal:
        payload = {"tool": args.tool, "status": "refused", "reason": str(refusal)}
        if args.json:
            json.dump(payload, sys.stdout, indent=2)
            sys.stdout.write("\n")
        # Also to stderr so the MCP wrapper surfaces it as an error.
        sys.stderr.write("REFUSED: {}\n".format(refusal))
        return 3

    binpath = shutil.which(spec["binary"])
    if not binpath:
        payload = {
            "tool": args.tool, "status": "not_installed", "binary": spec["binary"],
            "fallback": spec["fallback"], "docket": spec["docket"],
        }
        if args.json:
            json.dump(payload, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print("{} not installed.\nFallback: {}".format(spec["binary"], spec["fallback"]))
        return 0  # informative, not an error — the agent uses the fallback

    argv = _build_argv(spec, args.target)
    argv[0] = binpath
    argv += extra
    cwd = args.target if spec["arg_kind"] == "cwd_path" else None
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=RUN_TIMEOUT, cwd=cwd)
    except subprocess.TimeoutExpired:
        payload = {"tool": args.tool, "status": "timeout",
                   "timeout_s": RUN_TIMEOUT, "argv": argv}
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    except OSError as exc:
        sys.stderr.write("failed to run {}: {}\n".format(spec["binary"], exc))
        return 2

    out = (proc.stdout or "")[:OUTPUT_CAP]
    err = (proc.stderr or "")[:2000]
    payload = {
        "tool": args.tool, "status": "ran", "binary": binpath,
        "argv": argv, "returncode": proc.returncode,
        "docket": spec["docket"], "stdout": out, "stderr": err,
        "note": "Tool output SEEDS candidates. A finding still requires a canary "
                "proof per siege_protocol §1.3 — never report a scanner hit as a "
                "break-in on its own.",
    }
    if args.json:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("$ {}".format(" ".join(argv)))
        print("exit {}\n{}".format(proc.returncode, out))
        if err.strip():
            sys.stderr.write(err + "\n")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(
        description="Discover and drive the ray-siege arsenal, under the siege gate.")
    sub = ap.add_subparsers(dest="cmd")

    p_list = sub.add_parser("list", help="probe which arsenal tools are installed")
    p_list.add_argument("--json", action="store_true")
    p_list.add_argument("--side", choices=["offense", "defense"])

    p_run = sub.add_parser("run", help="drive one arsenal tool through the gate")
    p_run.add_argument("--tool", required=True)
    p_run.add_argument("--target", help="loopback URL/host, or a filesystem path")
    p_run.add_argument("--json", action="store_true")
    p_run.add_argument("extra", nargs="*", help="extra tool args (after --)")

    args = ap.parse_args(argv)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "run":
        return cmd_run(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
