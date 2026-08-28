#!/usr/bin/env python3
"""
ray_secrets.py — dependency-free secret-leak scanner for ray-cloak.

Catches the credentials an assistant most often leaves behind in a repo: real
connection strings, API keys, tokens, and private keys — in source, tests, JSON/
YAML config, Markdown docs, notebooks, SQL dumps, and CI files. It is the
evidence engine behind ray-cloak: the assistant does not merely *claim* it
checked for secrets before finishing a task — it runs this and reads the result.

Three things it does that a bare grep does not:
  1. Redacts every match — the secret value is never echoed back (printing it
     would leak it a second time, into the transcript).
  2. Raises severity by *where* the secret is. A credential in a Markdown doc
     that also carries the project URL is the exact real-world breach pattern
     (creds + login URL in one file) — flagged CRITICAL. A secret in a test file
     is HIGH, because throwaway tests are supposed to be deleted, not committed.
  3. Checks `.gitignore` coverage and flags throwaway-looking scratch files, so
     the "create a temp test, run it, then delete it" hygiene actually gets
     verified.

It is deliberately high-signal and bounded — it will not find a secret that has
been base64'd into a blob. For deep, entropy-based history scanning drive
gitleaks/trufflehog (ray-cloak points at them); this is the always-available,
zero-install first line.

Usage:
  python3 ray_secrets.py <file-or-dir> [--json] [--strict]

--strict exits 3 when any CRITICAL/HIGH finding exists (for a pre-commit gate).
"""

import argparse
import json
import os
import re
import sys

# --------------------------------------------------------------------------- #
# High-confidence secret value patterns. Each: (id, severity, regex). These
# match the *value*, so a redactor can blank exactly the sensitive span.
# --------------------------------------------------------------------------- #
_VALUE_RULES = [
    ("private-key-block", "CRITICAL",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("db-uri-with-creds", "CRITICAL",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://"
                r"[^\s:@/]+:[^\s:@/]+@[^\s/]+")),
    ("stripe-live-key", "CRITICAL", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}")),
    ("aws-access-key", "HIGH", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", "HIGH", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github-token", "HIGH",
     re.compile(r"\b(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})")),
    ("slack-token", "HIGH", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("stripe-pub-live", "HIGH", re.compile(r"\bpk_live_[0-9A-Za-z]{16,}")),
    ("openai-key", "HIGH", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("jwt", "MEDIUM",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer-token", "MEDIUM", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}")),
    ("slack-webhook", "HIGH",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
]

# Generic "key = value" assignment where the value looks real (not an env ref or
# a placeholder). Value captured in group 3 for redaction.
_ASSIGN_RE = re.compile(
    r'(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|'
    r'auth[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?url|database[_-]?url|'
    r'connection[_-]?string)\b'
    r'"?\s*[:=]\s*(["\']?)([^"\'\n]{6,})\2')

# Dangerous fallback: process.env.X || "real-value" / os.environ.get("X","real")
_FALLBACK_RE = re.compile(
    r'(?i)(?:process\.env\.\w+|os\.environ(?:\.get)?\(["\']\w+["\']\)?)\s*'
    r'(?:\|\||,)\s*["\'][^"\']*(?:://|:[^"\']*@|[A-Za-z0-9]{10,})[^"\']*["\']')

# A match is a false positive if the line references an env var, a placeholder,
# or a well-known dummy. Keeps the scanner high-signal.
_IGNORE_RE = re.compile(
    r'(?i)(process\.env|os\.environ|import\.meta\.env|getenv|\$\{|\$\(|%\(|'
    r'<[^>]+>|\{\{|\bENV\[|secretKeyRef|valueFrom|fromSecret|vault:|'
    r'change[_-]?me|example\.(com|org)|your[_-]|placeholder|dummy|redacted|'
    r'xxx+|\*{3,}|\.\.\.|null|None|true|false|""|\'\')')

_URL_RE = re.compile(r"https?://[^\s\"'`)]+")

_SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "env",
              "dist", "build", "target", ".terraform", ".next", "__pycache__",
              ".mypy_cache", ".pytest_cache", "coverage"}
_BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
               ".gz", ".tar", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".eot",
               ".so", ".dylib", ".dll", ".exe", ".class", ".pyc", ".lock"}

# Throwaway-looking filenames: if one of these is a test/scratch artifact, the
# hygiene rule is to delete it after running, not commit it.
_SCRATCH_RE = re.compile(
    r'(?i)(^|/|_|-|\.)(tmp|temp|scratch|debug|throwaway|delete[_-]?me|'
    r'quick[_-]?test|test[_-]?temp|sandbox|playground)(_|-|\.|$)')

# .gitignore should cover these so secrets never get staged.
_GITIGNORE_WANT = {
    ".env files": re.compile(r"(^|/)\.env"),
    "*.pem": re.compile(r"\*?\.pem\b"),
    "*.key": re.compile(r"\*?\.key\b"),
    "credentials*": re.compile(r"(?i)credentials"),
    "serviceAccount*": re.compile(r"(?i)serviceaccount"),
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _classify(basename):
    """Return a short file-class tag used to weight severity/messages."""
    b = basename.lower()
    if b == ".env.example" or b == ".env.sample" or b.endswith(".example"):
        return "example"  # placeholders expected; scanned but never elevated
    if b == ".env" or (b.startswith(".env.") and "example" not in b and "sample" not in b):
        return "dotenv"
    if b.endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts", ".test.py")) \
       or b.startswith("test_") or b.endswith("_test.py") or "/test" in b:
        return "test"
    if b.endswith((".md", ".markdown", ".mdx")):
        return "markdown"
    if b.endswith(".ipynb"):
        return "notebook"
    if b.endswith(".sql"):
        return "sql"
    if b == "dockerfile" or b.endswith(".dockerfile"):
        return "ci"
    if b.endswith((".yml", ".yaml")) and ("workflow" in b or "gitlab-ci" in b or "pipeline" in b):
        return "ci"
    if b.endswith((".json", ".yml", ".yaml", ".toml")):
        return "config"
    return "source"


def _redact(value):
    v = value.strip().strip("\"'")
    if len(v) <= 8:
        return "…(redacted)"
    return v[:4] + "…(redacted)…" + v[-2:]


def _mk(path, line_no, rid, sev, msg, secret_value):
    return {"file": path, "line": line_no, "rule": rid, "severity": sev,
            "message": msg, "evidence": _redact(secret_value)}


def scan_text(path, text, cls):
    findings = []
    has_url = bool(_URL_RE.search(text)) if cls == "markdown" else False
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        # 1. High-confidence value patterns.
        for rid, sev, rx in _VALUE_RULES:
            m = rx.search(line)
            if not m:
                continue
            findings.append(_mk(path, i, rid, sev, _msg_for(rid, cls), m.group(0)))

        # 2. Generic assignment with a real-looking value.
        m = _ASSIGN_RE.search(line)
        if m and not _IGNORE_RE.search(line):
            findings.append(_mk(path, i, "hardcoded-credential", "HIGH",
                                "Hardcoded credential — move it to an env var / secret manager.",
                                m.group(3)))

        # 3. Dangerous env fallback to a real default.
        if _FALLBACK_RE.search(line):
            findings.append(_mk(path, i, "dangerous-env-fallback", "MEDIUM",
                                "Env var falls back to a hardcoded secret — drop the default; fail closed.",
                                line))

    # Cross-line elevation for the real-world Markdown breach pattern.
    if cls == "markdown" and has_url:
        for f in findings:
            if f["severity"] in ("HIGH", "MEDIUM"):
                f["severity"] = "CRITICAL"
                f["message"] = ("Secret AND a project/login URL in the same doc — the exact "
                                "creds+URL pattern real breaches use. " + f["message"])
    # Secrets in an example file are expected placeholders; de-noise if any slipped.
    if cls == "example":
        findings = [f for f in findings if f["severity"] == "CRITICAL"]
    return findings


def _msg_for(rid, cls):
    base = {
        "private-key-block": "Private key committed — rotate it now; assume compromised.",
        "db-uri-with-creds": "Database URL with embedded credentials — use an env var; rotate the password.",
        "stripe-live-key": "LIVE payment secret key — rotate immediately; never commit gateway keys.",
        "aws-access-key": "AWS access key id — rotate; move to the secret manager / workload identity.",
        "google-api-key": "Google API key — rotate and restrict; source from env.",
        "github-token": "GitHub token — rotate now; assume compromised.",
        "slack-token": "Slack token — rotate; source from env.",
        "stripe-pub-live": "Stripe live key — verify it is the publishable key, not the secret.",
        "openai-key": "API secret key (sk-…) — rotate; source from env.",
        "jwt": "JWT literal — if it is a real signed token, it is a credential; do not commit.",
        "bearer-token": "Bearer token literal — source from env; rotate if real.",
        "slack-webhook": "Slack webhook URL with token — rotate; store as a secret.",
    }.get(rid, "Possible secret.")
    if cls == "test":
        base += " In a test file: use a fake fixture, and delete throwaway test scripts after running."
    elif cls == "notebook":
        base += " Notebook outputs can embed secrets too — clear outputs before saving."
    return base


def check_gitignore(root):
    gi = os.path.join(root, ".gitignore")
    if not os.path.isfile(gi):
        return {"present": False, "missing": list(_GITIGNORE_WANT),
                "note": "No .gitignore — .env/keys/credentials can be staged and committed."}
    try:
        with open(gi, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return {"present": True, "missing": [], "note": "unreadable"}
    missing = [name for name, rx in _GITIGNORE_WANT.items() if not rx.search(text)]
    return {"present": True, "missing": missing,
            "note": "All key secret paths covered." if not missing
                    else "Add these so secrets are never staged."}


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def scan(root):
    findings, scanned, scratch = [], 0, []
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    for full in iter_files(root):
        ext = os.path.splitext(full)[1].lower()
        if ext in _BINARY_EXT:
            continue
        try:
            if os.path.getsize(full) > 2_000_000:
                continue
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if "\x00" in text[:1024]:
            continue
        scanned += 1
        rel = os.path.relpath(full, base)
        cls = _classify(os.path.basename(full))
        for f in scan_text(rel, text, cls):
            findings.append(f)
        if _SCRATCH_RE.search(rel):
            scratch.append(rel)

    findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f["file"], f["line"]))
    report = {
        "root": root, "files_scanned": scanned, "finding_count": len(findings),
        "findings": findings,
        "gitignore": check_gitignore(base if os.path.isdir(root) else base),
        "scratch_files": scratch,
        "note": "High-signal bounded scan; secret VALUES are redacted. Deep entropy/"
                "history scanning needs gitleaks/trufflehog. If any secret was ever "
                "committed, ROTATE it — removing it from history is not enough.",
    }
    return report


def main(argv):
    ap = argparse.ArgumentParser(description="Dependency-free secret-leak scanner (ray-cloak).")
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument("--strict", action="store_true",
                    help="exit 3 if any CRITICAL/HIGH finding exists (pre-commit gate)")
    args = ap.parse_args(argv)
    if not os.path.exists(args.path):
        sys.stderr.write("error: no such path: {}\n".format(args.path))
        return 2

    report = scan(args.path)
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("Files scanned: {}  |  secret findings: {}".format(
            report["files_scanned"], report["finding_count"]))
        for f in report["findings"]:
            print("  [{}] {}:{}  {}  — {}".format(
                f["severity"], f["file"], f["line"], f["rule"], f["message"]))
            print("        evidence: {}".format(f["evidence"]))
        gi = report["gitignore"]
        if not gi.get("present") or gi.get("missing"):
            print("  .gitignore: {}".format(gi.get("note")))
            if gi.get("missing"):
                print("             missing coverage: {}".format(", ".join(gi["missing"])))
        if report["scratch_files"]:
            print("  throwaway-looking files (delete if temporary, and confirm): {}".format(
                ", ".join(report["scratch_files"])))
        print("\n({})".format(report["note"]))

    if args.strict:
        worst = min((_SEV_ORDER.get(f["severity"], 9) for f in report["findings"]), default=9)
        if worst <= _SEV_ORDER["HIGH"]:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
