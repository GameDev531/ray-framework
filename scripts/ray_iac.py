#!/usr/bin/env python3
"""
ray_iac.py — dependency-free Infrastructure-as-Code misconfig scanner for ray-terrain.

Flags high-signal, high-confidence misconfigurations in IaC sources using the
Python standard library alone (no tfsec/checkov/pyyaml required). It is a
deliberately *bounded* scanner: it catches the patterns that are unambiguous and
almost always wrong — open-to-the-world ingress, wildcard IAM, public storage,
privileged containers, hardcoded secrets — and is honest that deep semantic
analysis (full HCL/YAML graphs, cross-resource reasoning) needs a real tool like
tfsec, checkov, trivy, or kube-score, which ray-terrain drives when present.

Detection is line-oriented so every finding carries a `file:line`, and works
uniformly across Terraform HCL/JSON, CloudFormation, Kubernetes, Dockerfiles, and
compose. A per-file gate keeps it from flagging unrelated YAML/JSON.

Usage:
  python3 ray_iac.py <file-or-dir> [--json]
"""

import argparse
import json
import os
import re
import sys

# Each rule: (id, severity, compiled-regex, message). Matched per line.
# Written to be uniform across HCL (`= `), YAML/JSON (`: `) syntaxes.
_RULES = [
    ("open-ingress-world", "HIGH",
     re.compile(r"0\.0\.0\.0/0"),
     "Resource open to the entire internet (0.0.0.0/0) — scope the CIDR to known ranges."),
    ("open-ingress-world-v6", "HIGH",
     re.compile(r'"?::/0"?'),
     "Resource open to the entire IPv6 internet (::/0) — scope it."),
    ("iam-wildcard-action", "HIGH",
     re.compile(r'"?[Aa]ction"?\s*[:=]\s*\[?\s*"\*"'),
     "IAM policy grants Action \"*\" — grant only the specific actions needed (least privilege)."),
    ("iam-wildcard-resource", "MEDIUM",
     re.compile(r'"?[Rr]esource"?\s*[:=]\s*\[?\s*"\*"'),
     "IAM policy applies to Resource \"*\" — scope to specific ARNs."),
    ("s3-public-acl", "HIGH",
     re.compile(r'"?acl"?\s*[:=]\s*"(public-read|public-read-write)"'),
     "Storage bucket ACL is public — make it private and use scoped policies/signed URLs."),
    ("public-db", "HIGH",
     re.compile(r'publicly_accessible"?\s*[:=]\s*true'),
     "Database is publicly accessible — place it in a private subnet."),
    ("privileged-container", "HIGH",
     re.compile(r'privileged"?\s*[:=]\s*true'),
     "Privileged container — drop it; grant only the specific capabilities required."),
    ("allow-priv-escalation", "MEDIUM",
     re.compile(r'allowPrivilegeEscalation"?\s*[:=]\s*true'),
     "allowPrivilegeEscalation: true — set it false in the securityContext."),
    ("host-network", "MEDIUM",
     re.compile(r'hostNetwork"?\s*[:=]\s*true'),
     "Pod uses the host network namespace — avoid unless strictly required."),
    ("host-path", "MEDIUM",
     re.compile(r'"?hostPath"?\s*:'),
     "Pod mounts a host path — can escape isolation; avoid or tightly constrain."),
    ("unencrypted", "MEDIUM",
     re.compile(r'encrypted"?\s*[:=]\s*false'),
     "Encryption explicitly disabled — enable encryption at rest."),
    ("k8s-run-as-root", "LOW",
     re.compile(r'runAsNonRoot"?\s*[:=]\s*false'),
     "runAsNonRoot: false — run the container as a non-root user."),
]

# Secret rule handled specially (needs a value-shape check to avoid var refs).
_SECRET_RE = re.compile(
    r'(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|token|private[_-]?key)'
    r'"?\s*[:=]\s*(["\']?)([^"\'\n]{6,})\2')
_SECRET_IGNORE = re.compile(
    r'(var\.|local\.|data\.|module\.|\$\{|!Ref|!Sub|!GetAtt|secretKeyRef|valueFrom|'
    r'fromSecret|<[^>]+>|CHANGE_?ME|changeme|example|xxx+|\*{3,}|null|""|\'\')', re.IGNORECASE)

# Dockerfile-specific line rules.
_DOCKER_RULES = [
    ("docker-user-root", "LOW", re.compile(r"^\s*USER\s+root\b"),
     "Dockerfile sets USER root — run as a non-root user."),
    ("docker-latest-tag", "LOW", re.compile(r"^\s*FROM\s+\S+:latest\b"),
     "Base image pinned to :latest — pin a specific digest/version for reproducibility."),
    ("docker-add-url", "MEDIUM", re.compile(r"^\s*ADD\s+https?://"),
     "ADD from a URL — use COPY of a verified artifact; ADD fetches unverified content."),
]

_SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build", "target", ".terraform"}
_IAC_MARKERS = re.compile(
    r'(apiVersion:|"?Resources"?\s*[:=]|resource\s+"|provider\s+"|"AWSTemplateFormatVersion"|'
    r'^services:|^\s*kind:\s|terraform\s*\{)', re.MULTILINE)


def _is_iac_file(path, text):
    base = os.path.basename(path).lower()
    if base == "dockerfile" or base.endswith(".dockerfile"):
        return "dockerfile"
    if base.endswith(".tf") or base.endswith(".tf.json"):
        return "terraform"
    if base.startswith("docker-compose") or base.startswith("compose"):
        return "compose"
    if base.endswith((".yaml", ".yml", ".json")):
        # Only treat as IaC if it structurally looks like it, to avoid noise.
        if _IAC_MARKERS.search(text):
            return "generic-iac"
    return None


def scan_text(path, text, kind):
    findings = []
    lines = text.splitlines()
    has_user = False
    for i, line in enumerate(lines, 1):
        if kind == "dockerfile":
            if re.match(r"^\s*USER\s", line):
                has_user = True
            for rid, sev, rx, msg in _DOCKER_RULES:
                if rx.search(line):
                    findings.append(_mk(path, i, rid, sev, msg, line))
        for rid, sev, rx, msg in _RULES:
            if rx.search(line):
                findings.append(_mk(path, i, rid, sev, msg, line))
        m = _SECRET_RE.search(line)
        if m and not _SECRET_IGNORE.search(line):
            findings.append(_mk(path, i, "hardcoded-secret", "HIGH",
                                "Hardcoded credential/secret in IaC — move it to a secret manager / variable.",
                                line, redact=True))
    if kind == "dockerfile" and not has_user and lines:
        findings.append(_mk(path, 1, "docker-no-user", "LOW",
                            "Dockerfile never sets USER — the image runs as root by default.", ""))
    return findings


def _mk(path, line, rid, sev, msg, evidence, redact=False):
    ev = evidence.strip()
    if redact and len(ev) > 24:
        ev = ev[:18] + "…(redacted)"
    return {"file": path, "line": line, "rule": rid, "severity": sev,
            "message": msg, "evidence": ev[:160]}


def iter_iac_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def scan(root):
    results, scanned = [], 0
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    for full in iter_iac_files(root):
        try:
            if os.path.getsize(full) > 2_000_000:
                continue
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        kind = _is_iac_file(full, text)
        if not kind:
            continue
        scanned += 1
        rel = os.path.relpath(full, base)
        for f in scan_text(rel, text, kind):
            results.append(f)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    results.sort(key=lambda f: (order.get(f["severity"], 9), f["file"], f["line"]))
    return {"root": root, "files_scanned": scanned, "finding_count": len(results),
            "findings": results,
            "note": "High-signal bounded scan; deep HCL/YAML semantics need tfsec/checkov/trivy/kube-score."}


def main(argv):
    ap = argparse.ArgumentParser(description="Dependency-free IaC misconfig scanner (ray-terrain).")
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args(argv)
    if not os.path.exists(args.path):
        sys.stderr.write("error: no such path: {}\n".format(args.path))
        return 2
    report = scan(args.path)
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("IaC files scanned: {}  |  findings: {}".format(
            report["files_scanned"], report["finding_count"]))
        for f in report["findings"]:
            print("  [{}] {}:{}  {}  — {}".format(
                f["severity"], f["file"], f["line"], f["rule"], f["message"]))
        print("\n({})".format(report["note"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
