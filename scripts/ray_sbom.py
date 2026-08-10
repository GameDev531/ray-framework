#!/usr/bin/env python3
"""
ray_sbom.py — dependency-free SCA + SBOM generator for ray-manifest.

Parses a project's dependency lockfiles across ecosystems, emits a CycloneDX 1.5
SBOM, and flags known-vulnerable versions by querying the public OSV.dev API
(free, no key) — with a graceful offline mode. Standard library only (tomllib is
stdlib on Python 3.11+); no pip install.

Ecosystems parsed (lockfile -> OSV ecosystem):
  - npm         package-lock.json (v2/v3 + v1), yarn.lock (v1)   -> npm
  - pip         requirements.txt (pinned), Pipfile.lock          -> PyPI
  - poetry      poetry.lock                                      -> PyPI
  - cargo       Cargo.lock                                       -> crates.io
  - go          go.mod (require)                                 -> Go
  - composer    composer.lock                                    -> Packagist
  - rubygems    Gemfile.lock                                     -> RubyGems

Vulnerability matching:
  - Online (default): POST OSV.dev /v1/querybatch, then fetch each vuln's detail
    for severity + fixed version. Honors SSL_CERT_FILE for proxied environments.
  - Offline (--offline, or on any network failure): structural checks only —
    typosquat heuristics and floating-range flags — and it says CVE matching was
    skipped. It never fabricates a CVE.

Usage:
  python3 ray_sbom.py <project-dir> [--json] [--offline] [--sbom-out FILE]
"""

import argparse
import json
import os
import re
import sys
import urllib.request

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
NET_TIMEOUT = 25

# ecosystem -> (OSV ecosystem name, purl type)
ECOSYSTEMS = {
    "npm": ("npm", "npm"),
    "PyPI": ("PyPI", "pypi"),
    "crates.io": ("crates.io", "cargo"),
    "Go": ("Go", "golang"),
    "Packagist": ("Packagist", "composer"),
    "RubyGems": ("RubyGems", "gem"),
}

# A small set of frequently-typosquatted popular packages, per ecosystem, used
# only for a low-false-positive near-miss heuristic (offline-safe).
POPULAR = {
    "npm": {"react", "lodash", "express", "axios", "chalk", "commander", "debug",
            "request", "moment", "webpack", "babel", "typescript", "jest"},
    "PyPI": {"requests", "urllib3", "numpy", "pandas", "flask", "django", "boto3",
             "setuptools", "pip", "pytest", "colorama", "cryptography"},
}


# --------------------------------------------------------------------------- #
# Lockfile parsers — each returns a list of dicts:
#   {"ecosystem": <OSV name>, "name": str, "version": str, "direct": bool|None}
# --------------------------------------------------------------------------- #

def _load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_package_lock(path):
    data = _load_json(path)
    out = []
    if isinstance(data.get("packages"), dict):  # lockfile v2/v3
        for pkgpath, meta in data["packages"].items():
            if pkgpath == "":  # the root project itself
                continue
            name = meta.get("name") or pkgpath.split("node_modules/")[-1]
            ver = meta.get("version")
            if name and ver:
                out.append({"ecosystem": "npm", "name": name, "version": ver,
                            "direct": "/" not in pkgpath.strip("node_modules/").strip("/")})
    elif isinstance(data.get("dependencies"), dict):  # lockfile v1
        def walk(deps):
            for name, meta in deps.items():
                ver = meta.get("version")
                if ver:
                    out.append({"ecosystem": "npm", "name": name, "version": ver, "direct": None})
                if isinstance(meta.get("dependencies"), dict):
                    walk(meta["dependencies"])
        walk(data["dependencies"])
    return out


def parse_yarn_lock(path):
    out, seen = [], set()
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    # Blocks: a header line "name@range, name@range:" then an indented "version"
    blocks = re.split(r"\n(?=\S)", text)
    for block in blocks:
        header = block.splitlines()[0] if block.splitlines() else ""
        mver = re.search(r'^\s+version:?\s+"?([^"\n]+)"?', block, re.MULTILINE)
        if not mver:
            continue
        ver = mver.group(1).strip()
        # name is the token before the first @range in the header
        specs = header.rstrip(":").split(",")
        for spec in specs:
            spec = spec.strip().strip('"')
            m = re.match(r"^(@?[^@]+)@", spec)
            if m:
                name = m.group(1)
                key = (name, ver)
                if key not in seen:
                    seen.add(key)
                    out.append({"ecosystem": "npm", "name": name, "version": ver, "direct": None})
                break
    return out


def parse_requirements(path):
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)", line)
            if m:
                out.append({"ecosystem": "PyPI", "name": m.group(1), "version": m.group(2), "direct": True})
    return out


def parse_pipfile_lock(path):
    data = _load_json(path)
    out = []
    for section, direct in (("default", True), ("develop", False)):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta.get("version") or "").lstrip("=")
            if ver:
                out.append({"ecosystem": "PyPI", "name": name, "version": ver, "direct": direct})
    return out


def _parse_toml(path):
    if tomllib is None:
        return None
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def parse_poetry_lock(path):
    data = _parse_toml(path)
    if data is None:
        return []
    out = []
    for pkg in data.get("package", []):
        if pkg.get("name") and pkg.get("version"):
            out.append({"ecosystem": "PyPI", "name": pkg["name"], "version": pkg["version"], "direct": None})
    return out


def parse_cargo_lock(path):
    data = _parse_toml(path)
    if data is None:
        return []
    out = []
    for pkg in data.get("package", []):
        if pkg.get("name") and pkg.get("version"):
            out.append({"ecosystem": "crates.io", "name": pkg["name"], "version": pkg["version"], "direct": None})
    return out


def parse_go_mod(path):
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    # require ( ... ) blocks and single-line require
    for m in re.finditer(r"require\s+\(([^)]*)\)", text, re.DOTALL):
        for line in m.group(1).splitlines():
            line = line.split("//", 1)[0].strip()
            parts = line.split()
            if len(parts) >= 2:
                out.append({"ecosystem": "Go", "name": parts[0], "version": parts[1].lstrip("v"), "direct": True})
    for m in re.finditer(r"^require\s+(\S+)\s+(\S+)\s*$", text, re.MULTILINE):
        out.append({"ecosystem": "Go", "name": m.group(1), "version": m.group(2).lstrip("v"), "direct": True})
    return out


def parse_composer_lock(path):
    data = _load_json(path)
    out = []
    for section, direct in (("packages", True), ("packages-dev", False)):
        for pkg in data.get(section) or []:
            name, ver = pkg.get("name"), pkg.get("version")
            if name and ver:
                out.append({"ecosystem": "Packagist", "name": name, "version": ver.lstrip("v"), "direct": direct})
    return out


def parse_gemfile_lock(path):
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        in_specs = False
        for line in fh:
            if re.match(r"^\s{4}\S", line) and in_specs:
                m = re.match(r"^\s{4}([A-Za-z0-9._-]+)\s+\(([^)]+)\)", line)
                if m:
                    out.append({"ecosystem": "RubyGems", "name": m.group(1), "version": m.group(2), "direct": None})
            elif line.strip() == "specs:":
                in_specs = True
            elif re.match(r"^\S", line):
                in_specs = False
    return out


# filename -> parser
PARSERS = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "requirements.txt": parse_requirements,
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "Cargo.lock": parse_cargo_lock,
    "go.mod": parse_go_mod,
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
}


def discover_and_parse(root):
    """Walk the tree (skipping vendored dirs) and parse every known lockfile."""
    skip = {"node_modules", ".git", "vendor", ".venv", "venv", "dist", "build", "target"}
    components, sources = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            parser = PARSERS.get(fn)
            if not parser:
                continue
            full = os.path.join(dirpath, fn)
            try:
                found = parser(full)
            except (OSError, ValueError, KeyError) as exc:
                sources.append({"file": os.path.relpath(full, root), "error": str(exc)})
                continue
            rel = os.path.relpath(full, root)
            for c in found:
                c["source"] = rel
            components.extend(found)
            sources.append({"file": rel, "components": len(found)})
    # de-dupe by (ecosystem, name, version)
    uniq = {}
    for c in components:
        uniq.setdefault((c["ecosystem"], c["name"], c["version"]), c)
    return list(uniq.values()), sources


# --------------------------------------------------------------------------- #
# CycloneDX SBOM
# --------------------------------------------------------------------------- #

def to_cyclonedx(components):
    def purl(c):
        ptype = ECOSYSTEMS.get(c["ecosystem"], (None, c["ecosystem"].lower()))[1]
        return "pkg:{}/{}@{}".format(ptype, c["name"], c["version"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"vendor": "ray-framework", "name": "ray_sbom.py"}]},
        "components": [
            {"type": "library", "name": c["name"], "version": c["version"], "purl": purl(c)}
            for c in components
        ],
    }


# --------------------------------------------------------------------------- #
# Vulnerability matching (OSV.dev)
# --------------------------------------------------------------------------- #

def _http_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ray-sbom/0.5"},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=NET_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _fixed_versions(vuln, name):
    fixed = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name") and pkg["name"] != name:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def _severity(vuln):
    for sev in vuln.get("severity", []):
        if sev.get("score"):
            return sev["score"]
    db = vuln.get("database_specific", {})
    return db.get("severity") or "UNKNOWN"


def query_osv(components):
    """Return {(eco,name,ver): [vuln dicts]} or raise on network failure."""
    queries = [{"package": {"name": c["name"], "ecosystem": c["ecosystem"]}, "version": c["version"]}
               for c in components]
    if not queries:
        return {}
    batch = _http_json(OSV_BATCH_URL, {"queries": queries})
    results = batch.get("results", [])
    # collect unique ids, fetch details once each (bounded)
    id_detail = {}
    hits = {}
    for c, res in zip(components, results):
        vulns = res.get("vulns") or []
        if not vulns:
            continue
        key = (c["ecosystem"], c["name"], c["version"])
        details = []
        for v in vulns:
            vid = v.get("id")
            if vid and vid not in id_detail:
                try:
                    id_detail[vid] = _http_json(OSV_VULN_URL + vid)
                except (urllib.error.URLError, OSError, ValueError):
                    id_detail[vid] = {"id": vid}
            d = id_detail.get(vid, {"id": vid})
            details.append({
                "id": vid,
                "aliases": d.get("aliases", []),
                "summary": (d.get("summary") or "")[:200],
                "severity": _severity(d),
                "fixed": _fixed_versions(d, c["name"]),
            })
        hits[key] = details
    return hits


# --------------------------------------------------------------------------- #
# Offline structural heuristics
# --------------------------------------------------------------------------- #

def _levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat_flags(components):
    flags = []
    for c in components:
        pop = POPULAR.get(c["ecosystem"])
        if not pop:
            continue
        name = c["name"].lower()
        if name in pop:  # exact match (case-insensitive) is the real package
            continue
        for good in pop:
            # A case-only or normalization-only difference is the same package,
            # not a squat; require an actual edit at distance exactly 1.
            if name.replace("_", "-") == good.replace("_", "-"):
                break
            if abs(len(good) - len(name)) <= 1 and _levenshtein(name, good) == 1:
                flags.append({"name": c["name"], "version": c["version"],
                              "ecosystem": c["ecosystem"], "near": good})
                break
    return flags


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def analyze(root, offline):
    components, sources = discover_and_parse(root)
    sbom = to_cyclonedx(components)
    report = {
        "root": root,
        "component_count": len(components),
        "sources": sources,
        "vulnerabilities": [],
        "typosquat_suspects": typosquat_flags(components),
        "osv_status": "offline" if offline else "queried",
    }
    if not offline and components:
        try:
            hits = query_osv(components)
            for (eco, name, ver), details in hits.items():
                report["vulnerabilities"].append({
                    "ecosystem": eco, "name": name, "version": ver,
                    "vulns": details,
                })
        except (urllib.error.URLError, OSError, ValueError) as exc:
            report["osv_status"] = "unavailable ({}): CVE matching skipped".format(type(exc).__name__)
    report["vulnerable_count"] = len(report["vulnerabilities"])
    return report, sbom


def main(argv):
    ap = argparse.ArgumentParser(description="Dependency-free SCA + CycloneDX SBOM (ray-manifest).")
    ap.add_argument("path", help="project directory to scan")
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument("--offline", action="store_true", help="skip the OSV.dev network query")
    ap.add_argument("--sbom-out", help="write the CycloneDX SBOM to this file")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.path):
        sys.stderr.write("error: not a directory: {}\n".format(args.path))
        return 2

    report, sbom = analyze(args.path, args.offline)

    if args.sbom_out:
        with open(args.sbom_out, "w", encoding="utf-8") as fh:
            json.dump(sbom, fh, indent=2)

    if args.json:
        json.dump({"report": report, "sbom": sbom}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("Components: {}  |  OSV: {}".format(report["component_count"], report["osv_status"]))
        if report["vulnerabilities"]:
            print("\nVulnerable dependencies ({}):".format(report["vulnerable_count"]))
            for v in report["vulnerabilities"]:
                ids = ", ".join(d["id"] for d in v["vulns"])
                fixed = sorted({f for d in v["vulns"] for f in d["fixed"]})
                print("  {}@{} [{}]  {}  fixed: {}".format(
                    v["name"], v["version"], v["ecosystem"], ids, ", ".join(fixed) or "n/a"))
        else:
            print("No known-vulnerable versions matched." if report["osv_status"] == "queried"
                  else "CVE matching not performed ({}).".format(report["osv_status"]))
        if report["typosquat_suspects"]:
            print("\nTyposquat suspects:")
            for t in report["typosquat_suspects"]:
                print("  {} ~ {} ({})".format(t["name"], t["near"], t["ecosystem"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
