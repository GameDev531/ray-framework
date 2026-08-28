#!/usr/bin/env python3
"""Ray Framework finding validator.

Validates finding JSON files (and, with --insights, insights.jsonl / execution
logs) against schema.json — the single source of truth every Ray skill
references. Exit code is non-zero if any file fails, so a harness can gate a
stage on it.

Usage:
    python3 scripts/ray_validate.py workspace/findings/*.json
    python3 scripts/ray_validate.py --insights workspace/insights.jsonl
    python3 scripts/ray_validate.py --self-test        # run the built-in gate tests

Requires: jsonschema (pip install jsonschema). Falls back to a structural check
(required keys + enum membership + the four allOf gates, implemented directly)
when jsonschema is not installed, so it still runs in a bare environment.
"""
import json
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)  # scripts/ -> repo root, where schema.json lives
SCHEMA_PATH = os.path.join(REPO, "schema.json")


def load_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------- fallback gates
def _outcome(entry):
    if not isinstance(entry, dict):
        return None
    if "outcome" in entry:
        return entry["outcome"]
    if entry.get("passes") is False:
        return "FAIL"
    if entry.get("fires") is True:
        return "APPLIES"
    return None


def fallback_check(obj):
    """Minimal structural + gate check used when jsonschema is unavailable."""
    errs = []
    for key in ("id", "title", "description", "severity", "code_paths", "status", "history"):
        if key not in obj:
            errs.append(f"missing required key: {key}")
    tc = obj.get("triage_checklist")
    if isinstance(tc, dict):
        fails = [k for k, v in tc.items() if _outcome(v) == "FAIL"]
        unknowns = [k for k, v in tc.items() if _outcome(v) == "UNKNOWN"]
        if fails and obj.get("status") != "FALSE_POSITIVE":
            errs.append(f"triage FAIL on non-FALSE_POSITIVE finding ({', '.join(fails)})")
        if obj.get("status") == "VALID" and (fails or unknowns):
            errs.append("VALID finding has FAIL/UNKNOWN triage entries")
    if obj.get("patch_status") == "VERIFIED_SECURE":
        if obj.get("reattack_status") != "failed_to_bypass":
            errs.append("VERIFIED_SECURE without reattack_status=failed_to_bypass")
        variants = obj.get("reattack_variants") or []
        if len(variants) < 3 or any(v.get("triggered") for v in variants):
            errs.append("VERIFIED_SECURE without >=3 variants all triggered=false")
    if obj.get("status") == "DUPLICATE" and "duplicate_of" not in obj:
        errs.append("DUPLICATE without duplicate_of")
    if obj.get("discovery_commit") == "":
        errs.append("discovery_commit is empty string (must be omitted in degraded mode)")
    return errs


def validate_one(obj, validator):
    if validator is not None:
        return [e.message for e in sorted(validator.iter_errors(obj), key=str)]
    return fallback_check(obj)


def build_validator(schema):
    try:
        import jsonschema
        return jsonschema.Draft202012Validator(schema)
    except Exception:
        return None


# ------------------------------------------------------------------- self-test
def self_test():
    schema = load_schema()
    v = build_validator(schema)
    ok = True

    def expect(name, obj, should_pass):
        nonlocal ok
        errs = validate_one(obj, v)
        passed = not errs
        mark = "ok" if passed == should_pass else "FAIL"
        if passed != should_pass:
            ok = False
        detail = "" if passed == should_pass else f"  <- errs={errs}"
        print(f"  [{mark}] {name} (expected {'pass' if should_pass else 'reject'}){detail}")

    base_hist = [{"stage": "researcher", "action": "created", "pass_number": 1,
                  "timestamp": "2026-08-28T00:00:00Z"}]
    good = {
        "id": "a", "title": "SQLi in login", "description": "d", "severity": "HIGH",
        "code_paths": ["src/auth.py:42"], "status": "PROVISIONALLY_VALID", "history": base_hist,
    }
    print("Gate self-test:")
    expect("minimal valid finding", good, True)
    expect("missing severity", {k: x for k, x in good.items() if k != "severity"}, False)
    expect("bad severity enum", {**good, "severity": "SUPER"}, False)

    fp = {**good, "status": "FALSE_POSITIVE",
          "triage_checklist": {k: {"outcome": "PASS"} for k in TRIAGE_KEYS}}
    fp["triage_checklist"]["require_strict_reproducibility"] = {"outcome": "FAIL", "reason": "1-in-a-million race"}
    expect("FAIL allowed on FALSE_POSITIVE", fp, True)

    bad_fail = {**good, "status": "VALID",
                "triage_checklist": {k: {"outcome": "PASS"} for k in TRIAGE_KEYS}}
    bad_fail["triage_checklist"]["avoid_pedantic_linting"] = {"outcome": "FAIL", "reason": "x"}
    expect("FAIL rejected on VALID", bad_fail, False)

    valid_unknown = {**good, "status": "VALID",
                     "triage_checklist": {k: {"outcome": "PASS"} for k in TRIAGE_KEYS}}
    valid_unknown["triage_checklist"]["intrinsic_security_flaws"] = {"outcome": "UNKNOWN", "reason": "x"}
    expect("UNKNOWN rejected on VALID", valid_unknown, False)

    vs_ok = {**good, "patch_status": "VERIFIED_SECURE", "reattack_status": "failed_to_bypass",
             "reattack_variants": [{"description": f"v{i}", "triggered": False} for i in range(3)]}
    expect("VERIFIED_SECURE with 3 clean variants", vs_ok, True)

    vs_short = {**good, "patch_status": "VERIFIED_SECURE", "reattack_status": "failed_to_bypass",
                "reattack_variants": [{"description": "v", "triggered": False}]}
    expect("VERIFIED_SECURE with <3 variants rejected", vs_short, False)

    vs_trig = {**good, "patch_status": "VERIFIED_SECURE", "reattack_status": "failed_to_bypass",
               "reattack_variants": [{"description": f"v{i}", "triggered": i == 0} for i in range(3)]}
    expect("VERIFIED_SECURE with a triggered variant rejected", vs_trig, False)

    dup = {**good, "status": "DUPLICATE"}
    expect("DUPLICATE without duplicate_of rejected", dup, False)

    print("jsonschema backend" if v is not None else "fallback backend (install jsonschema for full coverage)")
    return ok


TRIAGE_KEYS = [
    "ignore_hypothetical_misuse", "ignore_missing_hygiene", "require_strict_reproducibility",
    "avoid_pedantic_linting", "no_security_flaw_stretching", "evaluate_questionable_file_paths",
    "ignore_resource_exhaustion_dos", "intrinsic_security_flaws", "verify_mitigations_pragmatically",
    "refine_code_paths_strictly", "ignore_simd_vector_padding", "ensure_source_code_coherence",
    "verify_attacker_control_of_source",
]


def main(argv):
    if "--self-test" in argv:
        sys.exit(0 if self_test() else 1)

    insights = False
    paths = []
    for a in argv[1:]:
        if a == "--insights":
            insights = True
        else:
            paths.append(a)
    if not paths:
        print(__doc__)
        sys.exit(2)

    schema = load_schema()
    v = build_validator(schema)
    failures = 0
    checked = 0
    for p in paths:
        if insights:
            with open(p, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    checked += 1
                    try:
                        json.loads(line)
                    except Exception as e:
                        failures += 1
                        print(f"{p}:{n}: invalid JSON ({e})")
            continue
        checked += 1
        try:
            obj = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            failures += 1
            print(f"{p}: invalid JSON ({e})")
            continue
        errs = validate_one(obj, v)
        if errs:
            failures += 1
            for e in errs:
                print(f"{p}: {e}")
    print(f"\n{checked} file(s) checked, {failures} failed"
          f"{'' if v is not None else '  [fallback backend]'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main(sys.argv)
