#!/usr/bin/env python3
"""Ray Framework reference orchestrator — the sync/pin/archive mechanics.

This is the drop-in reference implementation of the Pass Lifecycle Contract that
ray-conductor/SKILL.md describes. It does the deterministic, non-LLM parts:

    sync   — detect VCS, compute a content-hashed SNAPSHOT_ID
    pin     — copy the target to an immutable snapshot, strip VCS metadata,
              write the .ray_snapshot_id sentinel
    state   — create/advance workspace/.ray_state.json (the ONLY writer that
              creates it), append to snapshot_history, set active_snapshot
    archive — snapshot the pass's findings into workspace/archive/

The LLM stages themselves (prism, blueprint, ... , chronicle) are driven by the
agent following ray-conductor/SKILL.md; this script exists so the state/snapshot
bookkeeping is deterministic and identical every run.

Usage:
    python3 bin/ray-conductor.py begin  --target . [--state .] [--sync]
    python3 bin/ray-conductor.py archive --state . --pass 1
    python3 bin/ray-conductor.py show    --state .
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

WS = "workspace"
STATE_FILE = os.path.join(WS, ".ray_state.json")
SENTINEL = ".ray_snapshot_id"


def _run(cmd, cwd):
    try:
        out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=60)
        return out.returncode, out.stdout.strip(), out.stderr.strip()
    except Exception:
        return 1, "", "exec-failed"


def detect_vcs(root):
    if os.path.isdir(os.path.join(root, ".git")):
        return "git"
    if os.path.isdir(os.path.join(root, ".hg")):
        return "hg"
    if os.path.isdir(os.path.join(root, ".repo")):
        return "repo"
    return "none"


def _iter_files(root):
    skip = {".git", ".hg", ".repo", "node_modules", "vendor", "__pycache__",
            WS, ".ray_snapshot_id"}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip]
        for fn in sorted(fns):
            yield os.path.join(dp, fn)


def content_hash(root):
    """Deterministic 16-hex content hash of the tree (path + bytes)."""
    h = hashlib.sha256()
    for path in sorted(_iter_files(root)):
        rel = os.path.relpath(path, root)
        h.update(rel.encode("utf-8", "replace"))
        h.update(b"\0")
        try:
            with open(path, "rb") as fh:
                h.update(fh.read())
        except Exception:
            h.update(b"<unreadable>")
        h.update(b"\0")
    return h.hexdigest()[:16]


def compute_snapshot_id(root, vcs):
    ch = content_hash(root)
    if vcs == "git":
        rc, rev, _ = _run(["git", "rev-parse", "HEAD"], root)
        rc2, dirty, _ = _run(["git", "status", "--porcelain"], root)
        if rc == 0 and rev:
            return f"{rev}+content:{ch}" if (rc2 == 0 and dirty) else rev
    if vcs == "hg":
        rc, rev, _ = _run(["hg", "id", "-i"], root)
        if rc == 0 and rev:
            clean = not rev.endswith("+")
            return rev if clean else f"{rev.rstrip('+')}+content:{ch}"
    return f"content:{ch}"


def load_state(state_root):
    p = os.path.join(state_root, STATE_FILE)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return {"pass_number": 0, "snapshot_history": []}


def save_state(state_root, state):
    d = os.path.join(state_root, WS)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(state_root, STATE_FILE)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, p)


def pin_snapshot(target_root, state_root, snapshot_id):
    dest = os.path.join(state_root, WS, "snapshots", snapshot_id)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    def ignore(_dir, names):
        return [n for n in names if n in {".git", ".hg", ".repo", WS}]

    shutil.copytree(target_root, dest, ignore=ignore, symlinks=True)
    with open(os.path.join(dest, SENTINEL), "w", encoding="utf-8") as fh:
        fh.write(snapshot_id)
    return os.path.abspath(dest)


def cmd_begin(args):
    state_root = os.path.abspath(args.state)
    target = os.path.abspath(args.target)
    state = load_state(state_root)
    n = state.get("pass_number", 0) + 1

    if args.sync:
        vcs = detect_vcs(target)
        sid = compute_snapshot_id(target, vcs)
        root = pin_snapshot(target, state_root, sid)
        state["pass_number"] = n
        state["active_snapshot"] = {
            "root": root, "snapshot_id": sid, "snapshot_pinned": True,
            "pass": n, "vcs_type": vcs,
        }
        state.setdefault("snapshot_history", []).append(sid)
        save_state(state_root, state)
        print(json.dumps({"pass": n, "snapshot_id": sid, "snapshot_root": root,
                          "vcs_type": vcs, "mode": "PINNED"}, indent=2))
    else:
        state["pass_number"] = n
        state.pop("active_snapshot", None)
        save_state(state_root, state)
        print(json.dumps({"pass": n, "mode": "MODE-OFF",
                          "note": "no snapshot pinned; run with --sync for drift detection"},
                         indent=2))


def cmd_archive(args):
    state_root = os.path.abspath(args.state)
    n = args.pass_number
    findings = os.path.join(state_root, WS, "findings")
    dest = os.path.join(state_root, WS, "archive", f"findings_pass_{n}")
    os.makedirs(dest, exist_ok=True)
    copied = 0
    if os.path.isdir(findings):
        for fn in os.listdir(findings):
            if fn.endswith(".json"):
                shutil.copy2(os.path.join(findings, fn), os.path.join(dest, fn))
                copied += 1
    print(json.dumps({"archived_pass": n, "findings_copied": copied, "dest": dest}, indent=2))


def cmd_show(args):
    state_root = os.path.abspath(args.state)
    print(json.dumps(load_state(state_root), indent=2, sort_keys=True))


def main():
    ap = argparse.ArgumentParser(description="Ray reference orchestrator (sync/pin/archive)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("begin", help="start a pass: advance state, optionally pin a snapshot")
    b.add_argument("--target", default=".")
    b.add_argument("--state", default=".")
    b.add_argument("--sync", action="store_true")
    b.set_defaults(func=cmd_begin)

    a = sub.add_parser("archive", help="archive a pass's findings")
    a.add_argument("--state", default=".")
    a.add_argument("--pass", dest="pass_number", type=int, required=True)
    a.set_defaults(func=cmd_archive)

    s = sub.add_parser("show", help="print current state")
    s.add_argument("--state", default=".")
    s.set_defaults(func=cmd_show)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
