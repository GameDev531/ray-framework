#!/usr/bin/env python3
"""
ray_mcp_server.py — the Ray Framework's real tools, over MCP.

A dependency-free (stdlib-only) MCP server that exposes Ray's bundled helper
scripts as first-class tools an LLM calls directly, instead of narrating a Bash
invocation. The point is honesty: a tool call here either *executes* and returns
a result, or returns an error — there is no path for a model to "pretend" it ran.

Transport: MCP stdio — newline-delimited JSON-RPC 2.0 on stdin/stdout. Diagnostics
go to stderr only; stdout carries protocol messages exclusively.

It does not reimplement the helpers: each tool shells out to the existing
`ray_metadata.py` / `ray_memory.py` (and, when present, `ray_sbom.py` /
`ray_iac.py`) sitting beside this file, so the tool and the CLI can never drift.

Tools:
  - ray_metadata_extract(path, recurse?)      -> ray_metadata.py --json
  - ray_memory_recall(agent)                  -> ray_memory.py recall
  - ray_memory_add(agent, section, text)      -> ray_memory.py add
  - ray_memory_list()                         -> ray_memory.py list
  - ray_sbom_generate(path, offline?)         -> ray_sbom.py        (if bundled)
  - ray_iac_scan(path)                        -> ray_iac.py         (if bundled)
  - ray_arsenal_list(side?)                   -> ray_arsenal.py list (if bundled)
  - ray_arsenal_run(tool, target?, args?)     -> ray_arsenal.py run  (if bundled)
  - ray_secret_scan(path, strict?)            -> ray_secrets.py      (if bundled)

Run standalone for a smoke test:
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
                '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | python3 ray_mcp_server.py
"""

import json
import os
import subprocess
import sys

SERVER_NAME = "ray-tools"
SERVER_VERSION = "0.7.0"
# Echo the client's protocol version when given; otherwise advertise this one.
DEFAULT_PROTOCOL = "2025-06-18"
SUBPROCESS_TIMEOUT = 120

_HERE = os.path.dirname(os.path.abspath(__file__))


def _script(name):
    return os.path.join(_HERE, name)


def _log(msg):
    sys.stderr.write("[ray-mcp] {}\n".format(msg))
    sys.stderr.flush()


# --------------------------------------------------------------------------- #
# Tool implementations — each shells out to the bundled helper and returns
# (text, is_error). A missing optional helper returns a clear, non-fatal error.
# --------------------------------------------------------------------------- #

def _run(argv):
    """Run a helper subprocess; return (stdout, is_error)."""
    script = argv[0]
    if not os.path.exists(script):
        return ("tool unavailable: {} is not bundled in this Ray install".format(
            os.path.basename(script)), True)
    try:
        proc = subprocess.run(
            [sys.executable] + argv,
            capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return ("tool timed out after {}s".format(SUBPROCESS_TIMEOUT), True)
    except OSError as exc:
        return ("failed to run tool: {}".format(exc), True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        return ("tool exited {}: {}".format(proc.returncode, detail), True)
    return (proc.stdout, False)


def tool_metadata_extract(args):
    path = args.get("path")
    if not path:
        return ("missing required argument: path", True)
    argv = [_script("ray_metadata.py"), str(path), "--json"]
    if args.get("recurse"):
        argv.append("--recurse")
    return _run(argv)


def tool_memory_recall(args):
    agent = args.get("agent")
    if not agent:
        return ("missing required argument: agent", True)
    return _run([_script("ray_memory.py"), "recall", "--agent", str(agent)])


def tool_memory_add(args):
    for req in ("agent", "section", "text"):
        if not args.get(req):
            return ("missing required argument: {}".format(req), True)
    return _run([_script("ray_memory.py"), "add",
                 "--agent", str(args["agent"]),
                 "--section", str(args["section"]),
                 "--text", str(args["text"])])


def tool_memory_list(args):
    return _run([_script("ray_memory.py"), "list"])


def tool_sbom_generate(args):
    path = args.get("path")
    if not path:
        return ("missing required argument: path", True)
    argv = [_script("ray_sbom.py"), str(path), "--json"]
    if args.get("offline"):
        argv.append("--offline")
    return _run(argv)


def tool_iac_scan(args):
    path = args.get("path")
    if not path:
        return ("missing required argument: path", True)
    return _run([_script("ray_iac.py"), str(path), "--json"])


def tool_arsenal_list(args):
    argv = [_script("ray_arsenal.py"), "list", "--json"]
    side = args.get("side")
    if side:
        argv += ["--side", str(side)]
    return _run(argv)


def tool_arsenal_run(args):
    tool = args.get("tool")
    if not tool:
        return ("missing required argument: tool", True)
    argv = [_script("ray_arsenal.py"), "run", "--tool", str(tool), "--json"]
    target = args.get("target")
    if target:
        argv += ["--target", str(target)]
    extra = args.get("args") or []
    if not isinstance(extra, list):
        return ("argument 'args' must be an array of strings", True)
    if extra:
        # `--` ends option parsing so extra flags land in the `extra` positional.
        argv.append("--")
        argv += [str(a) for a in extra]
    return _run(argv)


def tool_secret_scan(args):
    path = args.get("path")
    if not path:
        return ("missing required argument: path", True)
    argv = [_script("ray_secrets.py"), str(path), "--json"]
    if args.get("strict"):
        argv.append("--strict")
    return _run(argv)


# name -> (schema, handler). Tools whose helper is not bundled still list and
# return a clean "tool unavailable" so discovery is stable across installs.
TOOLS = {
    "ray_metadata_extract": (
        {
            "description": "Extract document metadata (PDF /Info+XMP, Office docProps, "
                           "image EXIF) and harvest leaked paths/usernames/hosts from a "
                           "file or directory. Dependency-free (the FOCA method).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File or directory to inspect."},
                    "recurse": {"type": "boolean", "description": "Recurse into subdirectories."},
                },
                "required": ["path"],
            },
        },
        tool_metadata_extract,
    ),
    "ray_memory_recall": (
        {
            "description": "Read a Ray agent's curated cross-run memory "
                           "(~/.claude/ray-memory/<agent>.md). Empty is normal.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent": {"type": "string",
                                         "description": "Agent slug, e.g. reaver, bulwark, scrivener, vigil."}},
                "required": ["agent"],
            },
        },
        tool_memory_recall,
    ),
    "ray_memory_add": (
        {
            "description": "Append one high-signal lesson to a Ray agent's curated memory. "
                           "Refused if it would exceed the character cap (curate first).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent": {"type": "string"},
                    "section": {"type": "string", "description": "Section heading to file it under."},
                    "text": {"type": "string", "description": "The lesson, terse and durable."},
                },
                "required": ["agent", "section", "text"],
            },
        },
        tool_memory_add,
    ),
    "ray_memory_list": (
        {
            "description": "List Ray agents that have curated memory and each file's size.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        tool_memory_list,
    ),
    "ray_sbom_generate": (
        {
            "description": "Parse a project's dependency lockfiles into a CycloneDX SBOM and "
                           "flag known-vulnerable versions (OSV.dev), risky licenses, and "
                           "typosquats. Requires the ray_sbom helper (ray-manifest skill).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Project root to scan."},
                    "offline": {"type": "boolean", "description": "Skip the OSV.dev network query."},
                },
                "required": ["path"],
            },
        },
        tool_sbom_generate,
    ),
    "ray_iac_scan": (
        {
            "description": "Scan Infrastructure-as-Code (Terraform .tf.json, K8s/CFN JSON, "
                           "Dockerfile, compose) for high-signal misconfigurations. Requires "
                           "the ray_iac helper (ray-terrain skill).",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File or directory to scan."}},
                "required": ["path"],
            },
        },
        tool_iac_scan,
    ),
    "ray_arsenal_list": (
        {
            "description": "Probe which ray-siege arsenal tools (nmap, sqlmap, jwt_tool, "
                           "garak, semgrep, gitleaks, …) are actually installed, with "
                           "versions and a fallback for each absent one. Un-fakeable "
                           "capability discovery for the reaver/bulwark. Requires the "
                           "ray_arsenal helper (ray-siege).",
            "inputSchema": {
                "type": "object",
                "properties": {"side": {"type": "string", "enum": ["offense", "defense"],
                                        "description": "Filter to red-team or blue-team tools."}},
            },
        },
        tool_arsenal_list,
    ),
    "ray_arsenal_run": (
        {
            "description": "Drive one arsenal tool through the ray-siege gate: the target "
                           "must be loopback (127.0.0.0/8, ::1, localhost), no argument may "
                           "smuggle a remote host, and escalation/exfil switches are refused. "
                           "Returns the tool output, or 'not_installed' + fallback — never a "
                           "fabricated result. Requires the ray_arsenal helper (ray-siege).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "description": "Arsenal tool name, e.g. nmap, "
                                                              "sqlmap, jwt_tool, semgrep."},
                    "target": {"type": "string", "description": "Loopback URL/host, or a "
                                                               "filesystem path for SAST tools."},
                    "args": {"type": "array", "items": {"type": "string"},
                             "description": "Extra tool arguments (validated by the gate)."},
                },
                "required": ["tool"],
            },
        },
        tool_arsenal_run,
    ),
    "ray_secret_scan": (
        {
            "description": "Scan a file or directory for leaked secrets — DB connection "
                           "strings, API keys, tokens, private keys — in source, tests, "
                           "JSON/YAML, Markdown, notebooks, SQL and CI files. Redacts every "
                           "matched value (never echoes a secret), raises severity for the "
                           "creds+URL-in-a-doc breach pattern and secrets in test files, "
                           "checks .gitignore coverage, and flags throwaway scratch files. "
                           "Dependency-free (the ray-cloak guard).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File or directory to scan."},
                    "strict": {"type": "boolean", "description": "Fail (isError) if any "
                                                               "CRITICAL/HIGH secret is found — a pre-commit gate."},
                },
                "required": ["path"],
            },
        },
        tool_secret_scan,
    ),
}


# --------------------------------------------------------------------------- #
# JSON-RPC / MCP plumbing
# --------------------------------------------------------------------------- #

def _result(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle(msg):
    """Return a response dict, or None for notifications (no id)."""
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        proto = params.get("protocolVersion") or DEFAULT_PROTOCOL
        return _result(msg_id, {
            "protocolVersion": proto,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })

    if method in ("notifications/initialized", "initialized"):
        return None  # notification — no response

    if method == "ping":
        return _result(msg_id, {})

    if method == "tools/list":
        tools = [dict(name=name, **schema) for name, (schema, _h) in TOOLS.items()]
        return _result(msg_id, {"tools": tools})

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        entry = TOOLS.get(name)
        if entry is None:
            return _error(msg_id, -32602, "unknown tool: {}".format(name))
        _schema, handler = entry
        try:
            text, is_error = handler(arguments)
        except Exception as exc:  # never crash the server on a bad call
            text, is_error = ("tool raised {}: {}".format(type(exc).__name__, exc), True)
        return _result(msg_id, {
            "content": [{"type": "text", "text": text if text else ""}],
            "isError": bool(is_error),
        })

    if msg_id is None:
        return None  # unknown notification — ignore
    return _error(msg_id, -32601, "method not found: {}".format(method))


def main():
    _log("ray-tools MCP server up ({} tools)".format(len(TOOLS)))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stdout.write(json.dumps(_error(None, -32700, "parse error: {}".format(exc))) + "\n")
            sys.stdout.flush()
            continue
        # A batch is an array of messages.
        messages = msg if isinstance(msg, list) else [msg]
        responses = []
        for m in messages:
            if not isinstance(m, dict):
                continue
            resp = handle(m)
            if resp is not None:
                responses.append(resp)
        for resp in responses:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
