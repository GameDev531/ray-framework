# RAY_HELPER_VERSION = 1
#!/usr/bin/env python3
"""
ray_memory.py — curated, global, per-agent memory for Ray agents (Layer 1).

A deliberately tiny, dependency-free memory layer. It manages a plain Markdown
file per agent under a GLOBAL directory (default ~/.claude/ray-memory/<agent>.md)
so an agent's learnings persist and compound across every project and every run.

Design (curated memory, not a data vacuum):
  - Memory is born ONLY from the agent's own work. There is no ingestion of
    email, files, or history here. Callers append lessons they NOTICE while
    working; nothing is scraped.
  - Layer 1 only: a simple Markdown file the agent owns. No database, no vectors,
    no external service. (A future optional Layer 2 with SQLite/FTS5 is documented
    in ray-memory.md but intentionally not built here.)
  - A hard CHARACTER cap (not tokens) per file forces high signal: when the file
    is full, `add`/`replace` refuse and the agent must curate (remove low-value
    entries) instead of dumping.
  - Entries are located by a UNIQUE text snippet, never by an ID.

Actions: recall | add | replace | remove | list

Examples:
  python3 ray_memory.py recall  --agent reaver
  python3 ray_memory.py add     --agent reaver --section "Attack techniques that worked" \
                                --text "Express: mass-assignment on PATCH /users reaches is_admin when body is spread into update()"
  python3 ray_memory.py replace --agent bulwark --find "scope query to tenant" \
                                --text "scope the query to the session tenant AND add a WITH CHECK RLS policy"
  python3 ray_memory.py remove  --agent reaver --find "outdated note about X"

Exit codes: 0 ok; 2 usage/ambiguous/refused (cap or non-unique snippet); 1 error.
"""

import argparse
import os
import sys
from datetime import datetime, timezone

DEFAULT_DIR = os.path.expanduser(os.path.join("~", ".claude", "ray-memory"))
DEFAULT_MAX_CHARS = 6000  # per-file hard cap; forces curation over dumping.
KNOWN_AGENTS = ("reaver", "bulwark", "scrivener")

HEADER = (
    "<!-- Ray curated memory (Layer 1). Owned by the agent; born only from its own\n"
    "     work — never from ingested email/files/history. Keep entries high-signal\n"
    "     and terse; the character cap is enforced by scripts/ray_memory.py. -->\n"
)


def _safe_agent(name: str) -> str:
    # Filesystem-safe, no traversal. Agents are simple slugs.
    cleaned = "".join(c for c in name if c.isalnum() or c in ("-", "_")).strip("-_")
    if not cleaned:
        sys.stderr.write("error: invalid --agent name\n")
        sys.exit(2)
    return cleaned


def _path(mem_dir: str, agent: str) -> str:
    return os.path.join(mem_dir, agent + ".md")


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _atomic_write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, path)


def _ensure_scaffold(content: str, agent: str) -> str:
    if content.strip():
        return content
    return HEADER + "\n# Memory: {}\n".format(agent)


def _one_line(text: str) -> str:
    # Entries are single Markdown bullets; collapse whitespace/newlines.
    return " ".join(text.split()).strip()


def _find_entry_lines(lines, snippet):
    return [i for i, ln in enumerate(lines) if ln.lstrip().startswith("- ") and snippet in ln]


def cmd_recall(args):
    content = _read(_path(args.dir, args.agent))
    if not content.strip():
        # Empty is a normal, expected state — print nothing but succeed.
        return 0
    sys.stdout.write(content if content.endswith("\n") else content + "\n")
    return 0


def cmd_add(args):
    path = _path(args.dir, args.agent)
    content = _ensure_scaffold(_read(path), args.agent)
    entry = _one_line(args.text)
    if not entry:
        sys.stderr.write("error: --text is empty after normalization\n")
        return 2
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    bullet = "- {} _(learned {})_".format(entry, stamp)

    lines = content.splitlines()
    section = _one_line(args.section) if args.section else "Notes"
    header = "## " + section
    # Find the section; create it at the end if absent.
    idx = next((i for i, ln in enumerate(lines) if ln.strip() == header), None)
    if idx is None:
        if lines and lines[-1].strip() != "":
            lines.append("")
        lines.append(header)
        lines.append(bullet)
    else:
        # Insert after the last bullet already in this section.
        j = idx + 1
        last = idx
        while j < len(lines) and not lines[j].startswith("## "):
            if lines[j].lstrip().startswith("- "):
                last = j
            j += 1
        lines.insert(last + 1, bullet)

    new_content = "\n".join(lines) + "\n"
    if len(new_content) > args.max_chars:
        sys.stderr.write(
            "REFUSED: adding this entry would exceed the {}-char cap for '{}' "
            "(current {} chars). Curate first: remove a low-value entry with "
            "`remove --find \"...\"`, then retry. The cap is deliberate — memory "
            "must stay high-signal, not a dump.\n".format(
                args.max_chars, args.agent, len(content)
            )
        )
        return 2
    _atomic_write(path, new_content)
    sys.stdout.write("added to {} [{}]\n".format(os.path.basename(path), section))
    return 0


def cmd_replace(args):
    path = _path(args.dir, args.agent)
    content = _read(path)
    lines = content.splitlines()
    hits = _find_entry_lines(lines, args.find)
    if len(hits) == 0:
        sys.stderr.write("error: no entry contains the snippet (nothing replaced)\n")
        return 2
    if len(hits) > 1:
        sys.stderr.write(
            "REFUSED: snippet is not unique ({} matches). Give a longer, unique "
            "trecho.\n".format(len(hits))
        )
        return 2
    i = hits[0]
    indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines[i] = "{}- {} _(updated {})_".format(indent, _one_line(args.text), stamp)
    new_content = "\n".join(lines) + "\n"
    if len(new_content) > args.max_chars:
        sys.stderr.write(
            "REFUSED: replacement would exceed the {}-char cap. Shorten it.\n".format(
                args.max_chars
            )
        )
        return 2
    _atomic_write(path, new_content)
    sys.stdout.write("replaced 1 entry in {}\n".format(os.path.basename(path)))
    return 0


def cmd_remove(args):
    path = _path(args.dir, args.agent)
    content = _read(path)
    lines = content.splitlines()
    hits = _find_entry_lines(lines, args.find)
    if len(hits) == 0:
        sys.stderr.write("error: no entry contains the snippet (nothing removed)\n")
        return 2
    if len(hits) > 1:
        sys.stderr.write(
            "REFUSED: snippet is not unique ({} matches). Give a longer, unique "
            "trecho.\n".format(len(hits))
        )
        return 2
    del lines[hits[0]]
    _atomic_write(path, "\n".join(lines) + "\n")
    sys.stdout.write("removed 1 entry from {}\n".format(os.path.basename(path)))
    return 0


def cmd_list(args):
    try:
        names = sorted(
            f[:-3] for f in os.listdir(args.dir) if f.endswith(".md")
        )
    except FileNotFoundError:
        names = []
    for n in names:
        size = len(_read(_path(args.dir, n)))
        sys.stdout.write("{}\t{} chars\n".format(n, size))
    if not names:
        sys.stdout.write("(no memory files yet in {})\n".format(args.dir))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="ray_memory.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dir", default=DEFAULT_DIR,
                   help="memory directory (default: %(default)s)")
    p.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS,
                   help="per-file character cap (default: %(default)s)")
    sub = p.add_subparsers(dest="action", required=True)

    for name in ("recall", "add", "replace", "remove"):
        sp = sub.add_parser(name)
        sp.add_argument("--agent", required=True)
        if name == "add":
            sp.add_argument("--section", default="Notes")
            sp.add_argument("--text", required=True)
        if name == "replace":
            sp.add_argument("--find", required=True)
            sp.add_argument("--text", required=True)
        if name == "remove":
            sp.add_argument("--find", required=True)
    sub.add_parser("list")

    args = p.parse_args(argv)
    if getattr(args, "agent", None):
        args.agent = _safe_agent(args.agent)

    try:
        return {
            "recall": cmd_recall,
            "add": cmd_add,
            "replace": cmd_replace,
            "remove": cmd_remove,
            "list": cmd_list,
        }[args.action](args)
    except BrokenPipeError:
        return 0
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write("error: {}\n".format(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
