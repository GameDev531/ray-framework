#!/usr/bin/env sh
# Ray Framework installer.
#
# Copies (or symlinks) every ray-* skill directory into the target assistant's
# skill folder so the skills become invocable. Run from the repo root, or point
# it at a repo with --dest.
#
# Usage:
#   bin/ray-install.sh                      # install into ./.claude/skills (copy)
#   bin/ray-install.sh --assistant gemini   # ./.gemini/skills
#   bin/ray-install.sh --dest /path/to/repo # install into another repo
#   bin/ray-install.sh --link               # symlink instead of copy
#
# Assistants: claude (.claude/skills), gemini (.gemini/skills),
#             codex (.codex/skills), cursor (.cursor/rules)
set -eu

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST_REPO="."
ASSISTANT="claude"
MODE="copy"

while [ $# -gt 0 ]; do
  case "$1" in
    --assistant) ASSISTANT="$2"; shift 2 ;;
    --dest)      DEST_REPO="$2"; shift 2 ;;
    --link)      MODE="link"; shift ;;
    -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "$ASSISTANT" in
  claude) SUB=".claude/skills" ;;
  gemini) SUB=".gemini/skills" ;;
  codex)  SUB=".codex/skills" ;;
  cursor) SUB=".cursor/rules" ;;
  *) echo "unknown assistant: $ASSISTANT (claude|gemini|codex|cursor)" >&2; exit 2 ;;
esac

DEST="$DEST_REPO/$SUB"
mkdir -p "$DEST"

count=0
for dir in "$SRC"/ray-*/; do
  [ -f "$dir/SKILL.md" ] || continue
  name="$(basename "$dir")"
  target="$DEST/$name"
  rm -rf "$target"
  if [ "$MODE" = "link" ]; then
    # Prefer a relative symlink when installing inside the source repo itself
    # (portable across clones); fall back to an absolute link otherwise.
    if [ "$(cd "$DEST_REPO" && pwd)" = "$SRC" ]; then
      ln -s "../../$name" "$target"
    else
      ln -s "${dir%/}" "$target"
    fi
  else
    cp -R "$dir" "$target"
  fi
  count=$((count + 1))
done

echo "Installed $count ray-* skills into $DEST ($MODE)."
echo "Restart your assistant (or reload skills) so it re-scans the directory."
