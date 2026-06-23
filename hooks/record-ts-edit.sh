#!/usr/bin/env bash
# PostToolUse hook (Write|Edit): silently record which .ts/.tsx files were edited
# this turn, so the Stop hook can typecheck them once at the end. No typecheck here
# — this is instant and produces zero noise.
#
# Customize SKIP_GLOB below to exclude repos you never want auto-typechecked
# (e.g. a vendored or client repo with its own checks). Leave empty to check all.
set -uo pipefail

# Glob (case statement pattern) of paths to skip. Example: "*/some-vendor/Base/*"
SKIP_GLOB="*/CHANGE-ME-skip-repo/*"

input=$(cat)
file=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_response.filePath // empty' 2>/dev/null)
sid=$(printf '%s' "$input" | jq -r '.session_id // "default"' 2>/dev/null)

[ -z "$file" ] && exit 0
case "$file" in
  *.ts|*.tsx) ;;
  *) exit 0 ;;
esac
case "$file" in
  $SKIP_GLOB) exit 0 ;;
esac

printf '%s\n' "$file" >> "${TMPDIR:-/tmp}/claude-tsq-${sid}.txt"
exit 0
