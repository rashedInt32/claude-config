#!/usr/bin/env bash
# Stop hook: when the turn ends ("feature end"), typecheck the projects whose
# .ts/.tsx files were edited this turn (recorded by record-ts-edit.sh).
# - Prefers `pnpm typecheck`, falls back to local `tsc --noEmit`.
# - On failure: blocks once so the model fixes the errors, then re-checks on the
#   next stop. On the second pass it warns only (never loops forever).
set -uo pipefail

input=$(cat)
sid=$(printf '%s' "$input" | jq -r '.session_id // "default"' 2>/dev/null)
stop_active=$(printf '%s' "$input" | jq -r '.stop_hook_active // false' 2>/dev/null)
q="${TMPDIR:-/tmp}/claude-tsq-${sid}.txt"

[ -f "$q" ] || exit 0   # nothing edited this turn

# Unique project dirs (nearest package.json above each edited file).
pkgs=$(sort -u "$q" | while read -r f; do
  d=$(dirname "$f")
  while [ "$d" != "/" ] && [ -n "$d" ]; do
    [ -f "$d/package.json" ] && { echo "$d"; break; }
    d=$(dirname "$d")
  done
done | sort -u)

fails=""
while IFS= read -r pkgdir; do
  [ -z "$pkgdir" ] && continue
  if jq -e '.scripts.typecheck' "$pkgdir/package.json" >/dev/null 2>&1; then
    out=$(cd "$pkgdir" && pnpm typecheck 2>&1); rc=$?
  elif [ -x "$pkgdir/node_modules/.bin/tsc" ]; then
    out=$(cd "$pkgdir" && node_modules/.bin/tsc --noEmit 2>&1); rc=$?
  else
    continue
  fi
  [ "$rc" -ne 0 ] && fails="${fails}\n[$pkgdir]\n$(printf '%s' "$out" | tail -20)\n"
done <<< "$pkgs"

if [ -z "$fails" ]; then
  rm -f "$q"          # all green — clear the queue
  exit 0
fi

if [ "$stop_active" = "true" ]; then
  rm -f "$q"          # second pass: warn only, don't loop
  jq -cn --arg r "$(printf 'Typecheck still failing (not blocking again):%b' "$fails")" '{systemMessage:$r}'
  exit 0
fi

# First pass: keep the queue and send the model back to fix the errors.
jq -cn --arg r "$(printf 'Typecheck failed at end of turn. Fix these TypeScript errors before finishing:%b' "$fails")" '{decision:"block", reason:$r}'
exit 0
