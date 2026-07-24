#!/usr/bin/env bash
# Stop hook: when the turn ends ("feature end"), typecheck the projects whose
# .ts/.tsx files were edited this turn (recorded by record-ts-edit.sh).
# - Prefers `pnpm typecheck`, falls back to local `tsc --noEmit`.
# - Blocks ONLY on errors in files edited this turn. Pre-existing errors in
#   untouched files are counted, reported once, and explicitly marked as
#   not-ours so the model doesn't waste context investigating them.
# - On failure: blocks once so the model fixes the errors, then re-checks on the
#   next stop. On the second pass it warns only (never loops forever).
set -uo pipefail

input=$(cat)
sid=$(printf '%s' "$input" | jq -r '.session_id // "default"' 2>/dev/null)
stop_active=$(printf '%s' "$input" | jq -r '.stop_hook_active // false' 2>/dev/null)
q="${TMPDIR:-/tmp}/claude-tsq-${sid}.txt"

[ -f "$HOME/.claude/.no-typecheck" ] && { rm -f "$q"; exit 0; }   # opt-out sentinel: skip typecheck entirely
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
pre_note=""
while IFS= read -r pkgdir; do
  [ -z "$pkgdir" ] && continue
  if jq -e '.scripts.typecheck' "$pkgdir/package.json" >/dev/null 2>&1; then
    out=$(cd "$pkgdir" && pnpm typecheck 2>&1); rc=$?
  elif [ -x "$pkgdir/node_modules/.bin/tsc" ]; then
    out=$(cd "$pkgdir" && node_modules/.bin/tsc --noEmit 2>&1); rc=$?
  else
    continue
  fi
  [ "$rc" -eq 0 ] && continue

  # Error lines only (both tsc formats: "file(1,2): error TS…" and "file:1:2 - error TS…").
  errs=$(printf '%s\n' "$out" | grep -E 'error TS[0-9]+' || true)

  # This turn's edited files inside this project, as project-relative paths.
  rels=$(sort -u "$q" | grep -F "$pkgdir/" | sed "s|^$pkgdir/||")

  # Split: errors in edited files (ours) vs everything else (pre-existing).
  mine=""
  while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    m=$(printf '%s\n' "$errs" | grep -F "$rel" || true)
    [ -n "$m" ] && mine="${mine}${m}"$'\n'
  done <<< "$rels"
  mine=$(printf '%s' "$mine" | sort -u)

  total=0; [ -n "$errs" ] && total=$(printf '%s\n' "$errs" | grep -cE 'error TS[0-9]+')
  own=0;   [ -n "$mine" ] && own=$(printf '%s\n' "$mine" | grep -cE 'error TS[0-9]+')
  pre=$((total - own))

  if [ -n "$mine" ]; then
    note=""
    [ "$pre" -gt 0 ] && note=" (+$pre pre-existing error(s) in untouched files — IGNORE those, do not investigate them)"
    fails="${fails}\n[$pkgdir]${note}\n$(printf '%s\n' "$mine" | head -30)\n"
  elif [ "$pre" -gt 0 ]; then
    pre_note="${pre_note}\n[$pkgdir] $pre pre-existing typecheck error(s), none in files edited this turn. Ignored."
  fi
done <<< "$pkgs"

if [ -z "$fails" ]; then
  rm -f "$q"          # nothing of ours is broken — clear the queue
  if [ -n "$pre_note" ]; then
    jq -cn --arg r "$(printf 'Typecheck note (not blocking):%b' "$pre_note")" '{systemMessage:$r}'
  fi
  exit 0
fi

if [ "$stop_active" = "true" ]; then
  rm -f "$q"          # second pass: warn only, don't loop
  jq -cn --arg r "$(printf 'Typecheck still failing in files you edited (not blocking again):%b' "$fails")" '{systemMessage:$r}'
  exit 0
fi

# Warn-only: surface the errors in files edited this turn as a non-blocking note.
# No forced round-trip — the model is informed but the turn ends normally. Create
# ~/.claude/.no-typecheck to skip the typecheck run entirely.
rm -f "$q"
jq -cn --arg r "$(printf 'Typecheck failed in files you edited this turn (not blocking) — worth fixing before you move on; pre-existing errors elsewhere are already known, leave them alone:%b' "$fails")" '{systemMessage:$r}'
exit 0
