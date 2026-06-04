#!/usr/bin/env bash
# PreToolUse(Bash) hook: close the "global flag before subcommand" bypass in git.
#
# git's global options (-C <path>, -c <kv>, --git-dir, --work-tree, ...) sit BEFORE
# the subcommand, so a command like `git -C /x push` starts with "git -C", not
# "git push" — it slips past subcommand-scoped allow/ask/deny rules. This hook
# resolves the REAL subcommand after skipping global options and decides:
#   * read-only subcommand  -> allow  (e.g. git -C /x diff)
#   * anything else / unknown -> deny  (use `cd <repo>` then plain git instead)
# It only engages when such global flags are actually present; plain `git push`/
# `git diff` fall through untouched to the normal permission rules.
#
# Safety: tokenizes via a here-string (NO eval, NO command substitution), so a
# crafted command string cannot inject execution through this guard.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# Word-split on whitespace only; quotes aren't honored, but that just risks a
# safe misparse that falls to the deny/neutral default — never an over-allow.
read -ra toks <<< "$cmd"

readonly_re='^(status|log|diff|show|branch|blame|remote|tag|reflog|describe|rev-parse|ls-files|ls-tree|ls-remote|shortlog|fetch|whatchanged|cat-file|for-each-ref|name-rev|merge-base|symbolic-ref|rev-list|grep|var|version|help)$'

decide=""
n=${#toks[@]}
i=0
while [ $i -lt $n ]; do
  base="${toks[$i]##*/}"
  if [ "$base" != "git" ]; then
    i=$((i + 1))
    continue
  fi

  # Parse the options that follow this `git`, tracking whether any global flag
  # appeared and what the resolved subcommand is.
  j=$((i + 1))
  has_global=0
  sub=""
  while [ $j -lt $n ]; do
    o="${toks[$j]}"
    case "$o" in
      '&&'|'||'|';'|'|'|'|&'|'>'|'>>'|'<'|'2>'|'2>>'|'&')
        break ;;
      # global options that consume the NEXT token as their argument
      -C|--git-dir|--work-tree|--namespace|--super-prefix|--exec-path|-c)
        has_global=1; j=$((j + 2)); continue ;;
      # global options with an attached =value, or standalone global flags
      --git-dir=*|--work-tree=*|--namespace=*|--exec-path=*|--super-prefix=*|-c=*)
        has_global=1; j=$((j + 1)); continue ;;
      -p|--paginate|-P|--no-pager|--bare|--no-replace-objects|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs|--no-optional-locks|--no-advice)
        has_global=1; j=$((j + 1)); continue ;;
      -*)
        # unknown leading option: treat as a global flag, skip it (defensive)
        has_global=1; j=$((j + 1)); continue ;;
      *)
        sub="$o"; break ;;
    esac
  done

  if [ -n "$sub" ] && [ $has_global -eq 1 ]; then
    if printf '%s' "$sub" | grep -Eq "$readonly_re"; then
      [ -z "$decide" ] && decide="allow"   # tentative; a later write still wins
    else
      decide="deny"; break
    fi
  fi
  i=$j
done

case "$decide" in
  deny)
    printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"git global flag (-C/-c/--git-dir/--work-tree) reaches a non-read-only subcommand, bypassing the subcommand permission rules. cd into the repo and run plain git instead."}}'
    ;;
  allow)
    printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"git with global flags resolves to a read-only subcommand."}}'
    ;;
esac
exit 0
