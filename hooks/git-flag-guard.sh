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
# `-c <key=value>` and `--config-env` are ALWAYS denied, never vouched: several
# config keys (core.pager, core.sshCommand, core.editor, core.hooksPath,
# diff.external, alias.*, uploadpack.packObjectsHook, *.program, credential.helper,
# filter.*.clean/smudge, ...) make git EXECUTE an arbitrary command even under a
# read-only subcommand, so `git -c core.pager=/x/evil.sh log` would otherwise be
# waved through. The value is opaque to a word-scan, so we don't try to classify
# safe vs unsafe keys — deny the flag outright. -C/--git-dir/--work-tree carry no
# such exec capability and stay allowed.
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
  has_global=0   # any global flag seen (cosmetic or real) -> can vouch a read-only sub
  has_real=0     # a repo-retargeting/unknown flag seen -> forces a write sub into deny
  sub=""
  while [ $j -lt $n ]; do
    o="${toks[$j]}"
    case "$o" in
      '&&'|'||'|';'|'|'|'|&'|'>'|'>>'|'<'|'2>'|'2>>'|'&')
        break ;;
      # -c/--config-env can set command-executing config (core.pager,
      # core.sshCommand, diff.external, alias.*, ...) that runs an arbitrary
      # command even when the subcommand is read-only -> never vouch, deny.
      -c|-c=*|--config-env|--config-env=*)
        decide="deny_config"; break ;;
      # global options that consume the NEXT token as their argument
      -C|--git-dir|--work-tree|--namespace|--super-prefix|--exec-path)
        has_global=1; has_real=1; j=$((j + 2)); continue ;;
      # global options with an attached =value, or standalone global flags
      --git-dir=*|--work-tree=*|--namespace=*|--exec-path=*|--super-prefix=*)
        has_global=1; has_real=1; j=$((j + 1)); continue ;;
      # cosmetic flags: don't retarget the repo or enable exec. They still vouch a
      # read-only sub (has_global), but must NOT force a write sub into deny
      # (has_real stays 0), so `git --no-pager commit` falls through to normal rules
      # while `git --no-pager log` is still auto-allowed.
      -p|-P|--paginate|--no-pager|--no-optional-locks)
        has_global=1; j=$((j + 1)); continue ;;
      --bare|--no-replace-objects|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs|--no-advice)
        has_global=1; has_real=1; j=$((j + 1)); continue ;;
      -*)
        # unknown leading option: treat as a real global flag, skip it (defensive)
        has_global=1; has_real=1; j=$((j + 1)); continue ;;
      *)
        sub="$o"; break ;;
    esac
  done

  if [ -n "$sub" ] && [ $has_global -eq 1 ]; then
    if printf '%s' "$sub" | grep -Eq "$readonly_re"; then
      [ -z "$decide" ] && decide="allow"   # tentative; a later write still wins
    elif [ $has_real -eq 1 ]; then
      decide="deny"; break                 # write sub reached via a repo-retargeting flag
    fi
    # write sub behind ONLY cosmetic flags -> no opinion, fall through to normal rules
  fi
  i=$j
done

case "$decide" in
  deny_config)
    printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"git -c/--config-env can set command-executing config (core.pager, core.sshCommand, diff.external, alias.*, ...) that runs an arbitrary command even under a read-only subcommand. Drop the -c flag, or set the config in the repo and run plain git."}}'
    ;;
  deny)
    printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"git global flag (-C/--git-dir/--work-tree) reaches a non-read-only subcommand, bypassing the subcommand permission rules. cd into the repo and run plain git instead."}}'
    ;;
  allow)
    printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"git with global flags resolves to a read-only subcommand."}}'
    ;;
esac
exit 0
