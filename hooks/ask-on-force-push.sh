#!/usr/bin/env bash
# PreToolUse(Bash) hook: force a confirmation prompt for any FORCE push.
#
# Why this exists: the static rules `Bash(git push --force:*)` etc. are prefix
# patterns, so they only match when the flag sits immediately after `git push`.
# `git push origin main --force` does not match them. While `Bash(git push:*)`
# was in permissions.ask that gap was covered, because every push prompted.
# Plain pushes now go to the auto-mode classifier, so this hook re-closes the
# gap for the irreversible case only.
#
# Matches a force flag ANYWHERE in the push arguments, plus the `+refspec`
# syntax (`git push origin +main`), which is a force push with no flag.
# Everything else, including a plain push, gets no opinion from this hook.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# strip quoted strings so a literal mention (git commit -m "git push --force")
# is not mistaken for a real push.
noq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")

# git push must be at command position (start, after a separator, or in a
# loop/conditional body), not inside a path or filename. Global flags may sit
# between `git` and `push`, and a flag like `-C` or `-c` takes its value as a
# SEPARATE word, so each flag optionally consumes one following non-flag word
# (`git -C /repo push`). git-flag-guard.sh already denies that shape outright;
# matching it here is defense in depth, not the only guard.
printf '%s' "$noq" | grep -Eq '(^|[;&|(]|(^|[[:space:]])(do|then|else|if|elif|while|until)[[:space:]])[[:space:]]*git([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+push([[:space:]]|$)' || exit 0

# isolate the push arguments: everything from `push` to the next separator.
args=$(printf '%s' "$noq" | sed -E 's/.*[[:space:]]push([[:space:]]|$)/ /; s/[;&|].*//')

force=0
# long force flags
printf '%s' "$args" | grep -Eq '(^|[[:space:]])--force(-with-lease|-if-includes)?([[:space:]]|=|$)' && force=1
# short -f, including clusters like -fu / -uf
printf '%s' "$args" | grep -Eq '(^|[[:space:]])-[a-zA-Z]*f([a-zA-Z]*)([[:space:]]|$)' && force=1
# +refspec is a force push with no flag
printf '%s' "$args" | grep -Eq '(^|[[:space:]])\+[^[:space:]]+' && force=1

[ "$force" -eq 1 ] && printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Force push detected. This rewrites the remote branch and can destroy work pushed by others. Confirm before running."}}'
exit 0
