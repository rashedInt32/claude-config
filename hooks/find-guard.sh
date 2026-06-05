#!/usr/bin/env bash
# PreToolUse(Bash) hook: auto-allow READ-ONLY `find`, ask on destructive find.
#
# `find` is deliberately NOT in the static allowlist because it's dual-use
# (-delete, -exec rm, -fprintf write files). This hook lets read-only searches
# run without prompting while still gating the destructive forms. It's global,
# so it applies to every session/repo — which is the point: a behavioral "use fd"
# preference doesn't propagate across projects, but a hook in settings.json does.
#
#   read-only find (-type/-name/-ipath/-print/-prune/...)  -> allow
#   find with -delete/-exec/-execdir/-ok/-okdir/-fprint*/-fls -> ask
#   find alongside a dangerous command, $(...) sub, or file redirect -> ask
#   commands that don't invoke find                          -> no opinion
# Deny rules still win over this hook's `ask`. Fail-safe: any doubt -> ask.
#
# Quote handling: destructive-action / dangerous-word / redirect checks run
# against a quote-stripped copy (noq), so a dangerous token that's merely a
# literal argument (echo label, -name/-path pattern, grep string) doesn't trip
# the guard. Command-substitution checks strip ONLY single quotes (nosq),
# because $(...) and backticks stay live inside double quotes.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# engage only when `find` is invoked as a command (at command position — not as a
# substring in a path, nor as an argument like `grep find file`)
printf '%s' "$cmd" | grep -Eq '(^|[;&|(])[[:space:]]*find([[:space:]]|$)' || exit 0

emit() { printf '%s' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"$1\",\"permissionDecisionReason\":\"$2\"}}"; exit 0; }
ASK="find with a destructive action (-delete/-exec/...), a dangerous command, or a file redirect - confirm before running."

# quote-stripped copies (see header). noq: both quote styles. nosq: single only.
noq=$(printf '%s' "$cmd"  | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
nosq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g")

# (1) find's own destructive / file-writing / executing actions
printf '%s' "$noq" | grep -Eq '(^|[[:space:]])(-delete|-exec|-execdir|-ok|-okdir|-fprintf|-fprint|-fls)([[:space:]]|$)' && emit ask "$ASK"

# (2) defense in depth: a hook `allow` bypasses deny rules, so bail on any
# dangerous / state-changing word anywhere unquoted (e.g. `find . ; rm -rf ~`).
# git and xargs are dual-use and handled separately below (read-only forms are safe).
printf '%s' "$noq" | grep -Eq '(^|[^[:alnum:]_])(rm|rmdir|mv|cp|dd|tee|sponge|truncate|ln|install|mkfs|wipefs|chmod|chown|chgrp|sudo|doas|su|ssh|scp|sftp|rsync|nc|ncat|netcat|socat|telnet|kill|pkill|killall|shutdown|reboot|halt|eval|exec|source|crontab|launchctl|systemctl|mount|umount)([^[:alnum:]_]|$)' && emit ask "$ASK"

# (2a) git is dual-use: read-only subcommands (log/diff/status/...) are safe to run
# alongside find, but writes (push/commit/reset/...) must still block — a hook
# `allow` would otherwise bypass their ask/deny rules. Neutralize read-only git
# invocations, then ask if any `git` token remains. (git with global flags like
# -C/-c is left to git-flag-guard, which denies writes and allows reads.)
gitro='status|log|diff|show|branch|blame|remote|tag|reflog|describe|rev-parse|ls-files|ls-tree|ls-remote|shortlog|fetch|whatchanged|cat-file|for-each-ref|name-rev|merge-base|symbolic-ref|rev-list|grep|var|version|help'
gitchk=$(printf '%s' "$noq" | sed -E "s/(^|[^[:alnum:]_])git([[:space:]]+(-p|-P|--no-pager|--paginate|--no-optional-locks))*[[:space:]]+($gitro)([^[:alnum:]_]|\$)/\1 GITRO /g")
printf '%s' "$gitchk" | grep -Eq '(^|[^[:alnum:]_])git([^[:alnum:]_]|$)' && emit ask "$ASK"

# (2b) xargs is dual-use: safe only when its child command is read-only (the
# common `find ... | xargs grep`). Neutralize those, then ask if any xargs remains.
xro='grep|egrep|fgrep|rg|cat|wc|head|tail|ls|file|stat|echo|sort|uniq|cut|tr|basename|dirname|realpath|md5sum|shasum|sha256sum|cksum|column|nl|tac|rev'
xchk=$(printf '%s' "$noq" | sed -E "s/(^|[^[:alnum:]_])xargs([[:space:]]+-[^[:space:]]+)*[[:space:]]+($xro)([^[:alnum:]_]|\$)/\1 XARGSRO /g")
printf '%s' "$xchk" | grep -Eq '(^|[^[:alnum:]_])xargs([^[:alnum:]_]|$)' && emit ask "$ASK"

# (3) backticks or command substitution (live inside double quotes) -> can't vet -> ask
printf '%s' "$nosq" | grep -q '`' && emit ask "$ASK"
printf '%s' "$nosq" | grep -q '\$(' && emit ask "$ASK"

# (4) shell redirection to anything but /dev/null
sanitized=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[12]?>&[12]//g; s/&>[[:space:]]*\/dev\/null//g')
printf '%s' "$sanitized" | grep -q '>' && emit ask "$ASK"

emit allow "read-only find (no destructive actions, dangerous commands, or file writes)."
