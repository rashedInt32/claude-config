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
# dangerous / state-changing word anywhere unquoted (e.g. `find . ; rm -rf ~`, `find | xargs rm`)
printf '%s' "$noq" | grep -Eq '(^|[^[:alnum:]_])(rm|rmdir|mv|cp|dd|tee|sponge|truncate|ln|install|mkfs|wipefs|chmod|chown|chgrp|sudo|doas|su|ssh|scp|sftp|rsync|nc|ncat|netcat|socat|telnet|kill|pkill|killall|shutdown|reboot|halt|eval|exec|source|crontab|launchctl|systemctl|mount|umount|xargs|git)([^[:alnum:]_]|$)' && emit ask "$ASK"

# (3) backticks or command substitution (live inside double quotes) -> can't vet -> ask
printf '%s' "$nosq" | grep -q '`' && emit ask "$ASK"
printf '%s' "$nosq" | grep -q '\$(' && emit ask "$ASK"

# (4) shell redirection to anything but /dev/null
sanitized=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[12]?>&[12]//g; s/&>[[:space:]]*\/dev\/null//g')
printf '%s' "$sanitized" | grep -q '>' && emit ask "$ASK"

emit allow "read-only find (no destructive actions, dangerous commands, or file writes)."
