#!/usr/bin/env bash
# PreToolUse(Bash) hook: sole permission authority for curl/wget.
#
# curl/wget are NOT in the static `ask` list (an explicit ask rule would override
# this hook's `allow`). Instead this hook decides:
#   * curl/wget that targets ONLY localhost, with no file writes / dangerous
#     tokens / non-curl command-substitutions  -> allow (no prompt)
#   * any other curl/wget                                          -> ask (prompt)
#   * commands that don't use curl/wget                            -> no opinion
# Deny rules still win over this hook's `ask` (e.g. `curl localhost && rm -rf ~`
# is denied by the rm deny rule). Fail-safe: any doubt yields `ask`, never allow.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0
printf '%s' "$cmd" | grep -Eqw 'curl|wget' || exit 0   # not a curl/wget command

emit() { printf '%s' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"$1\",\"permissionDecisionReason\":\"$2\"}}"; exit 0; }
ASK="curl/wget is not a clean localhost-only probe (non-localhost host, file write, or dangerous command) - confirm before running."

# (2) dangerous / state-changing word anywhere -> defends against `curl localhost && rm -rf ~`
printf '%s' "$cmd" | grep -Eq '(^|[^[:alnum:]_])(rm|rmdir|mv|cp|dd|tee|sponge|truncate|ln|install|mkfs|wipefs|chmod|chown|chgrp|sudo|doas|su|ssh|scp|sftp|rsync|nc|ncat|netcat|socat|telnet|kill|pkill|killall|shutdown|reboot|halt|eval|exec|source|crontab|launchctl|systemctl|mount|umount|export|trap|git)([^[:alnum:]_]|$)' && emit ask "$ASK"

# (3) no backticks; every $(...) must be a curl/wget call
printf '%s' "$cmd" | grep -q '`' && emit ask "$ASK"
total_subs=$(printf '%s' "$cmd" | grep -oE '\$\(' | wc -l | tr -d ' ')
curl_subs=$(printf '%s' "$cmd" | grep -oE '\$\([[:space:]]*(curl|wget)' | wc -l | tr -d ' ')
[ "$total_subs" -ne "$curl_subs" ] && emit ask "$ASK"

# (4a) curl file-writing flags that aren't /dev/null
printf '%s' "$cmd" | grep -Eq '(^|[[:space:]])(-O|--remote-name|--remote-header-name|-J|--output-dir|-K|--config|-T|--upload-file)([[:space:]]|=|$)' && emit ask "$ASK"
for arg in $(printf '%s' "$cmd" | grep -oE '(-o|--output)[[:space:]]+[^[:space:]]+' | sed -E 's/^(-o|--output)[[:space:]]+//'); do
  [ "$arg" != "/dev/null" ] && emit ask "$ASK"
done

# (4b) shell redirection to anything but /dev/null (strip quoted strings first so a
# literal '>' inside a -w/-d value, e.g. "host -> HTTP", isn't read as a redirect)
unquoted=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
sanitized=$(printf '%s' "$unquoted" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[12]?>&[12]//g; s/&>[[:space:]]*\/dev\/null//g')
printf '%s' "$sanitized" | grep -q '>' && emit ask "$ASK"

# (5) every http(s) URL must be a localhost host
urls=$(printf '%s' "$cmd" | grep -oE "https?://[^[:space:]\"'\`)|;&>]+")
[ -z "$urls" ] && emit ask "$ASK"
while IFS= read -r u; do
  [ -z "$u" ] && continue
  rest=${u#*://}
  authority=${rest%%[/?#]*}
  hostport=${authority##*@}          # strip user:pass@ -> real host
  case "$hostport" in
    \[*\]*) host=$(printf '%s' "$hostport" | sed -E 's/^\[([^]]*)\].*/\1/') ;;  # [::1]:port
    *)      host=${hostport%%:*} ;;
  esac
  case "$host" in
    localhost|127.0.0.1|::1) ;;       # ok
    *) emit ask "$ASK" ;;             # any non-localhost host
  esac
done <<< "$urls"

emit allow "curl/wget targets only localhost and contains no file writes or dangerous commands."
