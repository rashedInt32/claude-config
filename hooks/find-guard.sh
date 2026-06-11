#!/usr/bin/env bash
# PreToolUse(Bash) hook: auto-allow READ-ONLY `find`, ask on anything else.
#
# `find` is deliberately NOT in the static allowlist because it's dual-use
# (-delete, -exec rm, -fprintf write files). This hook lets read-only searches
# run without prompting while gating the destructive forms. It's global, so it
# applies to every session/repo.
#
#   read-only find (-type/-name/-ipath/-print/-prune/...) whose only companions
#   are read-only commands  -> allow
#   find with -delete/-exec/-execdir/-ok/-okdir/-fprint*/-fls -> ask
#   find alongside ANY non-read-only command, a $()/backtick, or a file redirect -> ask
#   commands that don't invoke find -> no opinion
# Deny rules still win over this hook's `ask`. Fail-safe: any doubt -> ask.
#
# Design: a hook `allow` bypasses deny rules, so the companion check is an
# ALLOWLIST, not a denylist. Every command-position program must be `find`, a
# known read-only tool, or a read-only git/xargs invocation; an interpreter
# (`bash -c "rm"`, `python -c ...`) or arbitrary executable (`./x`) — whose
# payload a word-scan can't see — fails the allowlist and asks. Quote handling:
# structural checks run on a quote-stripped copy (noq); substitution checks
# strip only single quotes (nosq), since $()/`` stay live inside double quotes.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# engage only when find is a command (command position — not a path/arg substring)
printf '%s' "$cmd" | grep -Eq '(^|[;&|(])[[:space:]]*find([[:space:]]|$)' || exit 0

emit() { printf '%s' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"$1\",\"permissionDecisionReason\":\"$2\"}}"; exit 0; }
ASK="find with a destructive action (-delete/-exec/...), a non-read-only companion command, a \$()/backtick, or a file redirect - confirm before running."

noq=$(printf '%s' "$cmd"  | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
nosq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g")

# (1) find's own destructive / file-writing / executing actions
printf '%s' "$noq" | grep -Eq '(^|[[:space:]])(-delete|-exec|-execdir|-ok|-okdir|-fprintf|-fprint|-fls)([[:space:]]|$)' && emit ask "$ASK"

# (2) backticks -> can't vet -> ask. Command substitution $(...) is deferred to
# allow-readonly-pipeline, which vouches read-only `VAR=$(find ...)` forms and
# stays silent otherwise; a destructive find inside $() is already caught by the
# -delete/-exec check in (1) above, so deferring here can't wave a write through.
printf '%s' "$nosq" | grep -q '`' && emit ask "$ASK"
printf '%s' "$nosq" | grep -q '\$(' && exit 0

# (3) output redirection to anything but /dev/null -> ask
sanitized=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g')
printf '%s' "$sanitized" | grep -q '>' && emit ask "$ASK"

# (4) companion allowlist: neutralize read-only git/xargs, then require every
# command-position program to be find / a read-only tool / GITRO / XARGSRO.
gitro='status|log|diff|show|branch|blame|remote|tag|reflog|describe|rev-parse|ls-files|ls-tree|ls-remote|shortlog|fetch|whatchanged|cat-file|for-each-ref|name-rev|merge-base|symbolic-ref|rev-list|grep|var|version|help'
xro='grep|egrep|fgrep|rg|cat|wc|head|tail|ls|file|stat|echo|cut|tr|nl|tac|rev|comm|cmp|diff|hexdump|od|strings|md5sum|shasum|sha256sum|cksum|column|basename|dirname|realpath|jq|sort|uniq'
norm=$(printf '%s' "$noq" \
  | sed -E "s/(^|[^[:alnum:]_])git([[:space:]]+(-p|-P|--no-pager|--paginate|--no-optional-locks))*[[:space:]]+($gitro)([^[:alnum:]_]|\$)/\1 GITRO /g" \
  | sed -E "s/(^|[^[:alnum:]_])xargs([[:space:]]+-[^[:space:]]+)*[[:space:]]+($xro)([^[:alnum:]_]|\$)/\1 XARGSRO /g")
forsplit=$(printf '%s' "$norm" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g; s/[0-9]*<[[:space:]]*[^[:space:];&|]+//g' | tr -d '(){}')
roset=" base64 basename cat cd cksum column comm cmp cut date df diff dirname du echo egrep false fgrep file grep head hexdump jq ls md5sum nl od printenv printf pwd readlink realpath rev rg seq sha256sum shasum sleep sort stat strings tac tail test tr tree true type uniq wc which xxd "
safe="${roset}find GITRO XARGSRO "
while IFS= read -r seg; do
  seg=$(printf '%s' "$seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
  [ -z "$seg" ] && continue
  prog=${seg%%[[:space:]]*}
  prog=${prog##*/}
  case "$prog" in
    *=*) emit ask "$ASK" ;;          # VAR=val prefix (e.g. LD_PRELOAD=...) -> ask
  esac
  case "$safe" in
    *" $prog "*) ;;                  # read-only companion, ok
    *) emit ask "$ASK" ;;            # interpreter / unknown executable / writer -> ask
  esac
done <<< "$(printf '%s' "$forsplit" | awk '{ gsub(/[;&|]/, "\n"); print }')"

emit allow "read-only find with only read-only companion commands."
