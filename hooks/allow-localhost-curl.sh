#!/usr/bin/env bash
# PreToolUse(Bash) hook: sole permission authority for curl/wget.
#
# curl/wget are NOT in the static `ask` list (an explicit ask rule would override
# this hook's `allow`). Instead this hook decides:
#   * curl/wget that targets ONLY localhost, with no file writes, whose only
#     companions are read-only commands               -> allow (no prompt)
#   * curl (not wget) to ANY host when it is a pure read-only probe: GET/HEAD
#     only, no data/upload/auth/cookie flags, no env expansion anywhere, no
#     substitutions, plus all the shared gates above  -> allow (no prompt)
#   * any other curl/wget                              -> ask (prompt)
#   * commands that don't INVOKE curl/wget             -> no opinion
# Deny rules still win over this hook's `ask`. Fail-safe: any doubt yields `ask`.
#
# Engages ONLY when curl/wget is at command position, not when "curl"/"wget"
# appears inside a path, filename, or string (`cat foo-curl.sh`, `grep curl f`).
#
# Design: a hook `allow` bypasses deny rules, so companions are checked against an
# ALLOWLIST (read-only tools / read-only git), not a denylist — an interpreter or
# arbitrary executable next to the curl fails the check and asks. Quote handling:
# word/redirect/URL checks use a both-quotes-stripped copy (noq); substitution
# checks strip only single quotes (nosq), since $()/`` stay live in double quotes.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0
printf '%s' "$cmd" | grep -Eq '(^|[;&|(])[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*(curl|wget)([[:space:]]|$)' || exit 0   # curl/wget at command position (VAR= prefixes engage too; section 4 asks on them)

emit() { printf '%s' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"$1\",\"permissionDecisionReason\":\"$2\"}}"; exit 0; }
ASK="curl/wget is not a clean localhost-only probe (non-localhost host, file write, non-read-only companion, or dangerous command) - confirm before running."

noq=$(printf '%s' "$cmd"  | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
nosq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g")

# (1) no backticks; every $(...) must be a curl/wget call (substitutions live in double quotes)
printf '%s' "$nosq" | grep -q '`' && emit ask "$ASK"
total_subs=$(printf '%s' "$nosq" | grep -oE '\$\(' | wc -l | tr -d ' ')
curl_subs=$(printf '%s' "$nosq" | grep -oE '\$\([[:space:]]*(curl|wget)' | wc -l | tr -d ' ')
[ "$total_subs" -ne "$curl_subs" ] && emit ask "$ASK"

# (2) curl file-writing flags that aren't /dev/null. The cluster check also
# catches glued short forms (-sO, -sJ, -sT, -sK) that word-boundary regexes miss.
printf '%s' "$noq" | grep -Eq '(^|[[:space:]])(-O|--remote-name|--remote-header-name|-J|--output-dir|-K|--config|-T|--upload-file|-D|--dump-header|--trace|--trace-ascii|--libcurl|--etag-save)([[:space:]]|=|$)' && emit ask "$ASK"
printf '%s' "$noq" | grep -Eq '(^|[[:space:]])-[A-Za-z]*[OJKTD]' && emit ask "$ASK"
for arg in $(printf '%s' "$noq" | grep -oE '(-o|--output)[[:space:]]+[^[:space:]]+' | sed -E 's/^(-o|--output)[[:space:]]+//'); do
  [ "$arg" != "/dev/null" ] && emit ask "$ASK"
done

# (3) shell redirection to anything but /dev/null
sanitized=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g')
printf '%s' "$sanitized" | grep -q '>' && emit ask "$ASK"

# (4) companion allowlist: neutralize read-only git, then require every
# command-position program to be curl/wget / a read-only tool / GITRO.
gitro='status|log|diff|show|branch|blame|remote|tag|reflog|describe|rev-parse|ls-files|ls-tree|ls-remote|shortlog|fetch|whatchanged|cat-file|for-each-ref|name-rev|merge-base|symbolic-ref|rev-list|grep|var|version|help'
norm=$(printf '%s' "$noq" | sed -E "s/(^|[^[:alnum:]_])git([[:space:]]+(-p|-P|--no-pager|--paginate|--no-optional-locks))*[[:space:]]+($gitro)([^[:alnum:]_]|\$)/\1 GITRO /g")
forsplit=$(printf '%s' "$norm" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g; s/[0-9]*<[[:space:]]*[^[:space:];&|]+//g' | tr -d '(){}')
roset=" base64 basename cat cd cksum column comm cmp cut date df diff dirname du echo egrep false fgrep file grep head hexdump jq ls md5sum nl od printenv printf pwd readlink realpath rev rg seq sha256sum shasum sleep sort stat strings tac tail test tr tree true type uniq wc which xxd "
safe="${roset}curl wget GITRO "
while IFS= read -r seg; do
  seg=$(printf '%s' "$seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
  [ -z "$seg" ] && continue
  prog=${seg%%[[:space:]]*}
  prog=${prog##*/}
  case "$prog" in
    *=*) emit ask "$ASK" ;;          # VAR=val prefix -> ask
  esac
  case "$safe" in
    *" $prog "*) ;;
    *) emit ask "$ASK" ;;            # interpreter / unknown executable / writer -> ask
  esac
done <<< "$(printf '%s' "$forsplit" | awk '{ gsub(/[;&|]/, "\n"); print }')"

# (5) classify targets. Work on the quote-stripped copy (noq) so a flag value
# like -H "X: localhost" can't be mistaken for the target, then normalize
# scheme-less loopback authorities to scheme form. Bare non-loopback hosts stay
# unmatched and fall through to the strict remote tier (which needs a URL).
cmd_urls=$(printf '%s' "$noq" | sed -E 's#(^|[[:space:]=(])(localhost|127\.0\.0\.1|\[::1\]|::1)#\1http://\2#g')
urls=$(printf '%s' "$cmd_urls" | grep -oE "https?://[^[:space:]\"'\`)|;&>]+")
[ -z "$urls" ] && emit ask "$ASK"
remote=0
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
    *) remote=1 ;;                    # non-localhost host -> strict remote tier
  esac
done <<< "$urls"

[ "$remote" -eq 0 ] && emit allow "curl/wget targets only localhost, with no file writes and only read-only companions."

# (6) strict remote tier: pure read-only probe to any host. Everything that
# could carry data OUT (request bodies, uploads, auth material, cookies, env
# expansion) or is a downloader-by-default (wget) falls back to ask.
# Flag checks run against cnoq — only the curl segments of the pipeline — so a
# companion's flags (grep -c, sort -u...) can't trip curl's letter checks.
printf '%s' "$cmd" | grep -Eq '(^|[;&|(])[[:space:]]*wget([[:space:]]|$)' && emit ask "$ASK"   # wget writes files by default
[ "$total_subs" -ne 0 ] && emit ask "$ASK"                                    # no substitutions at all for remote
printf '%s' "$nosq" | grep -q '\$' && emit ask "$ASK"                         # no env expansion (secret exfil channel)
cnoq=""
while IFS= read -r seg; do
  seg=$(printf '%s' "$seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
  [ -z "$seg" ] && continue
  prog=${seg%%[[:space:]]*}; prog=${prog##*/}
  [ "$prog" = "curl" ] && cnoq="$cnoq $seg"
done <<< "$(printf '%s' "$forsplit" | awk '{ gsub(/[;&|]/, "\n"); print }')"
printf '%s' "$cnoq" | grep -Eq '(^|[[:space:]])(--data|--data-ascii|--data-binary|--data-raw|--data-urlencode|--form|--form-string|--form-escape|--json)([[:space:]]|=|$)' && emit ask "$ASK"
printf '%s' "$cnoq" | grep -Eq '(^|[[:space:]])(--user|--oauth2-bearer|--netrc|--netrc-file|--netrc-optional|--aws-sigv4|--cert|--key|--cookie|--cookie-jar)([[:space:]]|=|$)' && emit ask "$ASK"
printf '%s' "$cnoq" | grep -Eq '(^|[[:space:]])(--proxy|--preproxy|--connect-to|--resolve|--interface|--unix-socket|--abstract-unix-socket|--doh-url)([[:space:]]|=|$)' && emit ask "$ASK"   # rerouting a "read-only" probe
# short flags checked as clusters so glued forms (-sd, -su, -sb...) can't slip:
# d/F data, u auth, b/c cookies, E cert, x proxy. X needs its method inspected.
for cluster in $(printf '%s' "$cnoq" | grep -oE '(^|[[:space:]])-[A-Za-z]+' | sed -E 's/^[[:space:]]*-//'); do
  printf '%s' "$cluster" | grep -q '[dFubcEx]' && emit ask "$ASK"
  case "$cluster" in
    *X*) m=${cluster#*X}
         [ -z "$m" ] && m=$(printf '%s' "$cnoq" | sed -E "s/.*(^|[[:space:]])-[A-Za-z]*X[[:space:]]+([^[:space:]]+).*/\2/")
         case "$m" in GET|HEAD|get|head) ;; *) emit ask "$ASK" ;; esac ;;
  esac
done
xreq=$(printf '%s' "$cnoq" | grep -oE '(^|[[:space:]])--request([[:space:]]+|=)[^[:space:]]+' | sed -E 's/.*--request([[:space:]]+|=)//')
if [ -n "$xreq" ]; then
  while IFS= read -r m; do
    case "$m" in GET|HEAD|get|head) ;; *) emit ask "$ASK" ;; esac
  done <<< "$xreq"
fi
printf '%s' "$cmd" | grep -Eq '(^|[[:space:]])(-H|--header)([[:space:]]*=?[[:space:]]*)@' && emit ask "$ASK"   # header-from-file
printf '%s' "$cmd" | grep -Eq -- '--variable|--expand-' && emit ask "$ASK"                                     # curl templating can read env/files
printf '%s' "$cmd" | grep -Eiq 'authorization[: ]|x-api-key|api[-_]?key=|access_token=|client_secret=|bearer |cookie[: =]' && emit ask "$ASK"

emit allow "curl is a read-only GET/HEAD probe: no data, auth, cookies, env expansion, or file writes."
