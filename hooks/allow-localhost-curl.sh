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
# Command position includes loop/conditional bodies (`... ; do curl ...`).
#
# Design: a hook `allow` bypasses deny rules, so companions are checked against an
# ALLOWLIST (read-only tools / read-only git / read-only sed/awk), not a denylist
# — an interpreter or arbitrary executable next to the curl fails the check and
# asks. Quote handling: word/redirect checks use a both-quotes-stripped copy
# (noq); substitution checks strip only single quotes (nosq), since $()/`` stay
# live in double quotes; URLs are recovered from the raw command (section 5),
# because quoting a URL would otherwise erase the target entirely.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0
printf '%s' "$cmd" | grep -Eq '(^|[;&|(]|(^|[[:space:]])(do|then|else|if|elif|while|until)[[:space:]])[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*(curl|wget)([[:space:]]|$)' || exit 0   # curl/wget at command position (VAR= prefixes engage too; section 4 asks on them)

emit() { printf '%s' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"$1\",\"permissionDecisionReason\":\"$2\"}}"; exit 0; }
ASK="curl/wget is not a clean localhost-only probe (non-localhost host, file write, non-read-only companion, or dangerous command) - confirm before running."

noq=$(printf '%s' "$cmd"  | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
nosq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g")

# (1) no backticks; every $(...) must be a curl/wget call (substitutions live in double quotes)
printf '%s' "$nosq" | grep -q '`' && emit ask "$ASK"
total_subs=$(printf '%s' "$nosq" | grep -oE '\$\(' | wc -l | tr -d ' ')
curl_subs=$(printf '%s' "$nosq" | grep -oE '\$\([[:space:]]*(curl|wget)' | wc -l | tr -d ' ')
[ "$total_subs" -ne "$curl_subs" ] && emit ask "$ASK"

# (2) split the command into segments ONCE. Read-only git is neutralized to a
# single GITRO token first so its subcommand words can't look like programs.
# Leading shell keywords are peeled so loop/conditional bodies are judged by the
# command they actually run (`do curl ...` -> `curl ...`).
gitro='status|log|diff|show|branch|blame|remote|tag|reflog|describe|rev-parse|ls-files|ls-tree|ls-remote|shortlog|fetch|whatchanged|cat-file|for-each-ref|name-rev|merge-base|symbolic-ref|rev-list|grep|var|version|help'
norm=$(printf '%s' "$noq" | sed -E "s/(^|[^[:alnum:]_])git([[:space:]]+(-p|-P|--no-pager|--paginate|--no-optional-locks))*[[:space:]]+($gitro)([^[:alnum:]_]|\$)/\1 GITRO /g")
forsplit=$(printf '%s' "$norm" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g; s/[0-9]*<[[:space:]]*[^[:space:];&|]+//g' | tr -d '(){}')
segs=$(printf '%s' "$forsplit" | awk '{ gsub(/[;&|]/, "\n"); print }')

# Peel leading shell keywords off one segment; prints the remaining command (or
# nothing when the segment executes no command of its own, e.g. `done`, `fi`).
peel() {
  local s
  s=$(printf '%s' "$1" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
  while [ -n "$s" ]; do
    case "${s%%[[:space:]]*}" in
      for|done|fi|esac|in) s=""; break ;;                 # executes nothing
      do|then|else|while|until|if|elif)                   # precedes a command -> peel
        rest=${s#*[[:space:]]}
        [ "$rest" = "$s" ] && { s=""; break; }
        s=$(printf '%s' "$rest" | sed -E 's/^[[:space:]]+//'); continue ;;
      *) break ;;
    esac
  done
  printf '%s' "$s"
}

# curl-only segments, so a companion's flags (grep -o, sort -o, ls -T...) can
# never trip curl's own write-flag / short-cluster checks below.
cnoq=""
while IFS= read -r seg; do
  seg=$(peel "$seg")
  [ -z "$seg" ] && continue
  prog=${seg%%[[:space:]]*}; prog=${prog##*/}
  [ "$prog" = "curl" ] && cnoq="$cnoq $seg"
done <<< "$segs"

# (2b) curl file-writing flags that aren't /dev/null. The cluster check also
# catches glued short forms (-sO, -sJ, -sT, -sK) that word-boundary regexes miss.
printf '%s' "$cnoq" | grep -Eq '(^|[[:space:]])(-O|--remote-name|--remote-header-name|-J|--output-dir|-K|--config|-T|--upload-file|-D|--dump-header|--trace|--trace-ascii|--libcurl|--etag-save)([[:space:]]|=|$)' && emit ask "$ASK"
printf '%s' "$cnoq" | grep -Eq '(^|[[:space:]])-[A-Za-z]*[OJKTD]' && emit ask "$ASK"
for arg in $(printf '%s' "$cnoq" | grep -oE '(-o|--output)[[:space:]]+[^[:space:]]+' | sed -E 's/^(-o|--output)[[:space:]]+//'); do
  [ "$arg" != "/dev/null" ] && emit ask "$ASK"
done
# wget writes files by default; only an explicit -O /dev/null probe is a read.
if printf '%s' "$cmd" | grep -Eq '(^|[;&|(]|(^|[[:space:]])(do|then|else|if|elif|while|until)[[:space:]])[[:space:]]*wget([[:space:]]|$)'; then
  printf '%s' "$noq" | grep -Eq '(^|[[:space:]])(-[A-Za-z]*O|--output-document)[[:space:]]*=?[[:space:]]*/dev/null([[:space:]]|$)' || emit ask "$ASK"
fi

# (3) shell redirection to anything but /dev/null
sanitized=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g')
printf '%s' "$sanitized" | grep -q '>' && emit ask "$ASK"

# (4) companion allowlist: every command-position program must be curl/wget, a
# read-only tool, GITRO, or one of the vetted readers handled case-by-case.
roset=" bat base64 basename cat cd cksum column comm cmp cut date df diff dirname du echo egrep false fgrep file grep head hexdump jq ls md5sum nl od pbcopy printenv printf pwd readlink realpath rev rg seq sha256sum shasum sleep sort stat strings tac tail test [ [[ : tr tree true type uniq wc which xxd "
safe="${roset}curl wget GITRO "
saw_sedawk=0
numvars=" "                          # names assigned a bare integer in THIS command
while IFS= read -r seg; do
  seg=$(peel "$seg")
  [ -z "$seg" ] && continue
  prog=${seg%%[[:space:]]*}
  prog=${prog##*/}
  # A segment that is nothing but `NAME=<digits>` runs no command and cannot
  # carry a value anywhere else, so it is inert. Recording the name lets
  # section 5 resolve `localhost:$NAME` to a port it can actually see.
  nv=$(printf '%s' "$seg" | sed -nE 's/^([A-Za-z_][A-Za-z0-9_]*)=[0-9]+$/\1/p')
  if [ -n "$nv" ]; then
    case "$nv" in
      PATH|IFS|ENV|BASH_ENV|CDPATH|GLOBIGNORE|PS4|PROMPT_COMMAND|HISTFILE|LD_*|DYLD_*|BASH_*|GIT_*) emit ask "$ASK" ;;
    esac
    numvars="$numvars$nv "
    continue
  fi
  case "$prog" in
    *=*) emit ask "$ASK" ;;          # any other VAR=val prefix -> ask
  esac
  case "$prog" in
    # read-only sed/awk, same gate the pipeline hook uses: reject -i (in-place)
    # and -f (script from an unvetted file); the quoted script is scanned for
    # write/exec constructs before we allow (see the saw_sedawk block below).
    sed|awk|gawk|nawk)
      read -ra t <<< "$seg"
      kk=1
      while [ $kk -lt ${#t[@]} ]; do
        if [[ "${t[$kk]}" =~ ^-[A-Za-z]*[if] ]] || [[ "${t[$kk]}" =~ ^--(in-place|file)(=|$) ]]; then
          emit ask "$ASK"
        fi
        kk=$((kk + 1))
      done
      saw_sedawk=1
      continue ;;
    # xmllint/tidy pretty-print on stdin; both can write with -o/--output.
    xmllint|tidy)
      printf '%s' "$seg" | grep -Eq '(^|[[:space:]])(-o|--output)([[:space:]]|=|$)' && emit ask "$ASK"
      continue ;;
    python|python3)
      # ONLY the stdin JSON pretty-printer. Any other python invocation asks.
      printf '%s' "$seg" | grep -Eq '^python3?[[:space:]]+-m[[:space:]]+json\.tool([[:space:]]+--(indent|sort-keys|compact|no-ensure-ascii)([[:space:]]+[0-9]+)?)*[[:space:]]*$' || emit ask "$ASK"
      continue ;;
  esac
  case "$safe" in
    *" $prog "*) ;;
    *) emit ask "$ASK" ;;            # interpreter / unknown executable / writer -> ask
  esac
done <<< "$segs"

# sed/awk can hide a write or an exec inside their quoted script, which the flag
# check above cannot see. Scan every quoted string; over-bailing here only costs
# a prompt, while under-bailing would grant a hidden write.
if [ "$saw_sedawk" -eq 1 ]; then
  scripts=$(printf '%s' "$cmd" | grep -oE "'[^']*'|\"[^\"]*\"")
  printf '%s' "$scripts" | grep -Eq 'system[[:space:]]*\(|getline|fflush[[:space:]]*\(|close[[:space:]]*\(|ENVIRON|/dev/std(in|out|err)|print[a-z]*[^;{}]*[>|]|>>|[[:space:]]\|[[:space:]]' && emit ask "$ASK"
  printf '%s' "$scripts" | grep -Eq '([;{}!$/0-9]|[[:space:]])[[:space:]]*[wWrR][[:space:]]+[^[:space:];]|([;{}!$/0-9]|[[:space:]])[[:space:]]*e([[:space:]]|$)|s/[^/]*/[^/]*/[a-zA-Z0-9]*[we]|s\|[^|]*\|[^|]*\|[a-zA-Z0-9]*[we]' && emit ask "$ASK"
fi

# (5) classify targets. Flag values are matched on the quote-stripped copy (noq)
# so `-H "X: localhost"` can't pose as the target, but a quoted URL vanishes from
# noq entirely — so whole-token quoted URLs are recovered from the raw command
# (a value with inner spaces, like a header, is not a whole-token URL). Then
# scheme-less loopback authorities are normalized to scheme form. Bare
# non-loopback hosts stay unmatched and fall through to the strict remote tier.
qurls=$(printf '%s' "$cmd" | grep -oE "[\"'](https?://[^\"'[:space:]]+|(localhost|127\.0\.0\.1|\[::1\]|::1)(:[0-9]+)?(/[^\"'[:space:]]*)?)[\"']" | tr -d "\"'")
cmd_urls=$(printf '%s' "$noq $qurls" | sed -E 's#(^|[[:space:]=(])(localhost|127\.0\.0\.1|\[::1\]|::1)#\1http://\2#g')
urls=$(printf '%s' "$cmd_urls" | grep -oE "https?://[^[:space:]\"'\`)|;&>]+")
[ -z "$urls" ] && emit ask "$ASK"
remote=0
while IFS= read -r u; do
  [ -z "$u" ] && continue
  rest=${u#*://}
  authority=${rest%%[/?#]*}
  # An expansion inside the authority could rewrite the host at runtime
  # (`http://localhost:3000$X` with X='@evil.com'), so it never counts as local.
  # Sole exception: a literal loopback host followed by `:$PORT`, where PORT was
  # assigned a bare integer earlier in this same command — then the expansion is
  # a number we have actually seen, and cannot introduce a userinfo `@`.
  case "$authority" in
    *'$'*)
      a=$(printf '%s' "$authority" | sed -E 's/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/$\1/g')
      hostlit=${a%%:*}
      portref=${a#*:}
      [ "$portref" = "$a" ] && emit ask "$ASK"          # expansion is in the host, not the port
      case "$hostlit" in
        localhost|127.0.0.1|\[::1\]) ;;
        *) emit ask "$ASK" ;;
      esac
      pv=$(printf '%s' "$portref" | sed -nE 's/^\$([A-Za-z_][A-Za-z0-9_]*)$/\1/p')
      [ -z "$pv" ] && emit ask "$ASK"                   # `:$X/y`, `:${X:-3000}`, anything richer
      case "$numvars" in
        *" $pv "*) ;;
        *) emit ask "$ASK" ;;                           # value not visible in this command
      esac ;;
  esac
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
# Flag checks run against cnoq — only the curl segments of the pipeline.
printf '%s' "$cmd" | grep -Eq '(^|[;&|(]|(^|[[:space:]])(do|then|else|if|elif|while|until)[[:space:]])[[:space:]]*wget([[:space:]]|$)' && emit ask "$ASK"   # wget writes files by default
[ "$total_subs" -ne 0 ] && emit ask "$ASK"                                    # no substitutions at all for remote
printf '%s' "$nosq" | grep -q '\$' && emit ask "$ASK"                         # no env expansion (secret exfil channel)
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
