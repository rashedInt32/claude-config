#!/usr/bin/env bash
# PreToolUse(Bash) hook: auto-allow READ-ONLY command pipelines.
#
# Claude Code's built-in matcher auto-approves a compound command only when it
# can statically decompose it AND match every leaf. It gives up on gnarly shells
# (mixed && | ; operators, 2>/dev/null redirects, `!`-prefixed glob args, etc.),
# so read-only searches like
#   rg -n foo src --glob '!**/node_modules/**' 2>/dev/null | head -30 ; echo x ; rg ...
# prompt even though rg/echo/head/cd are each allowlisted.
#
# This hook closes that gap: if EVERY segment of the command is a known
# read-only program — and there's no command/process substitution and no output
# redirect to a real file — it emits `allow`. Otherwise it stays silent (no
# opinion), so the other hooks and the normal permission rules still apply.
#
# Read-only LOOPS/CONDITIONALS are covered too: shell keywords (for/while/until/
# if/do/then/else/done/fi/...) are peeled off each segment and the command they
# wrap is validated against the same read-only set — so `for f in *.d.ts; do grep
# x "$f"; done` allows, but `for f in *; do rm "$f"; done` still bails (rm isn't
# read-only). A `for VAR in WORDS` clause executes nothing, so it's skipped.
#
# Safety: a hook `allow` bypasses deny rules, so the allowed program set is
# strict — only tools that read/transform to stdout and can neither run another
# command nor be coerced into writing (no find/xargs/sed/awk/tee/node/...).
# Fail-safe: anything we can't prove read-only yields silence, never `allow`.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# nosq: strip single-quoted content only (double-quoted $()/`` stay live).
nosq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g")
# live command/process substitution anywhere -> can't vouch -> stay silent.
printf '%s' "$nosq" | grep -Eq '\$\(|`|<\(|>\(' && exit 0

# noq: strip both quote styles for the structural (redirect/split) checks.
noq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")

# output redirection to anything but /dev/null -> stay silent. (input '<' from a
# file is read-only and fine; process subst was already rejected above.)
red=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g')
printf '%s' "$red" | grep -q '>' && exit 0

# Build the program list: drop redirects + grouping chars, split on ; && || | &,
# then take each segment's program (first token, basename).
forsplit=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g; s/[0-9]*<[[:space:]]*[^[:space:];&|]+//g' | tr -d '(){}')
progs=$(printf '%s' "$forsplit" | awk '{ gsub(/[;&|]/, "\n"); print }')

# read-only program set: stdout-oriented tools that can neither run a command nor
# read interactively. A few (sort -o, uniq IN OUT, xxd IN OUT, tree -o, base64 -o)
# CAN write a file via a flag/positional arg, but that's fine here: writing to a
# SECRET path is blocked by deny-secret-access (they aren't metadata-safe there),
# and writing to a non-secret path is already permitted by the static allowlist.
roset=" base64 basename cat cd cksum column comm cmp cut date df diff dirname du echo egrep false fgrep file grep head hexdump jq ls md5sum nl od printenv printf pwd readlink realpath rev rg seq sha256sum shasum sleep sort stat strings tac tail test [ [[ : tr tree true type uniq wc which xxd "

found=0
while IFS= read -r seg; do
  seg=$(printf '%s' "$seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
  [ -z "$seg" ] && continue
  # Peel leading shell keywords and benign assignments off the segment until we
  # reach the actual command (or nothing left). This lets read-only LOOPS and
  # CONDITIONALS be vouched for: a `for VAR in WORDS` clause and bare
  # terminators (done/fi/esac) execute nothing; do/then/else/while/until/if/elif
  # merely PRECEDE a command. Whatever command remains is still validated against
  # the read-only set below, so a non-read-only body (e.g. `do rm "$f"`, a `while
  # curl ...` condition) still bails to silence. Benign `VAR=value` assignments
  # are peeled too, but env vars that change which binary runs or how words split
  # (PATH, LD_*, DYLD_*, IFS, BASH_ENV, ...) make us stay silent.
  while [ -n "$seg" ]; do
    first=${seg%%[[:space:]]*}
    case "$first" in
      for|done|fi|esac|in)              # this segment executes no command
        seg=""; break ;;
      do|then|else|while|until|if|elif) # keyword precedes a command -> peel it
        rest=${seg#*[[:space:]]}
        [ "$rest" = "$seg" ] && { seg=""; break; }   # lone keyword
        seg=$(printf '%s' "$rest" | sed -E 's/^[[:space:]]+//'); continue ;;
    esac
    case "$first" in
      [A-Za-z_]*=*)                     # benign VAR=value assignment prefix
        name=${first%%=*}
        case "$name" in
          PATH|IFS|ENV|BASH_ENV|BASHOPTS|SHELLOPTS|CDPATH|GLOBIGNORE|FIGNORE|FPATH|PS4|PROMPT_COMMAND|HISTFILE|LD_*|DYLD_*|BASH_*)
            exit 0 ;;
        esac
        rest=${seg#*[[:space:]]}
        [ "$rest" = "$seg" ] && { seg=""; break; } # pure assignment, nothing follows
        seg=$(printf '%s' "$rest" | sed -E 's/^[[:space:]]+//'); continue ;;
    esac
    break                              # reached a real command token
  done
  [ -z "$seg" ] && continue        # segment was only keywords / benign assignments
  prog=${seg%%[[:space:]]*}
  prog=${prog##*/}
  case "$roset" in
    *" $prog "*) found=1 ;;
    *) exit 0 ;;                   # an unknown / non-read-only program -> stay silent
  esac
done <<< "$progs"

[ "$found" -eq 1 ] || exit 0       # nothing recognizable -> no opinion

printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"every segment is a read-only command (no writes, no command substitution, no redirect to a real file)."}}'
exit 0
