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
# command nor be coerced into writing (tee/node/sh/... stay out). find and xargs
# ARE exec-capable but get dedicated read-only checks below: find rejects its
# exec/write actions, and xargs is vouched only when the command it runs is
# itself in the read-only set (so `xargs -n1 basename` allows, `xargs rm` bails).
# Fail-safe: anything we can't prove read-only yields silence, never `allow`.
#
# READ-ONLY SED/AWK are vouched as companions too (so `cd repo && grep x f &&
# sed -n '/A/,/B/p' f | head` runs without a prompt — "read freely"). They're
# gated on the things that turn a read into a WRITE/EXEC: the in-place / script-
# file flags (-i/--in-place/-f/--file, gawk -i inplace) are rejected per-segment,
# and the quoted script(s) are scanned for write/exec constructs — awk
# `system()`/`getline`/`print … >`/`… | cmd`/`>>`, and sed `w`/`W`/`r`/`R`/`e`
# commands and `s///w`/`s///e` flags. Any of those -> stay silent (the command
# falls to the normal prompt). This is footgun-prevention consistent with the
# rest of this config (node/npm already run arbitrary code), NOT a sandbox; the
# scan errs toward bailing, and secret paths are still blocked by
# deny-secret-access, which runs first.
#
# READ-ONLY GIT is vouched too, because the built-in "cd before git can run
# untrusted repo hooks" heuristic forces an ask on `cd <dir> && git <ro>` even
# when every segment is allowlisted. A git segment passes only if its
# subcommand is in GIT_RO_SUB, no global flag precedes the subcommand (that's
# git-flag-guard's domain), and no exec/write-capable flag follows (--output,
# -O/--open-files-in-pager, --upload-pack, --ext-diff, ...). When a command
# mixes git with cd, every cd target must stay inside a trusted root
# ($HOME/Documents/codes, $HOME/.claude) or be a relative path without `..` —
# otherwise we stay silent and the built-in warning still applies.
# GIT_* env prefixes (GIT_EXTERNAL_DIFF, GIT_PAGER, ...) also force silence,
# since they can make even a read-only subcommand execute something.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# nosq: strip single-quoted content only (double-quoted $()/`` stay live).
nosq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g")
# backticks / process substitution: can't vouch -> stay silent.
printf '%s' "$nosq" | grep -Eq '`|<\(|>\(' && exit 0

# Command substitution $(...): vouch when every occurrence is FLAT (not nested)
# and not arithmetic, AND both the inner command and the outer command validate
# as read-only below. We do NOT require assignment position: a $(...) in ARGUMENT
# position (e.g. `git diff $(git merge-base develop HEAD) HEAD`) is just as safe,
# because each $(...) is replaced by a sentinel `X` and every inner command is
# appended as its own segment -- so both the outer (with X) and the inner must
# pass the read-only program check. A $(...) in COMMAND position is rejected for
# free: its `X` lands in the program slot, and `X` isn't read-only, so the
# segment bails. This makes `f=$(find . | head -1); grep x "$f"` and
# `git diff $(git merge-base develop HEAD) HEAD` vouch, while `$(printf rm) file`
# (X at command position), `"$(rm -rf x)" f` (rm inner not read-only),
# `f=$(rm x)`, nested `$(echo $(date))`, and arithmetic `$((1+2))` do not.
if printf '%s' "$nosq" | grep -q '\$('; then
  printf '%s' "$nosq" | grep -q '\$((' && exit 0          # arithmetic $(( -> bail
  inners=$(printf '%s' "$nosq" | grep -oE '\$\([^()]*\)' | sed -E 's/^\$\(//; s/\)$//')
  outer=$(printf '%s' "$nosq" | sed -E 's/"?\$\([^()]*\)"?/X/g')
  printf '%s' "$outer" | grep -q '\$(' && exit 0          # leftover $( = nested -> bail
  [ -z "$inners" ] && exit 0                                # nothing extractable -> bail
  nosq="$outer ; $(printf '%s' "$inners" | tr '\n' ';')"   # outer + each inner as segments
fi

# noq: strip double quotes too for the structural (redirect/split) checks.
# (plain "[^"]*" — NOT \" — so a backslash inside a double-quoted arg, e.g. a
# grep pattern with \|, doesn't poison the class on BSD sed.)
noq=$(printf '%s' "$nosq" | sed -E 's/"[^"]*"//g')

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

# git subcommands safe to vouch (mirrors the static allowlist; never includes
# commit/push/reset/rebase/clean, so no ask/deny rule can be bypassed).
git_ro_sub=" status log diff show branch blame remote tag reflog describe rev-parse ls-files ls-tree ls-remote shortlog fetch cat-file for-each-ref name-rev merge-base rev-list grep var version show-ref diff-tree diff-index count-objects whatchanged stash "

found=0
saw_git=0
saw_sedawk=0
cd_untrusted=0
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
          PATH|IFS|ENV|BASH_ENV|BASHOPTS|SHELLOPTS|CDPATH|GLOBIGNORE|FIGNORE|FPATH|PS4|PROMPT_COMMAND|HISTFILE|LD_*|DYLD_*|BASH_*|GIT_*)
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

  if [ "$prog" = "git" ]; then
    read -ra t <<< "$seg"
    sub="${t[1]:-}"
    case "$sub" in
      ''|-*) exit 0 ;;             # bare git, or global flag before subcommand
    esac
    case "$git_ro_sub" in
      *" $sub "*) : ;;
      *) exit 0 ;;                 # not a vouched subcommand -> stay silent
    esac
    if [ "$sub" = "stash" ]; then
      [ "${t[2]:-}" = "list" ] || exit 0
    fi
    k=2
    while [ $k -lt ${#t[@]} ]; do
      case "${t[$k]}" in
        # flags that write a file or execute another program
        --output*|-o|-O*|--open-files-in-pager*|--upload-pack*|--receive-pack*|--exec*|--ext-diff)
          exit 0 ;;
      esac
      k=$((k + 1))
    done
    saw_git=1
    found=1
    continue
  fi

  case "$prog" in
    sed|awk|gawk|nawk)
      # Reject the flags that make sed/awk WRITE or load an unseen script:
      # -i/--in-place (any short cluster containing i, e.g. -ni), -f/--file
      # (program from a file we can't vet). gawk's `-i inplace` is caught by the
      # bare `-i` token too. The script-content scan after the loop covers the
      # in-program write/exec forms. Field separators (-F), -v, -n, -E, -r etc.
      # carry no write capability and pass through.
      read -ra t <<< "$seg"
      kk=1
      while [ $kk -lt ${#t[@]} ]; do
        # short cluster containing a lowercase i (in-place) or f (script-file),
        # e.g. -i, -i.bak, -ni, -f, -nf; or the long forms. -F/-v/-n/-E/-r/-s/-z
        # carry no lowercase i|f, so field-separators and friends pass through.
        if [[ "${t[$kk]}" =~ ^-[A-Za-z]*[if] ]] || [[ "${t[$kk]}" =~ ^--(in-place|file)(=|$) ]]; then
          exit 0
        fi
        kk=$((kk + 1))
      done
      saw_sedawk=1
      found=1
      continue ;;
  esac

  if [ "$prog" = "find" ]; then
    # read-only find: reject destructive / exec / file-writing actions (mirrors
    # find-guard). Used mainly to validate `find ... | head` inside a vouched
    # VAR=$(...) substitution, but applies anywhere find appears in the sweep.
    printf '%s' "$seg" | grep -Eq '(^|[[:space:]])(-delete|-exec|-execdir|-ok|-okdir|-fprint|-fprintf|-fls)([[:space:]]|$)' && exit 0
    found=1
    continue
  fi

  if [ "$prog" = "xargs" ]; then
    # read-only xargs: xargs is exec-capable, so vouch ONLY when the command it
    # runs is itself in the read-only set (e.g. `xargs -n1 basename`). Walk the
    # option tokens and stop at the first non-option -- that's the command word.
    # To stay safe we accept ONLY no-arg flags and ATTACHED option args
    # (-n1, -P4, -I{}); a SEPARATED option arg (-n 1), a replace/eof option, an
    # unknown flag, or any long option that might take an arg all BAIL. Rationale:
    # the earlier `tr -d '(){}'` strips `{}` placeholders, so a separated arg
    # could otherwise let a real command be mistaken for an option value
    # (`xargs -I {} rm` -> `xargs -I rm`). No command word found (bare xargs, or a
    # quote-hidden command stripped to nothing) also bails. Like the rest of this
    # file: footgun-prevention, not a sandbox -- a contrived `xargs "rm" f` that
    # quotes its command is out of scope (quotes are already stripped upstream).
    read -ra t <<< "$seg"
    xi=1
    xcmd=""
    while [ $xi -lt ${#t[@]} ]; do
      tok="${t[$xi]}"
      case "$tok" in
        --*=*) : ;;                                          # self-contained long opt
        --no-run-if-empty|--null|--verbose|--exit|--interactive|--open-tty) : ;;
        --*) exit 0 ;;                                       # long opt may take an arg -> bail
        -?*)
          cl="${tok#-}"; j=0; clen=${#cl}
          while [ $j -lt $clen ]; do
            c="${cl:$j:1}"
            case "$c" in
              0|o|p|r|t|x) j=$((j + 1)) ;;                   # no-arg flag char
              n|P|I|J|L|s|d|E|e|i|l|a|R|S)
                [ -z "${cl:$((j + 1))}" ] && exit 0          # separated arg form -> bail
                j=$clen ;;                                   # attached arg = rest of cluster
              *) exit 0 ;;                                   # unknown flag char -> bail
            esac
          done ;;
        *) xcmd="$tok"; break ;;                             # first non-option = the command
      esac
      xi=$((xi + 1))
    done
    [ -z "$xcmd" ] && exit 0                                 # no command word -> stay silent
    xcmd="${xcmd##*/}"
    case "$roset" in
      *" $xcmd "*) found=1; continue ;;
      *) exit 0 ;;                                           # command not read-only -> stay silent
    esac
  fi

  if [ "$prog" = "cd" ]; then
    read -ra t <<< "$seg"
    tgt="${t[1]:-}"
    case "$tgt" in
      *..*) cd_untrusted=1 ;;                             # any climb -> untrusted (even under a trusted prefix)
      ''|-) : ;;                                          # home / OLDPWD
      "$HOME/Documents/codes"|"$HOME/Documents/codes"/*) : ;;
      "$HOME/.claude"|"$HOME/.claude"/*) : ;;
      /*) cd_untrusted=1 ;;                               # absolute, outside trusted roots
      *) : ;;                                             # relative without a climb -> fine
    esac
  fi

  case "$roset" in
    *" $prog "*) found=1 ;;
    *) exit 0 ;;                   # an unknown / non-read-only program -> stay silent
  esac
done <<< "$progs"

[ "$found" -eq 1 ] || exit 0       # nothing recognizable -> no opinion
# git + a cd that leaves the trusted roots: let the built-in warning apply.
[ "$saw_git" -eq 1 ] && [ "$cd_untrusted" -eq 1 ] && exit 0

# If a sed/awk reader is present, scan the quoted script(s) for in-program
# write/exec constructs the flag check above can't see (they live inside quotes).
# We scan EVERY quoted string in the command — over-bailing on an innocent match
# inside some other tool's quoted arg (e.g. `grep 'system('`) just yields a
# prompt, which is safe; the danger direction (allowing a hidden write) is what
# we must never do.
if [ "$saw_sedawk" -eq 1 ]; then
  scripts=$(printf '%s' "$cmd" | grep -oE "'[^']*'|\"[^\"]*\"")
  # awk: command exec, pipe, getline, and output redirection from a print/printf.
  printf '%s' "$scripts" | grep -Eq 'system[[:space:]]*\(|getline|fflush[[:space:]]*\(|close[[:space:]]*\(|ENVIRON|/dev/std(in|out|err)|print[a-z]*[^;{}]*[>|]|>>|[[:space:]]\|[[:space:]]' && exit 0
  # sed: w/W/r/R (write or read-file) and e (execute) commands — after a command
  # boundary (start, ; { } !, an address digit/$, or a closing /) — plus the
  # s///w and s///e substitution flags (/ and | delimiters).
  printf '%s' "$scripts" | grep -Eq '([;{}!$/0-9]|[[:space:]])[[:space:]]*[wWrR][[:space:]]+[^[:space:];]|([;{}!$/0-9]|[[:space:]])[[:space:]]*e([[:space:]]|$)|s/[^/]*/[^/]*/[a-zA-Z0-9]*[we]|s\|[^|]*\|[^|]*\|[a-zA-Z0-9]*[we]' && exit 0
fi

printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"every segment is a read-only command (read-only sed/awk allowed; no writes, no command substitution, no redirect to a real file)."}}'
exit 0
