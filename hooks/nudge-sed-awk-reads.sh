#!/usr/bin/env bash
# PreToolUse(Bash) hook: nudge sed/awk-used-as-a-reader toward grep/Read/cut.
#
# sed/awk are statically allowlisted (Bash(sed:*)/Bash(awk:*)) but deliberately
# EXCLUDED from allow-readonly-pipeline.sh's read-only set, because they can write
# (-i, the w/W command, `print > f`) or execute (sed `e`, awk `system()`). So a
# read-only exploration sweep that uses sed/awk only for line/field extraction
# can't be auto-vouched, and the decision falls to Claude Code's BUILT-IN matcher,
# which throws a confusing "cd + write / path resolution bypass" prompt. That slip
# is silent and easy to repeat.
#
# This hook turns that slip into a VISIBLE, actionable ask: when sed/awk is used
# purely as a reader inside what is otherwise a read-only sweep, it returns `ask`
# whose reason names the vouched, prompt-free alternatives (grep -n / -A/-B/-C,
# cut -f, tail -n +N | head -M, the Read tool). Approving still runs the command;
# the nudge just surfaces the better form so the habit gets corrected.
#
# Fires ONLY when ALL hold, so real edits and real data tasks are left alone:
#   * sed/awk/gawk/nawk at command position (not a path/arg/quoted substring)
#   * NOT an in-place edit (-i / --in-place / gawk -i inplace) — that's a write
#   * no command/process substitution; no output redirect to a real file
#   * every OTHER command-position program is a known read-only tool
# Anything else -> stay silent (no opinion). git companions are intentionally NOT
# accepted here: a git+sed mix stays silent (falls to the built-in prompt as
# before) rather than risk this `ask`'s approval waving a git write past its own
# rule. Fail-safe: this hook only ever emits `ask` or stays silent — never allow,
# never deny.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# Fast exit when no sed/awk word is present at all (quotes stripped so a mention
# or filename can't trigger). This is only a cheap pre-filter — the segment loop
# below is the real authority on whether sed/awk is at COMMAND position, so a word
# that turns out to be an argument (e.g. `find . -name sed`) is correctly ignored
# there. The loose boundary (not just after a separator) lets `do sed` in a loop
# body through to that loop.
noq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
printf '%s' "$noq" | grep -Eq '(^|[[:space:]])(sed|awk|gawk|nawk)([[:space:]]|$)' || exit 0

# live command/process substitution anywhere -> can't reason -> stay silent.
nosq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g")
printf '%s' "$nosq" | grep -Eq '\$\(|`|<\(|>\(' && exit 0

# output redirect to anything but /dev/null -> a real task, not exploration.
red=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g')
printf '%s' "$red" | grep -q '>' && exit 0

# read-only program set (mirrors allow-readonly-pipeline.sh; git intentionally absent).
roset=" base64 basename cat cd cksum column comm cmp cut date df diff dirname du echo egrep false fgrep file grep head hexdump jq ls md5sum nl od printenv printf pwd readlink realpath rev rg seq sha256sum shasum sleep sort stat strings tac tail test [ [[ : tr tree true type uniq wc which xxd "

forsplit=$(printf '%s' "$noq" | sed -E 's/[12]?>>?[[:space:]]*\/dev\/null//g; s/[0-9]*>&[0-9-]+//g; s/&>[[:space:]]*\/dev\/null//g; s/[0-9]*<[[:space:]]*[^[:space:];&|]+//g' | tr -d '(){}')
segs=$(printf '%s' "$forsplit" | awk '{ gsub(/[;&|]/, "\n"); print }')

saw_reader=0
while IFS= read -r seg; do
  seg=$(printf '%s' "$seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
  [ -z "$seg" ] && continue
  # Peel leading shell keywords and benign VAR=value assignments (same idea as
  # allow-readonly-pipeline.sh) so sed/awk inside read-only loops/conditionals is
  # still seen. A dangerous env prefix (PATH/IFS/LD_*/...) makes us stay silent.
  while [ -n "$seg" ]; do
    first=${seg%%[[:space:]]*}
    case "$first" in
      for|done|fi|esac|in) seg=""; break ;;
      do|then|else|while|until|if|elif)
        rest=${seg#*[[:space:]]}
        [ "$rest" = "$seg" ] && { seg=""; break; }
        seg=$(printf '%s' "$rest" | sed -E 's/^[[:space:]]+//'); continue ;;
    esac
    case "$first" in
      [A-Za-z_]*=*)
        name=${first%%=*}
        case "$name" in
          PATH|IFS|ENV|BASH_ENV|BASHOPTS|SHELLOPTS|CDPATH|GLOBIGNORE|FIGNORE|FPATH|PS4|PROMPT_COMMAND|HISTFILE|LD_*|DYLD_*|BASH_*|GIT_*)
            exit 0 ;;
        esac
        rest=${seg#*[[:space:]]}
        [ "$rest" = "$seg" ] && { seg=""; break; }
        seg=$(printf '%s' "$rest" | sed -E 's/^[[:space:]]+//'); continue ;;
    esac
    break
  done
  [ -z "$seg" ] && continue
  prog=${seg%%[[:space:]]*}
  prog=${prog##*/}

  case "$prog" in
    sed|awk|gawk|nawk)
      # in-place edit on THIS invocation -> it's a write; leave to normal rules.
      if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])(-[A-Za-z]*i([.][^[:space:]]*)?|--in-place([=][^[:space:]]*)?)([[:space:]]|$)'; then
        exit 0
      fi
      # gawk -i inplace
      if printf '%s' "$seg" | grep -Eq '[[:space:]]-i[[:space:]]+inplace([[:space:]]|$)'; then
        exit 0
      fi
      saw_reader=1 ;;
    *)
      case "$roset" in
        *" $prog "*) ;;            # read-only companion, fine
        *) exit 0 ;;               # non-read-only program -> real task -> stay silent
      esac ;;
  esac
done <<< "$segs"

[ "$saw_reader" -eq 1 ] || exit 0

REASON="sed/awk used only to read inside an otherwise read-only sweep. Prefer a vouched tool that runs WITHOUT this prompt: grep -n (locate lines), grep -A/-B/-C (context around a match), cut -f (fields), tail -n +N | head -M (fixed line range), or the Read tool with offset/limit. For a pattern range like sed -n '/A/,/B/p', use grep -n -A<N> 'A' or grep the anchor then Read. Approve only if the sed/awk transform is genuinely required."
printf '%s' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"$REASON\"}}"
exit 0
