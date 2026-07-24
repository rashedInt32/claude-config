#!/usr/bin/env bash
# PreToolUse(Bash) hook: auto-allow READ-ONLY `python -c` inspection one-liners.
#
# Why this exists: `python3 -c "..."` prompts even for pure data inspection
# (e.g. json.load(open(p)) + print), for two reasons the static allowlist can't
# fix:
#   1. interpreters are DELIBERATELY excluded from allow-readonly-pipeline's
#      read-only program set (they run arbitrary code), so that hook stays
#      silent on python; and
#   2. a built-in Claude Code heuristic -- "newline followed by # inside a quoted
#      argument can hide arguments from path validation" -- forces an ask that a
#      static `Bash(python3:*)` allow rule cannot override. Only a hook `allow`
#      can. Python comments (`# ...`) on their own line trip it every time.
#
# This hook vouches ONLY the narrow, provably-read-only shape:
#   * a SINGLE command -- no ; && || | & chaining, no redirects, no command/
#     process substitution (checked on the quote-stripped "skeleton");
#   * whose program is python / python2 / python3 / pythonX.Y;
#   * invoked with -c "<script>" (not a .py file, not -m module, not - stdin,
#     not -i interactive -- those we cannot vet);
#   * whose script contains NONE of the write / exec / network / dynamic-eval
#     constructs blocklisted below, opens no file in a write mode, and references
#     no secret path.
# Anything else -> stay silent (exit 0, no opinion), so the normal prompt and the
# sibling hooks still apply.
#
# Doctrine (same as the sibling hooks): a hook `allow` bypasses deny rules, so
# the vouch is STRICT and FAIL-SAFE -- the scan errs toward BAILING (a false
# "prompt" is safe; a false "allow" is not). This is footgun-prevention, not a
# sandbox: `python3` is already as powerful as the allowlisted `node:*`, so the
# goal is only to keep obvious writes/exec/exfil behind the prompt, not to
# contain a determined adversary who controls the command.
#
# Layering notes:
#   * deny-secret-access runs FIRST and `deny` beats any `allow` -- but it STRIPS
#     the quoted -c script before its path scan, so a secret path INSIDE the
#     script is invisible to it. Therefore this hook does its OWN secret-path
#     check and bails if the script names one.
#   * Read-mode open() is allowed (so json.load(open(p)) passes); any write /
#     append / exclusive / update mode literal makes us bail.
#   * re.compile(...) and `import json` etc. are read-only and must pass, so
#     `compile(` and the plain `import` statement are NOT blocklisted; only the
#     builtin exec/eval and __import__/importlib dynamic forms are.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# --- structural: must be a single python -c invocation, nothing chained -------
# Strip single-quoted then double-quoted spans. Single first, so the single-
# quoted strings that live INSIDE the double-quoted -c script are removed before
# we drop the outer double-quoted arg -- leaving a clean "skeleton" of program +
# flags + any shell metacharacters that sit OUTSIDE quotes. Chaining, redirects
# and substitutions reveal themselves in that skeleton.
skel=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")

# any shell control metacharacter left in the skeleton -> not a lone command.
# (`\$\(` catches command substitution; process subst <(/>( is caught by < >.)
printf '%s' "$skel" | grep -Eq '[;&|<>`]|\$\(' && exit 0

# first skeleton token must be a python interpreter (basename).
prog=$(printf '%s' "$skel" | sed -E 's/^[[:space:]]+//')
prog=${prog%%[[:space:]]*}
prog=${prog##*/}
case "$prog" in
  python|python2|python3|python[0-9].[0-9]|python[0-9].[0-9][0-9]) : ;;
  *) exit 0 ;;
esac

# must be the -c form; reject the exec-ish flags we cannot vet (-m module,
# -i interactive, bare - = read from stdin).
printf '%s' "$skel" | grep -Eq '(^|[[:space:]])-c([[:space:]]|$)' || exit 0
printf '%s' "$skel" | grep -Eq '(^|[[:space:]])-[A-Za-z]*[mi]' && exit 0
printf '%s' "$skel" | grep -Eq '(^|[[:space:]])-([[:space:]]|$)' && exit 0

# --- content: block write / exec / network / dynamic-eval constructs ----------
# Scanned against the RAW command (the script lives inside it). Over-matching a
# construct that only appears in some innocent string just yields a prompt, which
# is safe; the direction we must never miss is a hidden write/exec.
# `(` after eval/exec disambiguates the builtins from words like "evaluate";
# re.compile is benign so `compile` is intentionally absent.
danger='os\.(system|popen|posix_spawn|exec|spawn|remove|unlink|rmdir|removedirs|rename|replace|mkdir|makedirs|chmod|chown|chflags|lchmod|link|symlink|truncate|ftruncate|write|writev|pwrite|open|fdopen|fork|forkpty|kill|killpg|putenv|unsetenv|setuid|setgid|dup2)'
danger="$danger"'|subprocess|shutil|pickle|shelve|marshal|ctypes|importlib|__import__|execfile|runpy|tempfile|sqlite3'
danger="$danger"'|socket|urllib|httplib|http\.client|http\.server|requests|httpx|aiohttp|ftplib|smtplib|poplib|imaplib|telnetlib|xmlrpc|webbrowser|paramiko'
danger="$danger"'|(^|[^[:alnum:]_])(pty|ssl|dill|cffi|mmap|fcntl)([^[:alnum:]_]|$)'
danger="$danger"'|eval[[:space:]]*\(|exec[[:space:]]*\(|input[[:space:]]*\(|raw_input|sys\.stdin'
danger="$danger"'|\.write[[:space:]]*\(|\.writelines|\.write_text|\.write_bytes|\.truncate[[:space:]]*\(|\.unlink[[:space:]]*\(|\.rmdir[[:space:]]*\(|\.mkdir[[:space:]]*\(|\.rename[[:space:]]*\(|\.replace[[:space:]]*\(|\.touch[[:space:]]*\(|\.chmod[[:space:]]*\(|\.symlink_to|\.hardlink_to|\.rmtree'
printf '%s' "$cmd" | grep -Eq "$danger" && exit 0

# builtin open() in a write/append/exclusive/update mode -> bail. Read modes
# (default / 'r' / 'rb' / 'rt') carry no w|a|x|+, so json.load(open(p)) passes.
# Matches a quoted mode-literal made ONLY of mode chars that includes w|a|x|+.
printf '%s' "$cmd" | grep -Eq "[\"'][rbtU]*[wax+][rwaxbt+U]*[\"']" && exit 0

# secret path referenced anywhere -- including inside the -c script, which
# deny-secret-access strips before its own scan -> don't vouch, let it prompt.
secret='(\.env([^[:alnum:].]|$)|\.env\.[A-Za-z0-9_.-]+|\.ssh([^[:alnum:].]|$)|\.aws([^[:alnum:].]|$)|\.gnupg([^[:alnum:].]|$)|\.azure([^[:alnum:].]|$)|\.kube([^[:alnum:].]|$)|\.config/gcloud|(^|/)secrets/|id_(rsa|dsa|ecdsa|ed25519)([^[:alnum:]]|$)|\.pem([^[:alnum:]]|$)|\.key([^[:alnum:]]|$)|\.p12([^[:alnum:]]|$)|\.pfx([^[:alnum:]]|$)|\.keystore([^[:alnum:]]|$)|\.netrc([^[:alnum:]]|$)|\.git-credentials|\.docker/config\.json|service-account[A-Za-z0-9_.-]*\.json|(^|[/[:space:]])credentials([[:space:];|&]|$)|\.secret([^[:alnum:]]|$))'
printf '%s' "$cmd" | grep -Eq "$secret" && exit 0

printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"read-only python -c inspection: single command (no chaining/redirect/substitution), no write/exec/network/eval constructs, no write-mode open, no secret paths."}}'
exit 0
