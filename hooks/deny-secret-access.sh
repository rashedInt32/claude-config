#!/usr/bin/env bash
# PreToolUse(Bash) hook: deny Bash commands that EXPOSE secret material.
#
# The settings deny rules (Read(.env), Read(~/.ssh/**), Read(//**/*.pem), ...)
# are scoped to the Read/Edit/Write TOOLS — Bash bypasses them, and the common
# read tools are allowlisted with `:*`, so `cat .env` / `cat ~/.ssh/id_rsa`
# would read secrets straight to stdout. This hook extends that protection to
# Bash, scoped to commands that actually expose contents.
#
# When a command references a secret path it is DENIED if EITHER:
#   * any command-position program is NOT a metadata-only op — i.e. it reads,
#     copies, transmits, or interprets (cat/grep/rg/head/cp/tar/curl/base64/
#     python/...), OR
#   * it redirects output INTO a secret path (echo pwn >> ~/.ssh/authorized_keys).
# Pure metadata ops on a secret are allowed: ls / stat / file / test / chmod /
# chown / find / du, plus git (so commit messages mentioning .env don't trip).
# deny beats every allow, including the other hooks. Fail-safe: only ever
# DENIES or stays silent — never allows anything.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# strip quoted content (so a prose mention isn't treated as a path), then
# neutralize safe .env lookalikes so config templates don't match.
noq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
noq=$(printf '%s' "$noq" | sed -E 's/\.env\.(example|sample|template|dist|defaults|schema)/.ENVSAFE/g')

# secret-path patterns (mirrors the Read/Edit/Write deny list)
secret='(\.env([^[:alnum:].]|$)|\.env\.[A-Za-z0-9_.-]+|\.ssh([^[:alnum:].]|$)|\.aws([^[:alnum:].]|$)|\.gnupg([^[:alnum:].]|$)|\.azure([^[:alnum:].]|$)|\.kube([^[:alnum:].]|$)|\.config/gcloud|(^|/)secrets/|(^|/)id_(rsa|dsa|ecdsa|ed25519)([^[:alnum:]]|$)|\.pem([^[:alnum:]]|$)|\.key([^[:alnum:]]|$)|\.p12([^[:alnum:]]|$)|\.pfx([^[:alnum:]]|$)|\.keystore([^[:alnum:]]|$)|\.netrc([^[:alnum:]]|$)|\.git-credentials|\.docker/config\.json|service-account[A-Za-z0-9_.-]*\.json|(^|[/[:space:]])credentials([[:space:];|&]|$)|\.secret([^[:alnum:]]|$))'

# no secret path referenced -> nothing to do
printf '%s' "$noq" | grep -Eq "$secret" || exit 0

DENY="exposes a secret path (.env / private key / credential store) via a content read, copy, transmit, or write. Bash access to secret contents is blocked by policy."
emit_deny() { printf '%s' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"$DENY\"}}"; exit 0; }

# (a) output redirection ( > / >> ) whose target is a secret path -> deny (write/overwrite a secret)
for t in $(printf '%s' "$noq" | grep -oE '>>?[[:space:]]*[^[:space:];|&<>]+' | sed -E 's/^>>?[[:space:]]*//'); do
  printf '%s' "$t" | grep -Eq "$secret" && emit_deny
done

# (b) every command-position program must be a metadata-only op; anything that
# reads/copies/transmits/interprets contents -> deny.
metasafe=" ls stat file test [ chmod chown chgrp chflags find realpath readlink dirname basename du df which type pwd cd echo printf git mkdir touch "
forsplit=$(printf '%s' "$noq" | sed -E 's/[0-9]*>>?[[:space:]]*[^[:space:];&|]+//g; s/[0-9]*>&[0-9-]+//g; s/[0-9]*<[[:space:]]*[^[:space:];&|]+//g' | tr -d '(){}')
while IFS= read -r seg; do
  seg=$(printf '%s' "$seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
  [ -z "$seg" ] && continue
  prog=${seg%%[[:space:]]*}
  prog=${prog##*/}
  case "$metasafe" in
    *" $prog "*) ;;                  # metadata-only op, doesn't expose contents
    *) emit_deny ;;                  # reader / copier / exfil / interpreter -> deny
  esac
done <<< "$(printf '%s' "$forsplit" | awk '{ gsub(/[;&|]/, "\n"); print }')"

exit 0
