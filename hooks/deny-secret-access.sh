#!/usr/bin/env bash
# PreToolUse(Bash) hook: deny Bash access to secret material.
#
# The settings deny rules (Read(.env), Read(~/.ssh/**), Read(//**/*.pem), ...)
# are scoped to the Read/Edit/Write TOOLS — Bash bypasses them entirely, and
# cat/grep/rg/cp/etc. are allowlisted with `:*`, so `cat .env` or
# `cat ~/.ssh/id_rsa` would otherwise read secrets straight to stdout. This hook
# extends the same protection to Bash: any command that references a known
# secret path is DENIED (deny beats every allow, including the other hooks).
#
# Scans a quote-stripped copy so real paths (`cat .env`, `cp ~/.ssh/id_rsa /tmp`)
# are caught while prose (`git commit -m "update .env.example"`) is not. Config
# templates (.env.example/.sample/.template/.dist/.defaults/.schema) are exempt.
# Fail-safe: this only ever DENIES or stays silent — it never allows anything.

cmd="$(jq -r '.tool_input.command // empty')"
[ -z "$cmd" ] && exit 0

# strip quoted content so a literal mention in a message/string isn't treated as
# a path; real file arguments to cat/grep/cp/... are unquoted in practice.
noq=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
# neutralize safe .env lookalikes so they don't trip the .env rule
noq=$(printf '%s' "$noq" | sed -E 's/\.env\.(example|sample|template|dist|defaults|schema)/.ENVSAFE/g')

DENY="references a secret path (.env / private key / credential store). Bash access to secrets is blocked by policy - read it yourself if you truly need it."
emit_deny() { printf '%s' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"$DENY\"}}"; exit 0; }

# secret-path patterns (mirrors the Read/Edit/Write deny list)
secret='(\.env([^[:alnum:].]|$)|\.env\.[A-Za-z0-9_.-]+|\.ssh([^[:alnum:].]|$)|\.aws([^[:alnum:].]|$)|\.gnupg([^[:alnum:].]|$)|\.azure([^[:alnum:].]|$)|\.kube([^[:alnum:].]|$)|\.config/gcloud|(^|/)secrets/|(^|/)id_(rsa|dsa|ecdsa|ed25519)([^[:alnum:]]|$)|\.pem([^[:alnum:]]|$)|\.key([^[:alnum:]]|$)|\.p12([^[:alnum:]]|$)|\.pfx([^[:alnum:]]|$)|\.keystore([^[:alnum:]]|$)|\.netrc([^[:alnum:]]|$)|\.git-credentials|\.docker/config\.json|service-account[A-Za-z0-9_.-]*\.json|(^|[/[:space:]])credentials([[:space:];|&]|$)|\.secret([^[:alnum:]]|$))'

printf '%s' "$noq" | grep -Eq "$secret" && emit_deny
exit 0
