#!/usr/bin/env bash
# check-secrets.sh -- block a commit that stages a credential.
#
# This repo is public, and the thing it mirrors (~/.claude/settings.json) sits
# next to real MCP tokens and API keys. .gitignore already keeps the obvious
# files out, but a gitignore only knows filenames -- it can't catch a token
# pasted into a README, a command example, or a settings.example.json field.
# gitleaks matches on content, so it covers the case the ignore list can't.
#
# Blocking by design, unlike check-deny-drift.sh next to it. That one warns
# because stale docs are recoverable. This one blocks because a credential that
# reaches a public remote is scraped within minutes and is not recoverable --
# deleting the line or rewriting history does not un-leak it.
#
# Escape hatch for a false positive is .gitleaksignore, not an env var: the
# fingerprint gets committed and reviewed alongside the code. An env-var bypass
# would be trivially settable by any agent running commits in this repo, which
# defeats the point.

set -uo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -n "$repo_root" ] || exit 0

# Not installed is the normal case on a fresh clone or in CI. Don't fail the
# commit over a missing tool, but don't pretend the scan happened either --
# silence here would read as "clean".
if ! command -v gitleaks >/dev/null 2>&1; then
  printf '\n  check-secrets: gitleaks not installed -- staged changes were NOT scanned.\n'
  printf '  Install it with: brew install gitleaks\n\n'
  exit 0
fi

cd "$repo_root" || exit 0

# --staged   scans the index, which is exactly what is about to be committed.
# --redact   keeps the matched value out of terminal scrollback and shell logs.
# --verbose  without it gitleaks prints only "leaks found: 1" and you are left
#            guessing which file; with it you get RuleID, File, Line, and the
#            Fingerprint needed for an exception -- all still redacted.
if gitleaks git --staged --redact --verbose --no-banner 2>&1; then
  exit 0
fi

printf '\n  check-secrets: staged changes look like they contain a credential.\n\n'
printf '  Commit blocked. This repo is public -- a secret pushed here is\n'
printf '  compromised the moment it lands, so treat it as leaked:\n\n'
printf '    1. Unstage it       git restore --staged <file>\n'
printf '    2. ROTATE the key   revoke and reissue it, even if it never pushed\n'
printf '    3. Re-commit\n\n'
printf '  If it is a false positive, copy the Fingerprint line printed above\n'
printf '  into .gitleaksignore, one per line:\n\n'
printf '    echo "settings.example.json:generic-api-key:42" >> .gitleaksignore\n\n'
printf '  and commit .gitleaksignore alongside the change, so the exception is\n'
printf '  visible in review rather than buried in shell history.\n\n'

exit 1
