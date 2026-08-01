#!/usr/bin/env bats
#
# Regression tests for hooks/git-flag-guard.sh.
#
# The hook's whole value is that it fails in the SAFE direction: a command it
# misparses should end up denied or ignored, never waved through. So the tests
# are split three ways --
#
#   deny    the bypass this hook exists to stop; regressions here are security bugs
#   allow   read-only subcommands it vouches for, so they don't prompt
#   silent  no opinion -- falls through to the normal permission rules
#
# A "silent" expectation is a real assertion, not a shrug: it means the hook
# correctly recognised the command as none of its business.
#
# Run: bats tests/git-flag-guard.bats

HOOK="${HOOK:-$BATS_TEST_DIRNAME/../hooks/git-flag-guard.sh}"

decision() {
  local out
  out=$(printf '{"tool_input":{"command":%s}}' "$(printf '%s' "$1" | jq -Rs .)" \
        | bash "$HOOK" 2>&1)
  if   printf '%s' "$out" | grep -q '"permissionDecision":"deny"';  then echo deny
  elif printf '%s' "$out" | grep -q '"permissionDecision":"allow"'; then echo allow
  else echo silent
  fi
}

assert_decision() { # <expected> <command>
  local got
  got=$(decision "$2")
  if [ "$got" != "$1" ]; then
    printf 'command:  %s\nexpected: %s\ngot:      %s\n' "$2" "$1" "$got" >&2
    return 1
  fi
}

# --------------------------------------------------------------------------
# The bypass this hook exists to close. These must never regress to allow.
# --------------------------------------------------------------------------

@test "deny: -C reaching a write subcommand" {
  assert_decision deny 'git -C /repo push'
}

@test "deny: --git-dir reaching a write subcommand" {
  assert_decision deny 'git --git-dir=/repo/.git push'
}

@test "deny: --work-tree reaching a write subcommand" {
  assert_decision deny 'git --work-tree=/repo commit -m wip'
}

@test "deny: -c can set command-executing config even under a read-only sub" {
  assert_decision deny 'git -c core.pager=/tmp/evil.sh log'
}

@test "deny: --config-env is the same hole by another name" {
  assert_decision deny 'git --config-env=core.pager=EVIL log'
}

@test "deny: a write sub behind -C survives later pipeline stages" {
  assert_decision deny 'cd /tmp && git -C /repo reset --hard HEAD~1 | tee out.txt'
}

# Wrapper commands still put git in command position. sudo/doas are denied
# outright in settings.json, but env/command are not -- so they must still
# resolve to the git underneath.

@test "deny: env wrapper still resolves the git underneath" {
  assert_decision deny 'env git -C /repo push'
}

@test "deny: command wrapper still resolves the git underneath" {
  assert_decision deny 'command git -C /repo push'
}

@test "deny: env assignment prefix does not hide the git" {
  assert_decision deny 'GIT_TRACE=1 git -C /repo push'
}

# --------------------------------------------------------------------------
# Read-only subcommands behind global flags: vouched, so they don't prompt.
# --------------------------------------------------------------------------

@test "allow: -C with a read-only subcommand" {
  assert_decision allow 'git -C /repo log'
}

@test "allow: -C with diff" {
  assert_decision allow 'git -C /repo diff --stat'
}

@test "allow: cosmetic --no-pager with a read-only subcommand" {
  assert_decision allow 'git --no-pager log --oneline -5'
}

# --------------------------------------------------------------------------
# None of the hook's business -> fall through to the normal rules.
# --------------------------------------------------------------------------

@test "silent: plain git with no global flags" {
  assert_decision silent 'git status'
}

@test "silent: plain git push (settings.json asks; hook has no opinion)" {
  assert_decision silent 'git push'
}

@test "silent: write sub behind a purely cosmetic flag" {
  assert_decision silent 'git --no-pager commit -m wip'
}

# --------------------------------------------------------------------------
# BUG 1: `2>&1` was missing from the redirection list, so it fell through to
# the catch-all and was read as the SUBCOMMAND. Not read-only -> spurious deny.
# --------------------------------------------------------------------------

@test "bug1: 2>&1 is a redirection, not a subcommand" {
  assert_decision silent 'git --bare 2>&1'
}

@test "bug1: 2>&1 after a read-only sub still allows" {
  assert_decision allow 'git -C /repo log 2>&1'
}

@test "bug1: other redirection forms are not subcommands" {
  assert_decision silent 'git --bare &> /dev/null'
}

@test "bug1: a redirection must not rescue a real write sub" {
  assert_decision deny 'git -C /repo push 2>&1'
}

# --------------------------------------------------------------------------
# BUG 2: any token named `git` was treated as a git invocation, including one
# that is another tool's SUBCOMMAND -- so that tool's flags were parsed as
# git's global flags.
# --------------------------------------------------------------------------

@test "bug2: gitleaks' git subcommand is not a git invocation" {
  assert_decision silent 'gitleaks git --staged --redact --no-banner 2>&1'
}

@test "bug2: jj's git subcommand is not a git invocation" {
  assert_decision silent 'jj git push --branch main'
}

@test "bug2: gh's git-ish args are not a git invocation" {
  assert_decision silent 'gh api repos/x/y --jq .git'
}

@test "bug2: a real git later in the same line is still caught" {
  assert_decision deny 'gitleaks git --staged 2>&1 && git -C /repo push'
}
