#!/usr/bin/env bats
#
# Regression tests for hooks/ask-on-force-push.sh.
#
# Why this hook exists: `permissions.ask` patterns are PREFIX matches, so
# `Bash(git push --force:*)` only fires when the flag sits immediately after
# `push`. `git push origin main --force` matches nothing. While a blanket
# `Bash(git push:*)` ask rule was in place that gap was hidden, because every
# push prompted anyway. This hook closes it directly, so force-push protection
# no longer depends on argument order.
#
#   ask     a force push in any spelling; regressions here are security bugs
#   silent  no opinion -- falls through to the normal permission rules
#
# A "silent" expectation is a real assertion: a hook `ask` outranks auto mode
# and drags the command back to a manual prompt, so over-matching is a real
# cost, not a harmless false positive.
#
# Run: bats tests/ask-on-force-push.bats

HOOK="${HOOK:-$BATS_TEST_DIRNAME/../hooks/ask-on-force-push.sh}"

decision() {
  local out
  out=$(printf '{"tool_input":{"command":%s}}' "$(printf '%s' "$1" | jq -Rs .)" \
        | bash "$HOOK" 2>&1)
  if printf '%s' "$out" | grep -q '"permissionDecision":"ask"'; then echo ask
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
# Force pushes. These must never regress to silent.
# --------------------------------------------------------------------------

@test "ask: --force directly after push" {
  assert_decision ask 'git push --force origin main'
}

@test "ask: --force trailing, the gap the prefix rules miss" {
  assert_decision ask 'git push origin main --force'
}

@test "ask: -f directly after push" {
  assert_decision ask 'git push -f origin main'
}

@test "ask: -f trailing" {
  assert_decision ask 'git push origin main -f'
}

@test "ask: --force-with-lease" {
  assert_decision ask 'git push --force-with-lease'
}

@test "ask: --force-if-includes" {
  assert_decision ask 'git push origin main --force-if-includes'
}

@test "ask: --force=value form" {
  assert_decision ask 'git push --force=true origin main'
}

@test "ask: +refspec is a force push with no flag" {
  assert_decision ask 'git push origin +main'
}

@test "ask: short flag cluster -uf" {
  assert_decision ask 'git push -uf origin feat'
}

@test "ask: short flag cluster -fu" {
  assert_decision ask 'git push -fu origin feat'
}

@test "ask: force push after a cd" {
  assert_decision ask 'cd /tmp/repo && git push origin main --force'
}

@test "ask: force push inside a loop body" {
  assert_decision ask 'for r in a b; do git push $r main --force; done'
}

@test "ask: global flag before push" {
  assert_decision ask 'git -C /repo push origin main --force'
}

# --------------------------------------------------------------------------
# Not this hook's business. Over-matching costs a manual prompt in auto mode.
# --------------------------------------------------------------------------

@test "silent: plain push" {
  assert_decision silent 'git push'
}

@test "silent: push with a remote and branch" {
  assert_decision silent 'git push origin main'
}

@test "silent: -u set-upstream is not a force" {
  assert_decision silent 'git push -u origin feat'
}

@test "silent: --tags is not a force" {
  assert_decision silent 'git push --tags'
}

@test "silent: --dry-run is not a force" {
  assert_decision silent 'git push --dry-run origin main'
}

@test "silent: force mentioned inside a quoted commit message" {
  assert_decision silent 'git commit -m "revert the git push --force"'
}

@test "silent: force mentioned inside a quoted echo" {
  assert_decision silent 'echo "git push -f"'
}

@test "silent: grepping for the string is not a push" {
  assert_decision silent 'grep -r "push --force" .'
}

@test "silent: a different git subcommand" {
  assert_decision silent 'git log --oneline'
}

@test "silent: not a git command at all" {
  assert_decision silent 'npm install lodash'
}

@test "silent: a path that merely contains the word push" {
  assert_decision silent 'cat scripts/git-push-notes.sh'
}
