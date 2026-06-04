#!/usr/bin/env bash
# PreToolUse(Bash) hook: force a confirmation prompt for any package install/add,
# even when the package manager is otherwise allowlisted (incl. npx/corepack wrappers,
# pnpm@version pins, and flags before the subcommand). Errs toward asking — never
# silently lets a real install through.
cmd="$(jq -r '.tool_input.command // empty')"
if printf '%s' "$cmd" | grep -Eq '(npm|pnpm|yarn|bun)(@[^[:space:]]+)?[[:space:]]+([^&|;]*[[:space:]])?(install|add|ci|update|upgrade|i)([[:space:]]|$)'; then
  printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Package install/add detected — confirm before installing dependencies."}}'
fi
exit 0
