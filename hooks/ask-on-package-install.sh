#!/usr/bin/env bash
# PreToolUse(Bash) hook: force a confirmation prompt for any package install/add,
# even when the package manager is otherwise allowlisted (incl. npx/corepack wrappers,
# pnpm@version pins, and flags before the subcommand). Errs toward asking — never
# silently lets a real install through.
cmd="$(jq -r '.tool_input.command // empty')"
# strip quoted strings first so a literal mention (e.g. git commit -m "npm install
# fix", or echo "run npm install") isn't mistaken for a real install.
cmd=$(printf '%s' "$cmd" | sed -E "s/'[^']*'//g; s/\"[^\"]*\"//g")
# neutralize `run <script>` so a script literally named install/add/ci/i/etc.
# (e.g. `npm run ci`) isn't mistaken for a real install. A real install elsewhere
# in the command (`npm run build && npm install x`) still matches.
cmd=$(printf '%s' "$cmd" | sed -E 's/(^|[[:space:]])run[[:space:]]+(install|add|ci|i|update|upgrade)([[:space:]]|$)/\1run SCRIPT\3/g')
if printf '%s' "$cmd" | grep -Eq '(npm|pnpm|yarn|bun)(@[^[:space:]]+)?[[:space:]]+([^&|;]*[[:space:]])?(install|add|ci|update|upgrade|i)([[:space:]]|$)'; then
  printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Package install/add detected — confirm before installing dependencies."}}'
fi
exit 0
