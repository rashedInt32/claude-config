# claude-config

A curated [Claude Code](https://docs.claude.com/en/docs/claude-code) permission setup
plus three safety hooks. The guiding principle:

> **Read freely, gate on write.** Investigation/read commands run without prompting;
> anything that changes state (writes, pushes, history rewrites, installs, deletes)
> still asks.

The real value is `settings.example.json` (the permission model) and the three hooks
in `hooks/` that close gaps a static allowlist can't.

## What's inside

```
hooks/
  ask-on-package-install.sh   # always confirm npm/pnpm/yarn/bun installs
  git-flag-guard.sh           # close the `git -C` / global-flag bypass
  allow-localhost-curl.sh     # auto-allow localhost curl/wget, ask otherwise
settings.example.json         # permissions (allow/deny/ask) + hook wiring
```

## Requirements

- Claude Code
- `jq`, `bash`, `grep`, `sed` (preinstalled on macOS; standard on Linux)

## Install

1. **Copy the hooks** into your Claude hooks directory and make them executable:
   ```sh
   mkdir -p ~/.claude/hooks
   cp hooks/*.sh ~/.claude/hooks/
   chmod +x ~/.claude/hooks/*.sh
   ```

2. **Merge `settings.example.json` into `~/.claude/settings.json`.** If you don't have
   one yet, copy it as a starting point. If you do, merge the `permissions` and `hooks`
   blocks (arrays are additive — don't drop your existing entries). The hook commands
   reference `$HOME/.claude/hooks/...`, so they work for any user.

3. **Edit the one machine-specific rule.** In `permissions.allow`, replace
   ```
   "Bash(cd /CHANGE-ME/to/your/projects/root*)"
   ```
   with the absolute path to where your code lives, e.g. `"Bash(cd /Users/you/code*)"`.
   (Permission rules match the literal command text, so use the real absolute path —
   `~` won't expand here.)

4. **Restart Claude Code.** Hooks hot-reload, but **permission rules are read at
   startup** — changes to `allow`/`deny`/`ask` only take effect after a restart (or
   reopening via `/hooks`).

## The three hooks

### `ask-on-package-install.sh`
The package managers (`npm`, `pnpm`, `yarn`, `bun`) are allowlisted so build/run/test
commands don't prompt — but **installs always should**. This hook detects
`install/add/ci/update/upgrade/i` anywhere in the command (including `npx pnpm@9 install`,
`pnpm -C pkg add`, `corepack pnpm add`) and forces a confirmation.

### `git-flag-guard.sh`
Allow rules are **prefix matches** (`Bash(git diff:*)`). A leading global flag shifts the
prefix: `git -C /path push` starts with `git -C`, not `git push`, so it slips past both
your `ask` rule on `git push` and your `deny` rules. This hook resolves the *real*
subcommand after skipping global flags (`-C`, `-c`, `--git-dir`, `--work-tree`, …) and:
- **allows** read-only subcommands (`diff`, `log`, `show`, `status`, …),
- **denies** everything else (`push`, `reset`, `rebase`, `commit`, …) — `cd` into the
  repo and use plain git for writes, where your normal rules apply.

It scans the whole command, so compound forms like `ls && git -C /x push` are caught too.
Tokenizes without `eval`/command-substitution, so the guard itself can't be injected.

### `allow-localhost-curl.sh`
`curl`/`wget` are deliberately **not** in the static `ask` list (an explicit `ask` rule
overrides a hook's `allow`). This hook is their sole authority:
- **allow** when every `http(s)` URL is localhost / `127.0.0.1` / `::1` **and** there are
  no file writes, dangerous tokens, or non-curl command substitutions,
- **ask** for anything else.

So localhost health-checks and port probes run silently, while outbound curl, file
writes (`-o`, `-O`, `>`), `@host` tricks, and `curl localhost && rm -rf ~` all still
prompt (and `deny` rules still hard-block the dangerous ones).

## Permission model at a glance

- **allow** — read-only git (incl. plumbing), coreutils, search tools, and JS runtimes
  (`node/npm/pnpm/bun` for build/run — installs are gated by the hook above).
- **ask** — `git push`/`--force`, `git reset --hard`, `rebase`, `filter-branch`,
  `clean -f/-fd`. (`curl`/`wget` are handled by the hook, not listed here.)
- **deny** — secrets (`.env`, SSH/GPG/cloud creds), `sudo`/`su`, `--no-verify` commits,
  `push --mirror`, and catastrophic `rm -rf` / `mkfs` / `dd` / `shutdown` forms.

## Caveats

- These are **guardrails, not a sandbox.** They reduce footguns and prompt fatigue; they
  don't contain a determined adversary. Review before adopting.
- Tested on macOS (BSD userland). The hooks use portable constructs but if you hit a
  GNU/BSD `sed`/`grep` quirk, open an issue.
- Don't commit your real `~/.claude/settings.json` — it may contain machine paths,
  tokens, or org IDs. `.gitignore` here already excludes `settings.json`.
