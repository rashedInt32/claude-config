# claude-config

A curated [Claude Code](https://docs.claude.com/en/docs/claude-code) permission setup
plus seven safety hooks. The guiding principle:

> **Read freely, gate on write.** Investigation/read commands run without prompting;
> anything that changes state (writes, pushes, history rewrites, installs, deletes)
> still asks.

The real value is `settings.example.json` (the permission model) and the seven hooks
in `hooks/` that close gaps a static allowlist can't.

## What's inside

```
hooks/
  deny-secret-access.sh       # block Bash access to .env / keys / credential stores
  ask-on-package-install.sh   # always confirm npm/pnpm/yarn/bun installs
  git-flag-guard.sh           # close the `git -C` / global-flag bypass
  allow-localhost-curl.sh     # auto-allow localhost curl/wget, ask otherwise
  find-guard.sh               # auto-allow read-only find, ask on -delete/-exec/...
  allow-readonly-pipeline.sh  # auto-allow all-read-only pipelines (incl. read-only git) the built-in matcher balks at
  nudge-sed-awk-reads.sh      # ask + nudge to grep/Read when sed/awk is used only to read
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

## The seven hooks

### `deny-secret-access.sh`
The `deny` rules for secrets (`Read(.env)`, `Read(~/.ssh/**)`, `Read(//**/*.pem)`, …) are scoped
to the **Read/Edit/Write tools** — Bash bypasses them, and `cat`/`grep`/`rg`/`cp` are allowlisted
with `:*`, so `cat .env` or `cat ~/.ssh/id_rsa` would read secrets straight to stdout. This hook
extends the same protection to Bash. When a command references a secret path (`.env`, `id_rsa`/
`id_ed25519`, `*.pem`/`*.key`/`*.p12`, `.aws`/`.ssh`/`.gnupg`/`.kube`/gcloud dirs, `.netrc`,
`.git-credentials`, `.docker/config.json`, `service-account*.json`, `secrets/`, `*.secret`) it is
**denied if it would expose the contents** — a read/copy/transmit/interpret verb (`cat`, `grep`,
`rg`, `head`, `cp`, `tar`, `curl`, `base64`, `python`, …) or a redirect that **writes into** a
secret path (`echo pwn >> ~/.ssh/authorized_keys`). A `deny` beats every allow, including the
other hooks.

Metadata-only ops are **allowed**, since they expose nothing: `ls`/`stat`/`file`/`test`/`find` and
`chmod`/`chown` on a key, plus `git` (so commit messages mentioning `.env` don't trip it). It scans
a quote-stripped copy so real paths are caught but prose isn't, and config templates
(`.env.example`/`.sample`/`.template`/`.dist`/`.defaults`/`.schema`) are exempt. Fail-safe: it only
ever denies or stays silent.



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
- **allow** when every `http(s)` URL is localhost / `127.0.0.1` / `::1`, there are no file
  writes or non-curl command substitutions, **and** every companion command is read-only
  (same allowlist as find-guard — so `curl localhost && bash -c "…"` asks),
- **ask** for anything else.

So localhost health-checks and port probes run silently, while outbound curl, file
writes (`-o`, `-O`, `>`), `@host` tricks, and `curl localhost && rm -rf ~` all still
prompt (and `deny` rules still hard-block the dangerous ones).

### `find-guard.sh`
`find` is dual-use — `-delete` and `-exec rm {} \;` are destructive — so it's deliberately
**not** allowlisted. But that means every read-only search prompts, which is noise. This
hook makes `find` usable without opening the destructive door:
- **allow** read-only `find` (`-type`, `-name`, `-ipath`, `-print`, `-prune`, …),
- **ask** when it sees `-delete`, `-exec`, `-execdir`, `-ok`, `-fprint*`, `-fls`, a file
  redirect, a `$(…)`, or **any companion command that isn't provably read-only**.

The companion check is an **allowlist, not a denylist** — every command-position program must be
`find`, a read-only tool (`cat`/`grep`/`head`/…), or a read-only `git`/`xargs` invocation.
So `find … && git log` and `find … | xargs grep` run without a prompt, while `find … && git push`,
`find … | xargs rm`, **and `find … && bash -c "…"` / `… && ./script.sh`** all ask — an
interpreter or arbitrary executable can hide a destructive payload a word-scan can't see, so it
never rides along inside an "allowed" find. Dangerous words inside quotes (`-name '*git*'`,
`echo "rm -rf"`) and inside paths don't trip it — only real command-position programs do.

Why a hook instead of "just use `fd`"? Because a *preference* to use `fd` can't be relied
on — it doesn't propagate across projects or sessions, and pasted `find` one-liners ignore
it. A hook in `settings.json` is **global and deterministic**: read-only `find` works
everywhere, destructive `find` is gated everywhere. (`fd` is still allowlisted and is a
fine, faster choice when you reach for it.)

### `allow-readonly-pipeline.sh`
Claude Code's built-in matcher auto-approves a compound command only when it can statically
decompose it and match every leaf — it gives up on gnarly shells (mixed `&&`/`|`/`;`,
`2>/dev/null` redirects, `!`-prefixed glob args), so a read-only search like
`rg -n foo src --glob '!**/node_modules/**' 2>/dev/null | head` prompts even though `rg`,
`head`, `cd` are each allowlisted. This hook closes that gap:
- **allow** when *every* segment is a known read-only program (`rg`, `grep`, `cat`, `ls`,
  `head`, `tail`, `wc`, `sort`, `uniq`, `cut`, `jq`, `diff`, `cd`, `echo`, …) **and** there's
  no command/process substitution and no output redirect to a real file,
- **silent** (no opinion) otherwise — the other hooks and normal rules still apply.

It also vouches **read-only git** (`status`, `log`, `diff`, `show`, `branch`, `blame`,
`stash list`, …), which is what defeats Claude Code's built-in *"changes directory before
running git, can execute untrusted hooks"* prompt on a `cd <repo> && git log` sweep — that
built-in heuristic ignores allowlist rules and can only be overridden by a hook `allow`.
Read-only git is gated tightly: it never includes a mutating subcommand
(`commit`/`push`/`reset`/`rebase`/`clean`/`stash` save), bails on a global flag before the
subcommand (that's `git-flag-guard`'s job) or an exec/write flag after it
(`--output`, `-O`, `--upload-pack`, `--ext-diff`, …) or a `GIT_*` env prefix, and — when a
`cd` is present — requires every `cd` target to stay inside a trusted root (no climbing out
via `..`), so a malicious sibling repo's config can't ride along.

Because a hook `allow` bypasses `deny`, the read-only set is otherwise strict: it excludes every
command-runner and in-place writer (`find`, `fd`, `xargs`, `sed`, `awk`, `tee`, `node`, …),
so a write or arbitrary-exec can never ride along inside an "allowed" pipeline.

### `nudge-sed-awk-reads.sh`
`sed`/`awk` are allowlisted (so real edits/data tasks work) but deliberately **excluded** from
`allow-readonly-pipeline.sh`'s read-only set — they can write (`-i`, the `w` command,
`print > file`) or execute (`sed e`, `awk system()`), and those hide inside the script string
where a word-scan can't catch them. The side effect: a read-only sweep that uses `sed`/`awk`
*only* to slice lines can't be auto-vouched, so it falls to the built-in "cd + write / path
resolution bypass" prompt — a silent, easy-to-repeat slip. This hook turns that into a visible,
actionable **ask**:
- **ask** — with a reason naming the prompt-free alternatives (`grep -n` / `-A`/`-B`/`-C`,
  `cut -f`, `tail -n +N | head -M`, the Read tool) — when `sed`/`awk` is used purely as a reader
  inside an otherwise all-read-only sweep,
- **silent** (no opinion) otherwise.

It fires only when there's no in-place edit (`-i`/`--in-place`/`gawk -i inplace`), no write
redirect, and no command substitution, and every *other* program is read-only — so real
transforms (`awk … > out`, `sed -i`, `npm run … | sed …`) are left alone. It **only ever asks or
stays silent**, never allow/deny, so `deny-secret-access` still wins on a `sed`-reads-a-secret
case. When it fires, the intended fix is to *rewrite* with `grep`/Read, not to approve.

## Permission model at a glance

- **allow** — read-only git (incl. plumbing), coreutils, search tools, and JS runtimes
  (`node/npm/pnpm/bun` for build/run — installs are gated by the hook above).
- **ask** — `git push`/`--force`, `git reset --hard`, `rebase`, `filter-branch`,
  `clean -f/-fd`. (`curl`/`wget` are handled by the hook, not listed here.)
- **deny** — secrets (`.env`, SSH/GPG/cloud creds) via the Read/Edit/Write tools **and via Bash**
  (the `deny-secret-access.sh` hook), `sudo`/`su`, `--no-verify` commits, `push --mirror`, and
  catastrophic `rm -rf` / `mkfs` / `dd` / `shutdown` forms.

## Caveats

- These are **guardrails, not a sandbox.** They reduce footguns and prompt fatigue; they
  don't contain a determined adversary. Review before adopting.
- Tested on macOS (BSD userland). The hooks use portable constructs but if you hit a
  GNU/BSD `sed`/`grep` quirk, open an issue.
- Don't commit your real `~/.claude/settings.json` — it may contain machine paths,
  tokens, or org IDs. `.gitignore` here already excludes `settings.json`.
