# claude-config

A curated [Claude Code](https://docs.claude.com/en/docs/claude-code) permission setup
plus seven safety hooks (and two workflow hooks). The guiding principle:

> **Read freely, gate on write.** Investigation/read commands run without prompting;
> anything that changes state (writes, pushes, history rewrites, installs, deletes)
> still asks.

The real value is `settings.example.json` (the permission model) and the seven safety
hooks in `hooks/` that close gaps a static allowlist can't. Two extra workflow hooks
typecheck edited TypeScript at the end of each turn.

## What's inside

```
hooks/
  deny-secret-access.sh       # block Bash access to .env / keys / credential stores
  ask-on-package-install.sh   # always confirm npm/pnpm/yarn/bun installs
  git-flag-guard.sh           # close the `git -C` / global-flag bypass
  allow-localhost-curl.sh     # auto-allow localhost curl/wget, ask otherwise
  find-guard.sh               # auto-allow read-only find, ask on -delete/-exec/...
  allow-readonly-pipeline.sh  # auto-allow all-read-only pipelines (incl. read-only git + sed/awk) the built-in matcher balks at
  allow-readonly-python.sh    # auto-allow read-only `python -c` inspection one-liners
  record-ts-edit.sh           # (workflow) note which .ts/.tsx files were edited this turn
  typecheck-on-stop.sh        # (workflow) typecheck those projects when the turn ends
commands/
  rv.md                       # /rv  — review a diff with a fresh-context subagent
  bugfix.md                   # /bugfix — reproduce, fix, prove fixed, review
  strict.md                   # /strict — hard rules preamble for a task
scripts/
  check-deny-drift.sh         # (maintainer) warn when the example's deny list falls behind the real config
  check-secrets.sh            # (maintainer) pre-commit: block a commit that stages a credential
tests/
  git-flag-guard.bats         # deny/allow/silent cases for the git guard
settings.example.json         # permissions (allow/deny/ask) + hook wiring + editorMode
keybindings.example.json      # Shift+Enter = newline (so plain Enter submits)
CLAUDE.example.md             # optional global guidelines (skill routing)
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

3. **Point the three machine-specific settings at your own paths.**

   a. In `permissions.allow`, replace
   ```
   "Bash(cd /CHANGE-ME/to/your/projects/root*)"
   ```
   with the absolute path to where your code lives, e.g. `"Bash(cd /Users/you/code*)"`.
   (Permission rules match the literal command text, so use the real absolute path —
   `~` won't expand here.)

   b. In `hooks/allow-readonly-pipeline.sh`, set `TRUSTED_ROOTS` (near the top) to the
   same place — it defaults to `$HOME/code` and `$HOME/.claude`. This is the allowlist of
   roots where `cd <repo> && git log` sweeps are auto-approved; if your code isn't under
   one of them, read-only git will still prompt. `$HOME` **does** expand here.

   c. In `hooks/record-ts-edit.sh`, optionally set `SKIP_GLOB` to exclude a repo from
   auto-typechecking. Leave the placeholder to typecheck everything.

4. **(Optional) Editor mode & keybindings.** `settings.example.json` sets
   `"editorMode": "vim"` for vim-style editing in the prompt box (`/config` →
   *Editor mode* to toggle, or `"normal"` to disable). To make plain **Enter** submit
   and **Shift+Enter** insert a newline, copy the keybindings template:
   ```sh
   cp keybindings.example.json ~/.claude/keybindings.json
   ```
   In tmux/screen, Shift+Enter may be swallowed — `Ctrl+J` and `\`+Enter always work as
   newline fallbacks. Terminals like iTerm2/WezTerm/Ghostty/Kitty pass Shift+Enter through
   natively.

5. **(Optional) Slash commands & global guidelines.**
   ```sh
   mkdir -p ~/.claude/commands
   cp commands/*.md ~/.claude/commands/    # adds /rv, /bugfix and /strict
   cp CLAUDE.example.md ~/.claude/CLAUDE.md
   ```
   See [Slash commands & guidelines](#slash-commands--guidelines) below. `CLAUDE.md` is
   user-global guidance — merge it into yours rather than overwriting if you already have one.

6. **Restart Claude Code.** Hooks hot-reload, but **permission rules are read at
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

**Two narrow carve-outs downgrade a hard deny to a normal prompt** (never to an allow — a human
still confirms, so an imperfect match can at worst cost you a keystroke):

- **`.env` setup.** `cp .env.example .env` (and `mv`/`ln`) is the standard first step in every
  repo, and hard-denying it was pure friction. The carve-out is tight: a single simple command
  (no chaining, redirect, or substitution), exactly two positional args, the **destination** in
  the `.env` family, and the **source** referencing no secret. `-t`/`--target-directory` breaks
  the "last arg is the destination" assumption, so it disables the carve-out. Key stores
  (`.ssh`/`.aws`/`authorized_keys`) are deliberately **excluded** — those stay denied.
- **`--env-file` / `--env`.** `docker`/`podman` (and their `-compose` forms) *pass* a secret into
  a container rather than printing it. Those flag values are stripped before the secret scan, so
  a `-v ~/.ssh:/root/.ssh` mount still trips the deny.



### `ask-on-package-install.sh`
The package managers (`npm`, `pnpm`, `yarn`, `bun`) are allowlisted so build/run/test
commands don't prompt — but **installs always should**. This hook detects
`install/add/ci/update/upgrade/i` anywhere in the command (including `npx pnpm@9 install`,
`pnpm -C pkg add`, `corepack pnpm add`) and forces a confirmation.

A **script named after an install verb** is not an install: `npm run ci` and `pnpm run update`
are neutralized before the scan, so they don't prompt. A real install elsewhere in the same
command still matches (`npm run build && npm install lodash` asks).

### `git-flag-guard.sh`
Allow rules are **prefix matches** (`Bash(git diff:*)`). A leading global flag shifts the
prefix: `git -C /path push` starts with `git -C`, not `git push`, so it slips past both
your `ask` rule on `git push` and your `deny` rules. This hook resolves the *real*
subcommand after skipping global flags (`-C`, `-c`, `--git-dir`, `--work-tree`, …) and:
- **allows** read-only subcommands (`diff`, `log`, `show`, `status`, …),
- **denies** everything else (`push`, `reset`, `rebase`, `commit`, …) — `cd` into the
  repo and use plain git for writes, where your normal rules apply.

Two refinements keep that rule from over- and under-firing:

- **`-c` / `--config-env` always deny.** They can hand git a command to execute
  (`git -c core.pager=/tmp/evil.sh log` would otherwise have been vouched as a read-only `log`),
  so no subcommand is read-only enough to survive them. `-C` / `--git-dir` / `--work-tree` only
  retarget the repo, so a read-only subcommand behind them is still allowed.
- **Cosmetic flags don't force a deny.** `--no-pager`, `-p`/`--paginate`,
  `--no-optional-locks` neither retarget the repo nor enable exec, so `git --no-pager commit`
  falls through to your **normal** rules (which is what you want — a plain commit prompt)
  instead of being hard-denied, while `git --no-pager log` is still auto-allowed.

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
  redirect, a backtick, or **any companion command that isn't provably read-only**.

A `$(…)` is **deferred** to `allow-readonly-pipeline` (which vouches the read-only
`VAR=$(find …)` form), so `f=$(find . -name X | head -1); grep -n foo "$f"` no longer prompts.
A *destructive* find inside `$()` is still caught here by the `-delete`/`-exec` check above.

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
  no output redirect to a real file,
- **silent** (no opinion) otherwise — the other hooks and normal rules still apply.

**Command substitution** is vouched in one narrow, safe shape: an assignment value,
`VAR=$(…)` (or `VAR="$(…)"`), where the inner command is itself fully read-only — so
`f=$(find . -name X | head -1); grep -n foo "$f"` auto-allows. The output lands in a
variable, never at command position, and a later `$var` used *as* a command isn't read-only
so it bails. Any other `$(…)` — at command position (`$(printf rm) file`), as a bare
argument (`echo $(date)`), nested, or arithmetic — keeps the hook silent. Backticks and
process substitution always bail. (`find-guard` defers its `$(…)` ask to this hook, so a
read-only `VAR=$(find …)` no longer prompts; a destructive find inside `$()` is still caught
by `find-guard`'s `-delete`/`-exec` check.)

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

Those roots are the **`TRUSTED_ROOTS` array at the top of the hook** — set it to where your
code lives (see install step 3b). Keep it small: git can execute code from a repo's own
config, so this is an allowlist, not "anywhere". One trusted `cd` never forgives an untrusted
one — `cd /evil && cd ~/code && git log` still prompts.

It also vouches **read-only `sed`/`awk`** as companions, so a sweep like
`cd repo && grep -n serve f.ts && sed -n '/A/,/B/p' f.ts | head` runs without a prompt —
honoring *read freely*. `sed`/`awk` can write (`-i`, the `w` command, `print > file`) or
execute (`sed e`, `awk system()`), so the hook gates exactly those: it rejects the
in-place / script-file flags (`-i`/`--in-place`/`-f`/`--file`, `gawk -i inplace`) per segment,
and scans the quoted script for write/exec constructs — `awk system()`/`getline`/`print … >`/
`… | cmd`/`>>`, and `sed` `w`/`W`/`r`/`R`/`e` commands and `s///w`/`s///e` flags. Any of those,
or a shell redirect, drops it back to a normal prompt. This is footgun-prevention, not a
sandbox (the rest of the allowlist already runs arbitrary code via `node`/`npm`/`make`), and
`deny-secret-access` — which runs first — still blocks `sed`/`awk` on secret paths.

Because a hook `allow` bypasses `deny`, the read-only set is otherwise strict: it excludes every
remaining command-runner and writer (`fd`, `tee`, `node`, `sh`, …), so a write or arbitrary-exec
can never ride along inside an "allowed" pipeline. Two exec-capable tools get **dedicated
read-only checks** instead of a blanket exclusion: **`find`** is vouched only when it carries no
`-delete`/`-exec`/`-fprint*`/redirect action, and **`xargs`** only when the command it runs is
itself in the read-only set — so `ls | xargs -n1 basename` auto-allows, while `xargs rm`,
`xargs sh -c "…"`, a separated option arg (`xargs -n 1 …`), or a bare `xargs` all fall back to a
prompt. (To stay safe against the earlier `{}`-stripping, only no-arg flags and *attached* option
args — `-n1`, `-P4`, `-I{}` — are parsed; anything ambiguous bails. This mirrors `find-guard`'s
own `find … | xargs grep` vs `find … | xargs rm` split.)

`sed`/`awk` are deliberately **not** in the static `allow` list (like `find`), so this hook is
their sole authority: read-only forms auto-allow here, while `sed -i`, redirects, and the other
write/exec forms fall through to a prompt. Note this is footgun-prevention, **not** a sandbox —
the script scan is heuristic and a *crafted* `sed`/`awk` write can evade it; that's acceptable
because `node`/`npm`/`make` already run arbitrary code, and `deny-secret-access` still blocks
secret paths. If you want a hard wall, deny `sed`/`awk` outright (you lose in-place edits).

### `allow-readonly-python.sh`
`python3 -c "…"` prompts even for pure data inspection, for two reasons a static allow rule
can't fix: interpreters are deliberately excluded from `allow-readonly-pipeline`'s read-only
set (they run arbitrary code), **and** a built-in Claude Code heuristic — *"newline followed by
`#` inside a quoted argument can hide arguments from path validation"* — forces an `ask` that
`Bash(python3:*)` cannot override. Only a hook `allow` can, and a Python comment on its own
line trips it every time.

This hook is python's sole authority, and vouches exactly one narrow shape:
- a **single** command — no `;`/`&&`/`||`/`|`/`&`, no redirects, no command or process
  substitution (checked on a quote-stripped skeleton),
- program is `python` / `python2` / `python3` / `pythonX.Y`,
- invoked as **`-c "<script>"`** — not a `.py` file, not `-m module`, not `-` stdin, not `-i`
  (those can't be vetted),
- and the script contains **no** write / exec / network / dynamic-eval construct
  (`open(…, 'w')`, `os.system`, `subprocess`, `socket`, `requests`, `eval`, `exec`, `__import__`,
  …) and references no secret path.

So `python3 -c "import json;print(json.load(open('a.json'))['k'])"` runs silently, while anything
that writes, shells out, reaches the network, or reads a `.env` falls back to a prompt. Same
doctrine as its siblings: a hook `allow` bypasses `deny`, so the scan errs toward **bailing** — a
false prompt is safe, a false allow is not. Footgun-prevention, not a sandbox (`python3` is
already as powerful as the allowlisted `node:*`).

## Workflow hooks (TypeScript typecheck on stop)

These two aren't about safety — they keep a fast feedback loop on TypeScript edits without
adding per-edit noise. Wired as `PostToolUse` (Write|Edit) and `Stop` in `settings.example.json`.

### `record-ts-edit.sh`
A `PostToolUse` hook on `Write|Edit`. It does **no** typechecking — it just appends each edited
`.ts`/`.tsx` path to a per-session queue file (`$TMPDIR/claude-tsq-<session>.txt`). Instant and
silent, so editing produces zero prompts or delay. Set `SKIP_GLOB` at the top to exclude repos
you never want auto-typechecked (e.g. a vendored repo with its own checks); leave it pointing at a
non-existent path to check everything.

### `typecheck-on-stop.sh`
A `Stop` hook that fires once when the turn ends. It reads the queue, resolves the nearest
`package.json` above each edited file, and typechecks each unique project — preferring
`pnpm typecheck`, falling back to a local `tsc --noEmit`.

It is **warn-only**: on failure it surfaces the errors in files you edited this turn as a
non-blocking note and the turn ends normally. An earlier version blocked once to force a fix
round-trip; that traded a real interruption for a check you can act on when you choose. Errors
elsewhere in the project are left alone — only files touched this turn are reported. The queue is
cleared either way.

To skip the typecheck entirely, create the opt-out sentinel:
```sh
touch ~/.claude/.no-typecheck    # rm it to re-enable
```

## Slash commands & guidelines

Optional, unrelated to the permission model — copy them or don't.

### `/rv` — review a diff
Hands **only the diff** (never the conversation or the writer's reasoning) to a fresh-context
code-reviewer subagent, whose stance is *assume the code is wrong*. It picks the diff
automatically — explicit `$ARGUMENTS` range, else uncommitted changes, else the branch against
its merge-base — and reports it before reviewing. Flags **only** correctness bugs, gaps against
stated requirements, and security issues; style and refactors go in a separate non-blocking
"optional" list. Hunts specifically for code that typechecks but misbehaves (eager vs lazy, wrong
default, inverted condition, off-by-one, stale state), workarounds that need a long comment to
justify themselves, and weakened or deleted assertions. Told plainly not to invent issues to look
useful.

It is told to **prove findings by execution** — a reproduced bug beats a plausible one — and may
build, test, and drive loopback. That capability needs a leash, so it must stop and ask before
reaching a non-loopback host, writing outside a scratch directory, or using credentials from the
environment. A local server is usually already running: it reuses that one after confirming the
server actually serves the current diff, and it may never kill or restart a server it did not
start. Output is findings only, with at most three lines on what the change gets right.

### `/bugfix` — reproduce, fix, prove, review
A six-step loop for bug work, built around one rule: **no red check, no fix.** Step 1 builds a
single check that fails on this bug, taking the cheapest form that works — a devtools
`evaluate_script` assertion returning a boolean (the default for anything in a browser), a
throwaway test when devtools can't reach it, or a Playwright script only for intermittent bugs.
If no check can be built it stops rather than hypothesising. Visual bugs are handed back with
that said plainly, because a screenshot is not an assertion.

It then **pauses for your approval** of the diagnosis before touching code. After the fix it
re-runs the *same* invocation, which must now go green, and shows red and green together. The
repro is throwaway by default: at the end it asks whether to keep or bin it, with a
recommendation — keep if the bug reached users or sits at a stable seam, bin if it drives
internals or needed heavy mocking. Finishes by running `/rv` on the diff. Never commits, never
pushes.

Assumes [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) and
[mattpocock/skills](https://github.com/mattpocock/skills) are installed; the devtools branch
needs the `chrome-devtools` MCP server. Drop the skill references if you use something else.

### `/strict` — hard rules for a task
Prepends eight non-negotiable rules to `$ARGUMENTS`: no workarounds or stubs, minimal change,
tests are ground truth (never skip or weaken one to go green), no history-discarding git
(`stash`/`reset`), match existing patterns, check for correct-not-just-compiling, verify before
claiming done and show the output, and stop and ask rather than guess.

### `CLAUDE.example.md`
User-global guidance, two rules. The first routes security-sensitive work (auth, secrets,
untrusted input, data storage) to a hardening skill **before** the code gets written. It assumes
[addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) is installed — adjust or
drop the skill name if you use something else.

The second is a **response shape** rule: lead diagnosis and fix turns with a three-line
Verified / Issue / Fix block, skip it on open questions, keep sentences short, and cap the
response at three sections. It exists because the same guidance kept in an auto-memory file did
not work — only the one-line memory *index* loads each session, so the constraints themselves
were never in context. Behavioural rules that must fire on every turn belong in `CLAUDE.md`;
memory is for facts you look up when they become relevant.

### `scripts/check-deny-drift.sh` (maintainer only)
`settings.example.json` is a hand-maintained mirror of a real `~/.claude/settings.json`, and the
`deny` list is the part carrying actual security weight. If a deny rule lands in the real config
and not the example, everyone adopting this repo gets *less* protection than the maintainer
decided they needed — and nothing catches it. This script diffs the two `permissions.deny` arrays
and reports both directions, comparing the **staged** example (what will actually be committed)
rather than the working tree.

Warn-only: it prints and exits 0. These settings deny `git commit --no-verify`, so a blocking
hook would be a trap with no way out; flip the final `exit 0` to `exit 1` if you want it to block
anyway. It exits silently when `~/.claude/settings.json` is absent, so clones and CI are unaffected.

```sh
./scripts/check-deny-drift.sh                       # one-off
CLAUDE_SETTINGS=/path/to/settings.json ./scripts/check-deny-drift.sh   # compare against another config

printf '#!/usr/bin/env bash\nexec "$(git rev-parse --show-toplevel)/scripts/check-deny-drift.sh"\n' \
  > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit            # run on every commit
```

## Permission model at a glance

- **allow** — read-only git (incl. plumbing), coreutils, search tools, and JS runtimes
  (`node/npm/pnpm/bun` for build/run — installs are gated by the hook above).
- **ask** — `git push`/`--force`, `git reset --hard`, `rebase`, `filter-branch`,
  `clean -f/-fd`. (`curl`/`wget` are handled by the hook, not listed here.)
- **deny** — secrets (`.env`, SSH/GPG/cloud creds) via the Read/Edit tools **and via Bash**
  (the `deny-secret-access.sh` hook), `sudo`/`su`, `--no-verify` commits, `push --mirror`, and
  catastrophic `rm -rf` / `mkfs` / `dd` / `shutdown` forms.

> **Note on `Write(.env)`.** *Reading* a `.env` is denied everywhere, but **creating** one is
> not: there are no `Write(.env*)` deny rules, so scaffolding a fresh `.env` goes through the
> normal prompt. `Edit(.env*)` **is** still denied — editing implies reading the existing
> secret first. If you'd rather block creation too, add back:
> ```json
> "Write(.env)", "Write(.env.*)", "Write(//**/.env)", "Write(//**/.env.*)"
> ```

## Contributing / maintainer setup

Tests for the git guard use [bats](https://github.com/bats-core/bats-core):

```sh
brew install bats-core        # or: npm i -g bats
bats tests/git-flag-guard.bats
```

They assert three outcomes per command — `deny` (the bypass the hook exists to
stop), `allow` (read-only, vouched so it doesn't prompt), and `silent` (no
opinion, falls through to the normal rules). A `silent` expectation is a real
assertion: it means the hook correctly recognised the command as none of its
business. Run them before touching `hooks/git-flag-guard.sh` — the deny cases
are the ones that must never regress.

Git does not track `.git/hooks/`, so the two maintainer checks in `scripts/`
have to be wired up by hand once per clone:

```sh
cat > .git/hooks/pre-commit <<'EOF'
#!/usr/bin/env bash
root=$(git rev-parse --show-toplevel) || exit 0
"$root/scripts/check-secrets.sh" || exit 1
exec "$root/scripts/check-deny-drift.sh"
EOF
chmod +x .git/hooks/pre-commit
```

`check-secrets.sh` **blocks** the commit (a credential reaching a public remote
is scraped within minutes and can't be un-leaked; rotate it, don't just delete
the line). It needs `gitleaks` — without it the check warns and lets the commit
through rather than breaking on a machine that doesn't have it. False positives
go in `.gitleaksignore` as fingerprints, so the exception is visible in review.
`check-deny-drift.sh` only warns.

## Caveats

- These are **guardrails, not a sandbox.** They reduce footguns and prompt fatigue; they
  don't contain a determined adversary. Review before adopting.
- Tested on macOS (BSD userland). The hooks use portable constructs but if you hit a
  GNU/BSD `sed`/`grep` quirk, open an issue.
- Don't commit your real `~/.claude/settings.json` — it may contain machine paths,
  tokens, or org IDs. `.gitignore` here excludes `settings*.json` (broad on purpose: it
  catches `settings.local.json` and stray copies like `settings.backup.json` too) and
  negates `settings.example.json` back in. Note that `.gitignore` has no effect on a file
  that's already tracked, or on `git add -f`.
