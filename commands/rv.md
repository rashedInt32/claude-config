Review a diff with the code-reviewer subagent (fresh context).

Which diff to review:
1. If arguments name a base branch, commit, or range ($ARGUMENTS), review that diff.
2. Else, if there are uncommitted changes, review those.
3. Else, review this branch's commits against its merge-base with the default branch
   (e.g. `git diff $(git merge-base main HEAD)..HEAD`; use origin/main if there is
   no local main). Say which diff you picked before reviewing.

Give the reviewer ONLY the diff (plus stated requirements, if any). Not the conversation,
not the writer's reasoning. Its stance: assume the code is wrong; the job is to find
reasons it does not work.

Flag ONLY:
- correctness bugs
- gaps against the stated requirements
- security issues

Hunt specifically for:
- code that typechecks but behaves differently than intended (eager vs lazy evaluation,
  wrong default, inverted condition, off-by-one, stale cache/state)
- workarounds and stubs: if a change needs a long comment to justify why the workaround
  is OK, the code is wrong. Flag it.
- weakened, skipped, or deleted tests and assertions

Treat style, naming, and refactors as optional: list them separately under "optional",
don't block on them.

If you find nothing critical, say so plainly. Do NOT invent issues to look useful.

Prove findings by execution where you can — a reproduced bug beats a plausible one.
You may build the code, run its tests, start local servers, and send requests to loopback
(127.0.0.1, ::1, localhost). Clean up what you start.

A local server is usually already running. Check before you start one. If you find one,
confirm it serves the current diff — hit something the diff adds or changes — then reuse
it for observation. Never restart, kill, or reconfigure a server you did not start. If you
need a clean or isolated instance, start yours on a distinct unused port and stop only that
one.

STOP and ask first before you:
- send a request to any non-loopback host
- run anything that writes outside a scratch directory, including any database write,
  migration, or destructive path
- use credentials, tokens, or API keys from the environment or a .env file
- send load, fuzzing, or abuse traffic to a server you did not start — it is likely wired
  to real dev data

Say which of these you did in your report.

Report findings only. No summary, verification, or scoring sections. At most three lines
on what the change gets right, and only where it bears on correctness — e.g. a deletion
that was necessary, or a fix that closes a real bug. Otherwise skip it.
