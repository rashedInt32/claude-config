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
