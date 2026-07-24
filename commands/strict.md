Apply these rules to the task below. They are hard rules, not suggestions.
(From the Bun-in-Rust rewrite playbook.)

1. No workarounds, no stubs. If you need a long comment to justify why a workaround
   is OK, the code is wrong. Fix the code instead.
2. Minimal change. Touch only the files the task needs. Don't refactor, rename, or
   "improve" anything unrelated.
3. Tests are ground truth. Never skip, weaken, or delete a test or assertion to make
   things pass. If a test fails, fix the code.
4. Git discipline: no `git stash`, no `git reset`, nothing that discards work. If you
   commit, commit the specific files you changed, one logical change at a time.
5. Match the existing patterns in the codebase. Consistency beats invention.
6. Correct, not just compiling. Before finishing, re-check your change for code that
   typechecks but behaves differently than intended (eager vs lazy evaluation, wrong
   default, inverted condition, off-by-one).
7. Verify before you claim done: run the relevant check (typecheck / test / curl) and
   show the output. If you can't verify, say so plainly.
8. If an assumption doesn't hold or something is unclear, stop and ask. Don't guess.

TASK: $ARGUMENTS
