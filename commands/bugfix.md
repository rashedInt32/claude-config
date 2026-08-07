Fix a bug: reproduce it, fix it, prove it fixed, review the diff.

Bug: $ARGUMENTS

## 1. Reproduce, before reading code for a theory

Use `/mattpocock-skills:diagnosing-bugs` for the diagnosis loop.

Build ONE check that fails on this bug. Take the cheapest form that works:

1. **Devtools assertion.** Default for anything in a browser. Drive the page with the
   chrome-devtools MCP, then run `evaluate_script` returning a boolean for the exact
   symptom. Report the boolean, not a description of what you saw.
2. **Throwaway test.** When devtools cannot reach it: pure logic, data transforms,
   backend paths. Write it to be deleted. Do not wire it into the suite yet.
3. **Playwright or Puppeteer script.** Only for intermittent bugs or repeat offenders.
   If the repo has no browser-automation setup, adding one is a real change. Ask first.

The check must go RED now. Paste the invocation and its red output.

If you cannot build one, STOP. Say what you tried and what you need. Do not
hypothesise without a check.

If the bug is visual ("this looks wrong"), say so plainly. A screenshot is not an
assertion. Hand it back rather than claim a check you did not make.

## 2. Stop and confirm

Show me three things: the symptom, the red check, and the root cause in a line or two.

Wait for my go-ahead before you change any code.

## 3. Fix

Smallest change that addresses the cause, not the symptom.

Run `/mattpocock-skills:tdd` only if the fix adds or changes behaviour at a seam.
Writing a repro test is not TDD. Skip the skill for that.

If the bug touches auth, secrets, untrusted input, or data storage, run
`/agent-skills:security-and-hardening` BEFORE writing the fix.

## 4. Prove it

Re-run the SAME check from step 1. Same invocation. It must now go green.

Show the red and the green together. A change that does not flip it is not a fix.

Then run the repo's own full test command to catch collateral damage.

## 5. Keep or bin the test

Only if step 1 produced a test or a script. Devtools-only runs leave nothing behind,
so skip this step.

Ask me, with a recommendation and one line of reasoning:

- Recommend KEEP if the bug reached users, or it is a logic or data bug at a stable
  seam, or this bug has regressed before.
- Recommend REMOVE if the test drives internals, needed heavy mocking, is slow or
  flaky, or the cause was a one-off config or environment issue.

If I say keep, move it to the repo's test location and name it properly.
If I say remove, delete it.

## 6. Review

Run `/rv` on the resulting diff.

Never commit. Never push. Those are my call.
