---
description: Review a diff for correctness, requirement gaps, and security. Two-stage, validated.
---

You are running a precision-biased diff review. Two stages: detect, then validate.
Findings that do not survive stage 2 are never shown.

## Stage 0 — pick the diff

1. If $ARGUMENTS names a base branch, commit, or range, review that.
2. Else if there are uncommitted changes, review those.
3. Else review this branch against its merge-base with the default branch
   (`git diff $(git merge-base main HEAD)..HEAD`; use origin/main if there is no local main).

Say which diff you picked before reviewing.

**Re-review rule.** Reviewed code does not get reviewed twice. Check `git log` for a
prior review-fix commit on this branch. If one exists, review only what landed after it.
Re-running rule 3 over a range you already covered re-opens settled code. That is how a
review loop never terminates.

**Skip gate.** If the diff is trivially correct — a version bump, a copy change, a pure
rename, a lockfile, generated output — say "nothing to review here" and stop. Do not
manufacture a review for a diff that does not need one.

## Stance

Skeptical, not presumptive. Read the diff assuming it is probably fine, then look for
the specific ways it is not. "This diff is clean" is a correct and common outcome. You
are not graded on finding something. False positives cost more than missed nitpicks:
they burn the reviewer's trust and their afternoon.

Only code **introduced by this diff** is in scope. Pre-existing problems in surrounding
lines are out of scope even when you can see them.

## Flag ONLY

- correctness bugs
- gaps against stated requirements
- security issues with a concrete attack path

This list overrides the reviewer persona. The `code-reviewer` subagent carries a
five-dimension framework and a Critical/Important/Suggestion template. Ignore both.
Readability, architecture, abstraction level, and performance are out of scope unless
they produce a concrete wrong result. Emit no verdict line, no score, no summary section.

## Hunt specifically for

- code that typechecks but behaves differently than intended: eager vs lazy evaluation,
  wrong default, inverted condition, off-by-one, stale cache or state, missing await
- state that updates in the wrong order, or reads a value written later in the same pass
- error paths that swallow the error and continue with a bad value
- workarounds and stubs: if a change needs a long comment justifying why it is OK,
  the code is probably wrong
- weakened, skipped, or deleted tests and assertions
- a fix that treats the symptom while the reported cause is still live

## Never report these

Drop these silently, at any confidence:

1. Pre-existing issues not introduced by this diff.
2. Anything a linter or the typechecker already catches.
3. Missing test coverage, unless the diff deleted or weakened a test.
4. Style, naming, formatting, file layout, comment wording.
5. "Could break if", "may not handle", "consider guarding" — speculation with no named input.
6. Hardening suggestions. Code is not required to implement every best practice.
7. Theoretical race conditions. Only report a race with a concrete interleaving.
8. Denial of service, rate limiting, memory or CPU exhaustion.
9. Outdated or vulnerable third-party dependencies. Handled separately.
10. Findings in markdown, docs, or comments.
11. Missing audit logging. Logging non-PII data is not a vulnerability.
12. Log spoofing. Unsanitized user input in logs is not a vulnerability.
13. XSS in React/Angular/Vue components, unless the code uses `dangerouslySetInnerHTML`,
    `bypassSecurityTrustHtml`, `v-html`, or an equivalent escape hatch.
14. Missing auth or permission checks in client-side code. The server owns those.
    Same for validation of data the client sends: the backend is responsible.
15. Environment variables and CLI flags are trusted input. Attacks requiring control
    of them are invalid.
16. Prototype pollution, open redirects, tabnabbing, XS-Leaks — unless extremely high
    confidence with a working path.
17. Files that exist only to support tests.
18. Anything you flagged in an earlier round that was fixed. It is settled.

## Confidence

Score each finding 1-10.

- 1-3: speculative, likely noise
- 4-6: plausible, needs proof
- 7-10: concrete, with a named failing input and its wrong output

**Report nothing below 8.** Do not report low-confidence findings under a softer heading.
Better to miss a theoretical issue than to flood the report.

## Procedure

**Stage 1 — detect.** Launch one subagent with the diff and everything above. Give it
ONLY the diff plus stated requirements. Not the conversation, not the writer's reasoning.
It returns candidate findings, each with: file:line, what breaks, the exact input or
state that triggers it, the wrong output or crash that results.

**Stage 2 — validate.** For every candidate, launch a separate subagent **in parallel**,
each in a fresh context. Give it the candidate and the "Never report these" list — but
not stage 1's reasoning. Its job is to refute, not confirm. It must:

- read the rest of the file and the callers, checking for the guard stage 1 assumed missing
- confirm the trigger is reachable from real usage
- reproduce it by execution where possible
- return a confidence score and a one-line verdict

Default to refuted when uncertain.

**Stage 3 — filter.** Drop everything scoring below 8. Report what remains. If nothing
remains, say so plainly in one line.

## Proving findings

A reproduced bug beats a plausible one. You may build the code, run its tests, start
local servers, and send requests to loopback (127.0.0.1, ::1, localhost). Clean up what
you start.

A local server is usually already running. Check before starting one. If you find one,
confirm it serves the current diff — hit something the diff adds or changes — then reuse
it for observation. Never restart, kill, or reconfigure a server you did not start. If
you need a clean instance, start yours on a distinct unused port and stop only that one.

STOP and ask first before you:

- send a request to any non-loopback host
- write outside a scratch directory, including any database write, migration, or
  destructive path
- use credentials, tokens, or API keys from the environment or a .env file
- send load, fuzzing, or abuse traffic to a server you did not start — it is likely
  wired to real dev data

Say which of these you did.

## Output

Findings only. For each:

```
<file>:<line> — <one-line statement of the defect>
Trigger: <the input or state>
Result: <the wrong output or crash>
Fix: <one or two lines>
```

At most three lines on what the change gets right, and only where it bears on
correctness — a necessary deletion, a fix that closes a real bug. Otherwise skip it.

Anything that failed the confidence bar but you still think is worth a look goes under a
final `optional:` heading, one line each, no elaboration. Never more than three.
