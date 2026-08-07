# Global guidelines (all projects)

## Skill routing (addy agent-skills)
When touching auth, secrets, untrusted input, or data storage, invoke
security-and-hardening BEFORE writing the code.

## Response shape
- Diagnosis, debug, and fix turns open with a **Bottom line** block: exactly 3
  lines, one idea each, labelled Verified / Issue / Fix.
- Skip that block on open questions, comparisons, planning, and conversation.
- Sentences under 15 words. Active voice. No em-dash asides, no parentheticals,
  no clauses stacked onto clauses.
- Keep hedges, as their own short sentence: "This depends on X." Never drop a
  qualifier to sound clean.
- Cap the whole response at 3 top-level sections. No tables unless comparing 3+
  items on 3+ axes.
