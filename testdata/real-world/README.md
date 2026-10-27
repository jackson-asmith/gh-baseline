# Real-world fixture

A snapshot of five real repositories, collected on 2026-10-14 with
`--save-snapshot`, and the findings a manual audit expected for them.
The `securityPolicy` field was added on 2026-10-27 by querying the community
profile API directly and verifying each repo by hand.

- `snapshot.json` is the collected state. The one private repository is
  renamed `retired-gem`; nothing else is changed.
- `expected.json` holds the audit's pass/fail/skip call for each of the 55
  checks. The audit read the raw API responses and workflow files and did not
  look at gh-baseline's output, so these expectations don't share the code's
  assumptions. It caught one real bug: `workflow.stale-secrets` used to fail
  `retired-gem` for secrets that no longer existed.
- `baseline.json` assigns the tiers the audit was done against.

`TestRealWorldFixture` evaluates the snapshot as of its own `generatedAt`, so
staleness doesn't drift with the calendar. When a check's behavior changes on
purpose, update `expected.json` only after re-checking the repository by hand.
