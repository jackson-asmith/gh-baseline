# 0002. Classify plan-limited rulesets in the collector, by message

- **Status:** Accepted
- **Date:** 2026-10-13

## Context

Rulesets on private repositories need a paid plan (GitHub Pro, Team, or
Enterprise). On a free plan, reading a private repository's branch rules
returns HTTP 403. Such a repository can't be protected, so the ruleset
checks should report `skip`: there is nothing to fix and nothing unknown.

GitHub also returns 403 when the token can't read the repository's rules.
That case must report `unknown`, since the protection might be missing.
The two responses differ only in their message:

| Situation | Status | Message |
|---|---|---|
| Free plan, private repo | 403 | `Upgrade to GitHub Pro or make this repository public to enable this feature.` |
| Token lacks access | 403 | `Resource not accessible by personal access token` |

The first version matched this text inside the checks, against the error
string stored in the snapshot. That put GitHub's wording in the evaluation
layer and in every saved snapshot.

## Decision

The collector classifies the response once, where the status and message
are available. A 403 on a private repository whose message starts with
`Upgrade to GitHub` sets `Repo.RulesetsUnavailable`. Any other failure is
recorded in `Repo.Errors` as before. The checks read the field and never
interpret error text.

## Alternatives considered

- **Status and visibility alone** (any 403 on a private repo). Wrong for
  tokens without access: a missing protection would be reported as `skip`
  when it should be `unknown`.
- **Look up the account's plan** (`/user` or `/orgs/{org}`). Deterministic,
  but needs extra calls and scopes, the plan isn't always readable for
  organizations, and the plan name alone doesn't say which features apply.
- **Report every 403 as `unknown`.** Honest, but every private repo on a
  free plan would appear in every report with nothing anyone can do about
  it.

## Consequences

- The dependency on GitHub's wording lives in one function (`planLimited`
  in `internal/collect`) with a test that uses the real message.
- If GitHub rewords the message, affected repositories become `unknown`,
  not `pass`. The failure is visible and safe.
- Snapshots saved before this change store the raw error, so re-evaluating
  them reports these repositories as `unknown` until they're collected
  again.
