# 0002. Classify plan-limited rulesets in the collector, by message

- **Status:** Accepted; amended 2026-10-13 (see Amendment)
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

The second row, and the paragraph before the table, were assumptions
rather than observations; the amendment below records what GitHub returns.

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

## Amendment, 2026-10-13: the token case is a 404

The second row of the table above was never observed; it was an assumption
written into a test. Checked against the live API:

| Situation | Observed | Message |
|---|---|---|
| Free plan, private repo | 403 | `Upgrade to GitHub Pro or make this repository public to enable this feature.` |
| Fine-grained token without access to the private repo | 404 | `Not Found` |

GitHub hides a private repository from a token that can't see it rather
than refusing it, and reading branch rules needs only metadata access,
which any token that can see the repository has. So the ambiguity this
record was written to resolve doesn't occur for the token case. Rejecting
"status and visibility alone" for the reason given above was wrong: with
the tokens tested, a 403 on a private repo's rules did mean a free plan.

The decision stands, for a smaller reason. GitHub uses 403 for other
refusals, such as organization SAML enforcement, and those must stay
`unknown`. Checking the message costs one string comparison and only ever
errs toward `unknown`. The tests now use the observed responses and say
where each came from; the SAML case is GitHub's general message and hasn't
been observed on this endpoint.

