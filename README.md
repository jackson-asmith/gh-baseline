# gh-baseline

A `gh` extension that reports where your GitHub repositories drift from a
security baseline you declare once, in a file.

```
$ gh baseline --owner octo-dev --repo legacy-gem
REPO        CHECK                        STATUS  SEVERITY  DETAIL
legacy-gem  ruleset.branch-safety        fail    high      master allows deletion and force push
legacy-gem  security.secret-scanning     fail    high      secret scanning is off
legacy-gem  security.push-protection     fail    high      push protection is off
legacy-gem  workflow.token-permissions   fail    medium    no top-level permissions: .github/workflows/gempush.yml
legacy-gem  workflow.pinned-actions      fail    medium    not pinned to a SHA: actions/checkout@v2, actions/setup-ruby@v1
legacy-gem  workflow.dependabot-actions  fail    low       no dependabot.yml
legacy-gem  workflow.stale-secrets       fail    high      no push in 2400 days; secrets GPR_AUTH_TOKEN, RUBYGEMS_AUTH_TOKEN still exist and workflows use them

How to fix:
  ruleset.branch-safety: Add a ruleset on the default branch with "Restrict deletions" and "Block force pushes".
  workflow.stale-secrets: If the repo is retired, archive it, delete its Actions secrets, and revoke the credentials behind them.
  ...

7 failed, 0 unknown, 1 passed, 3 skipped
```

## Why

Repositories accumulate over years and drift. New ones start unprotected.
Old ones keep deploy workflows with live credentials long after anyone
remembers them. A required status check quietly accepts results from any
source, so anything that can post a commit status can satisfy it.

Checking this by hand means a dozen settings pages per repository.
`gh-baseline` checks it all in one run, and the exit code tells a scheduled
workflow when something changed.

## Install

```sh
gh extension install jackson-asmith/gh-baseline
```

## Use

```sh
# Every repo you own, against the built-in default baseline
gh baseline --owner your-username

# Your own baseline, with tiers
gh baseline --baseline baseline.json

# Specific repos only
gh baseline --baseline baseline.json --repo api --repo website

# Save what was collected, then re-evaluate it offline after editing the baseline
gh baseline --baseline baseline.json --save-snapshot run.snapshot.json
gh baseline --baseline baseline.json --snapshot run.snapshot.json

# Everything, including passes, as JSON
gh baseline --baseline baseline.json --format json
```

Exit codes: `0` nothing failed, `1` at least one check failed, `2` the run
itself failed. `unknown` results don't fail the run, but they're listed. A
repository that can't be read at all is reported as `unknown` for every check
rather than stopping the run. Transient API errors are retried; an exhausted
rate limit stops the run with exit `2` and says when it resets.

When `--owner` is the account `gh` is logged in as, or an organization you
belong to, private repositories are included. For any other user, GitHub only
lists their public repositories.

GitHub Enterprise works through `GH_HOST` or `--hostname`.

## Baseline

Repositories don't all need the same protection, so a baseline defines tiers
and assigns repositories to them. See
[`baseline.example.json`](baseline.example.json):

```json
{
  "owner": "jackson-asmith",
  "defaultTier": "basic",
  "tiers": {
    "basic":    { "requirePullRequest": false, "requireStatusChecks": false },
    "reviewed": { "requirePullRequest": true,  "requireStatusChecks": false },
    "ci":       { "requirePullRequest": true,  "requireStatusChecks": true }
  },
  "repos": { "keel": "ci", "jacksonsmith.github.io": "reviewed" },
  "exclude": [],
  "includeForks": true,
  "staleDays": 365
}
```

Every tier requires the default branch to block deletion and force pushes.
A repository whose scheduled workflow commits straight to the default branch
belongs in `basic`, since requiring a pull request would break it.

## Checks

| ID | Fails when |
|---|---|
| `ruleset.branch-safety` | The default branch allows deletion or force pushes |
| `ruleset.pull-request` | The tier requires a PR and no rule enforces one |
| `ruleset.status-checks` | The tier requires checks and none are required |
| `ruleset.check-source` | A required check accepts any source instead of a specific app |
| `security.secret-scanning` | Secret scanning is off (public repos) |
| `security.push-protection` | Push protection is off (public repos) |
| `security.vuln-reporting` | Private vulnerability reporting is off (public repos) |
| `security.security-policy` | No SECURITY.md exists (public repos) |
| `workflow.token-permissions` | A workflow has no top-level `permissions:` |
| `workflow.pinned-actions` | An action is referenced by tag or branch instead of a commit SHA |
| `workflow.dependabot-actions` | Workflows exist but Dependabot doesn't keep them updated |
| `workflow.stale-secrets` | No push in `staleDays` and workflows use secrets that still exist |

Rules are read from the effective rules on the default branch, so it doesn't
matter which ruleset (or how many) provides them.

## Design choices

- **Read-only.** It never changes a repository; every failure comes with a fix.
- **Honest about blind spots.** If the API won't show something, the result is
  `unknown`, never `pass`. Malware alerts and default workflow-token
  permissions aren't visible to it at all. The one exception: private repos
  on a free plan can't have rulesets, so the ruleset checks skip them instead
  of reporting `unknown`.
- **Minimal dependencies.** One third-party package (`gopkg.in/yaml.v3`) for
  correct workflow YAML parsing; everything else is standard library.
- **Checks are pure functions** of a saved snapshot, so they're tested against
  fixtures and never need the network.

More in [docs/DESIGN.md](docs/DESIGN.md).

## Related tools

- [OpenSSF Scorecard](https://github.com/ossf/scorecard) scores a single
  project's health from the outside. gh-baseline instead checks every repo an
  owner has against a baseline they declare, including settings only the owner
  can see, such as required-check sources and which secrets still exist.
- [OpenSSF Allstar](https://github.com/ossf/allstar) continuously enforces
  policies across an organization, opening issues or fixing settings. It now
  runs as an app you host yourself. gh-baseline is an on-demand, read-only
  report that needs nothing installed and also covers personal accounts.

They overlap on branch protection and workflow hygiene. Running Scorecard or
Allstar alongside gh-baseline is reasonable; see
[docs/DESIGN.md](docs/DESIGN.md#prior-art) for details.

## Token

It uses your `gh` login, or `GH_TOKEN` / `GITHUB_TOKEN`. A fine-grained token
needs read-only Metadata, Contents, and Administration on the repositories
you audit, plus Secrets, Actions, and Environments so `workflow.stale-secrets`
can see which secrets exist. Only names are read, never values. Nothing needs
write access.

## Upgrading to v0.2.0

- `workflow.stale-secrets` now checks that the secrets a stale workflow uses
  still exist, instead of assuming every `${{ secrets.X }}` is live. Repos
  whose workflows only mention deleted secrets now pass.
- A fine-grained token needs three more read-only permissions for that:
  Secrets, Actions, and Environments. Without them the check reports
  `unknown` for stale repositories. A `gh` login already has them.
- Snapshots saved by v0.1.0 don't record secrets, so replaying one with
  `--snapshot` reports `unknown` for stale repositories that use secrets.
  Collect a fresh snapshot to get a result.

## Development

```sh
go test ./...
go run . --snapshot testdata/snapshot.json --all
```

## License

MIT
