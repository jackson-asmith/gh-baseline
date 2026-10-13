# gh-baseline design

## Problem

A personal or small-team GitHub account accumulates repositories over years.
Each one has its own branch protection, security toggles, and workflows, and
they drift: new repos start unprotected, old repos keep deploy workflows with
live credentials, and a required status check quietly accepts results from
any source. Checking all of this by hand means clicking through a dozen
settings pages per repository.

`gh-baseline` states the intended configuration once, as a file, and reports
every place an account's repositories differ from it.

## Goals

- **Baseline as code.** One file declares what "good" looks like, in tiers,
  and which repositories belong to which tier.
- **Owner's view.** Check the settings an owner can see and an outside
  scanner can't: rulesets and their check sources, secret scanning, private
  vulnerability reporting.
- **Honest results.** Anything the API won't show is reported as `unknown`,
  never as a pass.
- **Read-only.** The tool never changes a repository. Remediation is text.
- **Zero dependencies.** Standard library only. A supply-chain auditing tool
  should not itself carry a dependency tree.
- **Runs anywhere `gh` does**, including GitHub Enterprise via `GH_HOST`.

## Non-goals (for now)

- Fixing anything (`--fix` is a possible later addition, dry-run by default).
- Organization-level policy (org rulesets, Actions policies, member settings).
- Scoring or ranking projects. Scorecard already does that well.

## Architecture

```
collect ──▶ snapshot (JSON) ──▶ evaluate ──▶ report
 REST API     one file per run     pure checks    table / JSON
```

1. **Collect.** For each repository: repo metadata and
   `security_and_analysis`, the effective rules on the default branch
   (`/rules/branches/{branch}`, which merges every ruleset that applies),
   private vulnerability reporting, the workflow files, and `dependabot.yml`.
   An endpoint that refuses access records an error for that field instead of
   failing the run.
   A repository that can't be read at all is recorded the same way, and
   every check on it reports `unknown`.
2. **Snapshot.** Everything collected goes into one JSON document. Checks
   never touch the network, so they are tested against recorded fixtures,
   and a saved snapshot can be re-evaluated (`--snapshot`) after editing the
   baseline.
3. **Evaluate.** Each check is a function from one repository's snapshot and
   its tier to findings. A finding has a check ID, status (`pass`, `fail`,
   `unknown`, `skip`), severity, message, and remediation.
4. **Report.** A table for people, JSON for scripts. The exit code is
   non-zero when any finding fails, so a scheduled workflow can alert on
   drift.

## Baseline and tiers

Not every repository needs the same protection. A repository with CI should
require a pull request and passing checks; a repository whose scheduled
workflow commits to the default branch cannot require a pull request at all.
Tiers encode that judgment:

```json
{
  "owner": "jackson-asmith",
  "defaultTier": "basic",
  "tiers": {
    "basic": { "requirePullRequest": false, "requireStatusChecks": false },
    "ci":    { "requirePullRequest": true,  "requireStatusChecks": true }
  },
  "repos": { "keel": "ci", "LinuxConfig": "ci" },
  "exclude": ["old-experiment"],
  "includeForks": true,
  "staleDays": 365
}
```

Every tier also requires the default branch to block deletion and force
pushes.

## Check catalog

| ID | Severity | Fails when |
|---|---|---|
| `ruleset.branch-safety` | high | Default branch allows deletion or force push |
| `ruleset.pull-request` | medium | Tier requires a PR and no rule enforces one |
| `ruleset.status-checks` | medium | Tier requires checks and none are required |
| `ruleset.check-source` | high | A required check accepts any source (no app pinned) |
| `security.secret-scanning` | high | Secret scanning is off (public repos) |
| `security.push-protection` | high | Push protection is off (public repos) |
| `security.vuln-reporting` | low | Private vulnerability reporting is off (public repos) |
| `workflow.token-permissions` | medium | A workflow has no top-level `permissions:` |
| `workflow.pinned-actions` | medium | An action is referenced by tag or branch instead of a commit SHA |
| `workflow.dependabot-actions` | low | Workflows exist but Dependabot doesn't update them |
| `workflow.stale-secrets` | high | No push in `staleDays` and workflows reference secrets |

`ruleset.check-source` is the least obvious: a required check named
`ShellCheck` with no source can be satisfied by anything allowed to post a
commit status, whether or not the workflow ran.

## Known blind spots

Reported as `unknown` or not checked, because the REST API doesn't expose
them to this kind of token:

- Dependabot malware alerts setting
- Default `GITHUB_TOKEN` permissions and environment protection rules, when
  the token lacks Actions/Administration read
- Which Actions secrets exist (the tool infers secret use from workflow text)

Workflow parsing is line-based for now (top-level `permissions:` and `uses:`
lines). It handles conventional formatting; a YAML parser is the obvious
upgrade if that proves too loose.

## Authentication and scopes

The token comes from `GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth token`. A
fine-grained token needs read-only access to Metadata, Contents, and
Administration (for rulesets and vulnerability reporting). Nothing needs
write access.

## Prior art

[OpenSSF Scorecard](https://github.com/ossf/scorecard) scores a project's
health from the outside, including token permissions, pinned dependencies,
and dangerous workflow patterns. `gh-baseline` differs in scope and
viewpoint: it enforces one owner's declared baseline across all their
repositories, and checks settings only the owner can see, such as ruleset
check sources and secret scanning. Running both is reasonable.

## Roadmap

1. SARIF output, so findings can be uploaded to code scanning.
2. A scheduled workflow that opens or updates an issue on drift.
3. `--fix` for settings the API can change, dry-run by default.
4. Tier selection by topic or by "has CI", not just by name.
