# Changelog

## v0.5.0 — 2026-10-27

### Documentation
- Added `security.security-policy` to the README check table (was missing since v0.3.0).
- Updated the "No dependencies" design bullet to reflect the `yaml.v3` dependency added in v0.4.0.

### Tests
- Refreshed the real-world fixture with actual `securityPolicy` values queried from the
  GitHub community profile API. Four public repos now report real pass/fail results for
  `security.security-policy` instead of `unknown`.

## v0.4.0 — 2026-10-27

### Changed
- `workflow.token-permissions` and `workflow.pinned-actions` now use `gopkg.in/yaml.v3`
  to parse workflow files instead of a line-based scanner. This eliminates a class of
  false positives where a `uses:` string inside a `run:` block scalar was mistakenly
  reported as an action reference. Flow-style YAML and anchors are now also handled
  correctly. See [ADR 0004](docs/adr/0004-yaml-parser-for-workflows.md).
- `gopkg.in/yaml.v3` is the project's first third-party dependency.

## v0.3.0 — 2026-10-27

### New checks
- **`security.security-policy`**: fails when a public repository has no `SECURITY.md`.
  Private repositories are skipped. Uses the GitHub community profile API
  (`/repos/{owner}/{repo}/community/profile`).

### New output format
- **`--format sarif`**: emits SARIF 2.1.0 JSON, ready for upload to GitHub code
  scanning via `github/codeql-action/upload-sarif`. All catalog rules appear in the
  driver regardless of findings; `fail` and `unknown` findings produce results;
  `pass` and `skip` are omitted.

### Documentation
- Added README section explaining how `gh-baseline` relates to OpenSSF Scorecard and
  Allstar, and where it fits alongside them.

## v0.2.0 — 2026-10-14

### New checks
- **`workflow.stale-secrets`**: fails when a repository has had no push activity for
  longer than `staleDays` (default 90) and its workflows still reference secrets that
  exist. The check verifies the secrets actually exist before failing — it no longer
  flags secrets that have already been removed.

### Fixes
- Replaced an assumed 403 response for token-permission probing with logic based on
  observed API responses, eliminating a class of spurious `unknown` results.

### Tests
- Added fuzz tests for the workflow parser; two bugs found and fixed.
- Added a smoke test that builds the binary and runs it against a real repository in CI.
- Added a real-world fixture: a snapshot of five real repositories with findings
  verified by manual audit, used as a regression check in `TestRealWorldFixture`.

## v0.1.0 — 2026-09-30

Initial release. Checks:

| ID | Fails when |
|---|---|
| `ruleset.branch-safety` | The default branch allows deletion or force pushes |
| `ruleset.pull-request` | The tier requires a PR and no rule enforces one |
| `ruleset.status-checks` | The tier requires checks and none are required |
| `ruleset.check-source` | A required check accepts any source instead of a specific app |
| `security.secret-scanning` | Secret scanning is off (public repos) |
| `security.push-protection` | Push protection is off (public repos) |
| `security.vuln-reporting` | Private vulnerability reporting is off (public repos) |
| `workflow.token-permissions` | A workflow has no top-level `permissions:` |
| `workflow.pinned-actions` | An action is referenced by tag or branch instead of a commit SHA |
| `workflow.dependabot-actions` | Workflows exist but Dependabot doesn't keep them updated |
