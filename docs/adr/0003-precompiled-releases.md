# 0003. Distribute as a precompiled `gh` extension

- **Status:** Accepted
- **Date:** 2026-10-13

## Context

The tool is meant to be installed with `gh extension install
jackson-asmith/gh-baseline`. For a Go extension, `gh` installs a binary
attached to the repository's latest release; with no release binaries,
installation fails. The release workflow was removed in an early cleanup,
which left the documented install command broken.

## Decision

Keep `.github/workflows/release.yml`. Pushing a `v*` tag runs
`cli/gh-extension-precompile`, which builds binaries for each supported
platform and attaches them to a GitHub release. The workflow follows the
repository's own baseline: actions pinned by SHA, read-only token by
default, and `contents: write` only on the release job.

## Alternatives considered

- **`go install` only.** Works without releases, but needs a Go toolchain,
  doesn't integrate with `gh extension upgrade`, and drops the
  `gh baseline` command name.
- **A script extension** (an executable `gh-baseline` script at the repo
  root that runs `go run`). Also needs Go, and compiles on every run.

## Consequences

- Users need only `gh`; upgrades come through `gh extension upgrade`.
- Releasing is a tag push, and every release builds the same way.
- The release job is the one place with write access, which makes it the
  workflow to review most carefully.
