# 0001. Standard library only

- **Status:** Accepted
- **Date:** 2026-10-13 (recorded after the fact; the decision was made with
  the initial commit)

## Context

gh-baseline audits supply-chain settings: action pinning, Dependabot
coverage, who can satisfy a required check. Every dependency it takes is
part of the supply chain of anyone who runs it with a token that can read
their repositories' administration settings.

The obvious dependencies are `github.com/cli/go-gh` (auth and REST client)
and a YAML parser for workflow files.

## Decision

Use only the Go standard library.

- REST calls go through a small client on `net/http` (`internal/ghapi`).
- The token comes from `GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth token`,
  which reuses the user's `gh` login the way `go-gh` would.
- Workflow files are read line by line (top-level `permissions:`, `uses:`
  lines, `secrets.` references) rather than parsed as YAML.

## Alternatives considered

- **`go-gh`.** Handles auth, hosts, and pagination. Not much code is saved
  for a read-only client, and it brings its own dependency tree.
- **`gopkg.in/yaml.v3`** for workflows. Exact parsing, at the cost of the
  project's only third-party dependency. The line-based reader is enough
  for conventionally formatted workflows.

## Consequences

- Nothing to vet, update, or pin beyond the Go toolchain and the CI
  actions.
- The client owns retries, pagination, and rate limits itself, and tests
  them itself.
- The workflow reader can be fooled by unusual formatting: flow-style
  mappings, anchors, or `permissions` set inside a multi-line string. A
  false result there is a missed finding, not a crash. If that proves too
  loose in practice, switching to a YAML parser is the expected next step
  and gets its own record.
