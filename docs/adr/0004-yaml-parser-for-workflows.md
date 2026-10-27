# 0004. YAML parser for workflow files

- **Status:** Accepted; supersedes [0001](0001-standard-library-only.md) on workflow parsing
- **Date:** 2026-10-27

## Context

ADR 0001 chose a line-based reader for workflow files and named a YAML parser
as the expected upgrade "if that proves too loose in practice." Two checks
depend on this reader:

- `workflow.token-permissions` uses `hasTopLevelPermissions` to detect whether
  a workflow declares a top-level `permissions:` key.
- `workflow.pinned-actions` uses `unpinnedUses` to collect every `uses:`
  reference that isn't pinned to a commit SHA.

The line-based reader has confirmed blind spots:

- `uses:` inside a `run:` block scalar is indistinguishable from a `uses:` step
  reference if indented the same way — a false positive for `workflow.pinned-actions`.
- `permissions:` inside a multi-line string value at column 0 would be a false
  positive for `workflow.token-permissions`, though this is contrived in
  practice.
- Flow-style YAML (`uses: {run: foo}` on a single line) and anchors are
  structurally invisible to a line scanner.

`secretsUsed` searches for `${{ secrets.NAME }}` template expressions inside
string values. A YAML parser gives you the parsed string, but finding the
expressions still requires a regex. That function stays line/regex-based.

## Decision

Use `gopkg.in/yaml.v3` for `hasTopLevelPermissions` and `unpinnedUses`.
This is the project's first third-party dependency.

`yaml.v3` is a stable, widely-used package with no runtime dependencies of
its own. It will appear in `go.sum` alongside its test dependency
(`gopkg.in/check.v1`), but `check.v1` is not a runtime dependency of
`gh-baseline`.

## Alternatives considered

- **Keep the line-based reader.** The known false positives are rare in
  practice. Acceptable, but the upgrade path was always anticipated and the
  fix is small.
- **`encoding/json` after converting YAML.** No standard-library converter
  exists; this would require a YAML parser anyway.
- **A hand-written recursive-descent parser.** More code than `yaml.v3` with
  no advantage.

## Consequences

- `workflow.token-permissions` and `workflow.pinned-actions` correctly handle
  flow-style YAML, block scalars, and anchors.
- The `uses:` inside a `run:` block is no longer a false positive.
- `go.mod` gains one entry; `go.sum` gains entries for `yaml.v3` and its test
  dependency.
- The fuzz tests for both functions remain valid: their invariants (comments
  and blank lines don't change the result) hold for a YAML parser because YAML
  ignores comments.
- Malformed workflow YAML returns `false` / `nil` conservatively: the check
  reports unknown only if the collect step failed to read the file, not if the
  file content is syntactically invalid.
