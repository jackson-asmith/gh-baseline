#!/usr/bin/env bash
# Runs gh-baseline the way a user does: as a separate program, against the
# recorded fixture. Checks the exit code, one known finding, and --help.
#
# Usage: smoke-test.sh <command...>
#   smoke-test.sh ./gh-baseline      # a freshly built binary
#   smoke-test.sh gh baseline        # the installed extension
set -uo pipefail

out=$("$@" --snapshot testdata/snapshot.json 2>&1)
code=$?
echo "$out"

if [ "$code" -ne 1 ]; then
  echo "::error::exit code $code, want 1 (the fixture has failing checks)"
  exit 1
fi
if ! grep -q "accepts any source: lint" <<<"$out"; then
  echo "::error::output is missing the expected ruleset.check-source finding"
  exit 1
fi
if ! "$@" --help >/dev/null 2>&1; then
  echo "::error::--help did not exit 0"
  exit 1
fi
echo "smoke test passed"
