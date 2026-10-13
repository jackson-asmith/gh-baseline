package check

import (
	"reflect"
	"testing"
)

func TestHasTopLevelPermissions(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"top level", "on: push\npermissions:\n  contents: read\njobs: {}\n", true},
		{"inline", "permissions: read-all\n", true},
		{"job level only", "jobs:\n  build:\n    permissions:\n      contents: read\n", false},
		{"none", "on: push\njobs: {}\n", false},
		{"colon on the next line is not a key", "permissions\n:", false}, // found by FuzzHasTopLevelPermissions
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasTopLevelPermissions(tt.content); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnpinnedUses(t *testing.T) {
	content := `
jobs:
  a:
    uses: ./.github/workflows/lint.yml
  b:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@v6
      - name: quoted
        uses: "ludeeus/action-shellcheck@2.0.0"
      - uses: docker://alpine:3.20
      - uses: docker://alpine@sha256:0123456789abcdef
      - uses: github/codeql-action/init@main
      - uses: someone/no-ref
`
	want := []string{
		"actions/setup-python@v6",
		"ludeeus/action-shellcheck@2.0.0",
		"docker://alpine:3.20",
		"github/codeql-action/init@main",
		"someone/no-ref",
	}
	if got := unpinnedUses(content); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestUnpinnedUsesAcrossLines(t *testing.T) {
	// Found by FuzzUnpinnedUses: a value on the line after `uses:` is valid
	// YAML, and a comment line in between must not hide it.
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{"value on the next line", "steps:\n  - uses:\n      actions/cache@v4\n", []string{"actions/cache@v4"}},
		{"comment before the value", "steps:\n  - uses:\n      # cache\n      actions/cache@v4\n", []string{"actions/cache@v4"}},
		{"commented-out step", "steps:\n  # - uses: actions/cache@v4\n", nil},
		{"colon on the next line is not a key", "uses\n: actions/cache@v4\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unpinnedUses(tt.content); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unpinnedUses(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}

func TestSecretsUsed(t *testing.T) {
	content := `
env:
  A: ${{ secrets.DEPLOY_KEY }}
  B: ${{secrets.GITHUB_TOKEN}}
  C: ${{ secrets.DEPLOY_KEY }}
run: echo ${{ github.ref }} ${{ inputs.x || secrets.FALLBACK }}
`
	want := []string{"DEPLOY_KEY", "FALLBACK"}
	if got := secretsUsed(content); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
