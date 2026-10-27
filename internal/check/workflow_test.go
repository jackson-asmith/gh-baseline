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
	// A value on the line after `uses:` is valid YAML; the YAML parser handles
	// this naturally. A commented-out step must not be reported.
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			"value on the next line",
			"jobs:\n  a:\n    steps:\n      - uses:\n          actions/cache@v4\n",
			[]string{"actions/cache@v4"},
		},
		{
			"comment before the value",
			"jobs:\n  a:\n    steps:\n      - uses:\n          # cache\n          actions/cache@v4\n",
			[]string{"actions/cache@v4"},
		},
		{"commented-out step", "jobs:\n  a:\n    steps:\n      # - uses: actions/cache@v4\n", nil},
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

func TestUnpinnedUsesIgnoresRunBlocks(t *testing.T) {
	// A `uses:` string inside a run: block scalar must not be reported as an
	// action reference. The line-based parser was susceptible to this false
	// positive; the YAML parser is not.
	content := "jobs:\n  a:\n    steps:\n      - run: |\n          uses: bad/action@v1\n"
	if got := unpinnedUses(content); got != nil {
		t.Errorf("unpinnedUses reported %q from inside a run: block", got)
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
