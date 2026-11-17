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

func TestSecretsUsedBracketNotation(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			"single quotes",
			"run: echo ${{ secrets['DEPLOY_KEY'] }}",
			[]string{"DEPLOY_KEY"},
		},
		{
			"double quotes",
			"run: echo ${{ secrets[\"API_TOKEN\"] }}",
			[]string{"API_TOKEN"},
		},
		{
			"mixed dot and bracket",
			"run: echo ${{ secrets.FOO }} ${{ secrets['BAR'] }}",
			[]string{"FOO", "BAR"},
		},
		{
			"deduplicates across notations",
			"run: echo ${{ secrets.KEY }} ${{ secrets['KEY'] }}",
			[]string{"KEY"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretsUsed(tt.content); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSecretsInherit(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			"job with secrets: inherit",
			"jobs:\n  call:\n    uses: ./.github/workflows/shared.yml\n    secrets: inherit\n",
			true,
		},
		{
			"explicit secrets map, not inherit",
			"jobs:\n  call:\n    uses: ./.github/workflows/shared.yml\n    secrets:\n      MY_SECRET: ${{ secrets.MY_SECRET }}\n",
			false,
		},
		{
			"no secrets field",
			"jobs:\n  build:\n    steps:\n      - run: echo hello\n",
			false,
		},
		{
			"comment mentioning inherit is not a match",
			"# secrets: inherit\njobs:\n  build:\n    steps:\n      - run: echo hello\n",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretsInherit(tt.content); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDependabotCoversActions(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			"covers github-actions",
			"version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n",
			true,
		},
		{
			"covers npm only",
			"version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n",
			false,
		},
		{
			"comment mentioning github-actions is not a match",
			"version: 2\nupdates:\n  # package-ecosystem: github-actions\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n",
			false,
		},
		{
			"covers both npm and github-actions",
			"version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dependabotCoversActions(tt.content); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
