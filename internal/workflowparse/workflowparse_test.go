package workflowparse_test

import (
	"reflect"
	"testing"

	"github.com/jackson-asmith/gh-baseline/internal/workflowparse"
)

func TestParseTriggers_String(t *testing.T) {
	e := workflowparse.Parse("on: push\n")
	if !reflect.DeepEqual(e.Triggers, []string{"push"}) {
		t.Errorf("triggers = %v, want [push]", e.Triggers)
	}
}

func TestParseTriggers_List(t *testing.T) {
	e := workflowparse.Parse("on: [push, pull_request]\n")
	if !reflect.DeepEqual(e.Triggers, []string{"push", "pull_request"}) {
		t.Errorf("triggers = %v", e.Triggers)
	}
}

func TestParseTriggers_Mapping(t *testing.T) {
	e := workflowparse.Parse("on:\n  push:\n  schedule:\n    - cron: '0 0 * * *'\n")
	has := func(name string) bool {
		for _, t := range e.Triggers {
			if t == name {
				return true
			}
		}
		return false
	}
	if !has("schedule") || !has("push") {
		t.Errorf("triggers = %v, want push and schedule", e.Triggers)
	}
}

func TestHasAutomaticTrigger(t *testing.T) {
	tests := []struct {
		content string
		want    bool
	}{
		{"on:\n  schedule:\n    - cron: '0 0 * * *'\n", true},
		{"on: repository_dispatch\n", true},
		{"on: push\n", false},
		{"on: [push, pull_request]\n", false},
		{"on: workflow_dispatch\n", false},
		{"# on: schedule\non: push\n", false},
	}
	for _, tt := range tests {
		e := workflowparse.Parse(tt.content)
		if got := workflowparse.HasAutomaticTrigger(e); got != tt.want {
			t.Errorf("HasAutomaticTrigger(%q) = %v, want %v", tt.content, got, tt.want)
		}
	}
}

func TestParsePermissions_Present(t *testing.T) {
	e := workflowparse.Parse("on: push\npermissions:\n  contents: read\njobs: {}\n")
	if e.Permissions == nil {
		t.Fatal("Permissions is nil, want non-nil")
	}
	if e.Permissions.Scopes["contents"] != "read" {
		t.Errorf("contents = %q, want read", e.Permissions.Scopes["contents"])
	}
}

func TestParsePermissions_ReadAll(t *testing.T) {
	e := workflowparse.Parse("permissions: read-all\n")
	if e.Permissions == nil || !e.Permissions.ReadAll {
		t.Errorf("Permissions = %v, want ReadAll=true", e.Permissions)
	}
}

func TestParsePermissions_WriteAll(t *testing.T) {
	e := workflowparse.Parse("permissions: write-all\n")
	if e.Permissions == nil || !e.Permissions.WriteAll {
		t.Errorf("Permissions = %v, want WriteAll=true", e.Permissions)
	}
}

func TestParsePermissions_Absent(t *testing.T) {
	e := workflowparse.Parse("jobs:\n  build:\n    permissions:\n      contents: read\n")
	if e.Permissions != nil {
		t.Errorf("Permissions = %v, want nil (job-level only)", e.Permissions)
	}
}

func TestParsePermissions_KeyColonOnNextLine(t *testing.T) {
	// found by FuzzHasTopLevelPermissions in its prior life in the check package
	e := workflowparse.Parse("permissions\n:")
	if e.Permissions != nil {
		t.Errorf("Permissions = %v, want nil", e.Permissions)
	}
}

func TestParseActions_Unpinned(t *testing.T) {
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
	e := workflowparse.Parse(content)
	var unpinned []string
	for _, a := range e.Actions {
		if !a.Pinned {
			unpinned = append(unpinned, a.Ref)
		}
	}
	want := []string{
		"actions/setup-python@v6",
		"ludeeus/action-shellcheck@2.0.0",
		"docker://alpine:3.20",
		"github/codeql-action/init@main",
		"someone/no-ref",
	}
	if !reflect.DeepEqual(unpinned, want) {
		t.Errorf("unpinned = %q\nwant     %q", unpinned, want)
	}
}

func TestParseActions_RunBlockNotAction(t *testing.T) {
	content := "jobs:\n  a:\n    steps:\n      - run: |\n          uses: bad/action@v1\n"
	e := workflowparse.Parse(content)
	for _, a := range e.Actions {
		if a.Ref == "bad/action@v1" {
			t.Errorf("reported uses: inside run: block as action")
		}
	}
}

func TestParseActions_ValueOnNextLine(t *testing.T) {
	e := workflowparse.Parse("jobs:\n  a:\n    steps:\n      - uses:\n          actions/cache@v4\n")
	if len(e.Actions) != 1 || e.Actions[0].Ref != "actions/cache@v4" {
		t.Errorf("actions = %v, want one entry for actions/cache@v4", e.Actions)
	}
	if e.Actions[0].Pinned {
		t.Error("actions/cache@v4 should not be pinned")
	}
}

func TestParseActions_LocalAlwaysPinned(t *testing.T) {
	e := workflowparse.Parse("jobs:\n  a:\n    uses: ./.github/workflows/shared.yml\n")
	if len(e.Actions) != 1 || !e.Actions[0].Pinned {
		t.Errorf("local reference should be pinned: %v", e.Actions)
	}
}

func TestParseActions_DockerDigest(t *testing.T) {
	e := workflowparse.Parse("jobs:\n  a:\n    steps:\n      - uses: docker://alpine@sha256:0123456789abcdef\n")
	if len(e.Actions) != 1 || !e.Actions[0].Pinned {
		t.Errorf("docker digest should be pinned: %v", e.Actions)
	}
}

func TestParseActions_OwnerRepo(t *testing.T) {
	e := workflowparse.Parse("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@abc123\n")
	if len(e.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(e.Actions))
	}
	a := e.Actions[0]
	if a.Owner != "actions" || a.Repo != "checkout" {
		t.Errorf("owner=%q repo=%q, want actions/checkout", a.Owner, a.Repo)
	}
}

func TestParseActions_ReusableKind(t *testing.T) {
	content := "jobs:\n  a:\n    uses: acme/shared-workflows/.github/workflows/test.yml@abc\n"
	e := workflowparse.Parse(content)
	if len(e.Actions) != 1 || e.Actions[0].Kind != workflowparse.ActionKindReusable {
		t.Errorf("expected reusable kind: %v", e.Actions)
	}
}

func TestParseSecrets_Named(t *testing.T) {
	content := `
env:
  A: ${{ secrets.DEPLOY_KEY }}
  B: ${{secrets.GITHUB_TOKEN}}
  C: ${{ secrets.DEPLOY_KEY }}
run: echo ${{ github.ref }} ${{ inputs.x || secrets.FALLBACK }}
`
	e := workflowparse.Parse(content)
	names := make([]string, 0)
	for _, s := range e.Secrets {
		if !s.Inherited {
			names = append(names, s.Name)
		}
	}
	want := []string{"DEPLOY_KEY", "FALLBACK"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("secret names = %q, want %q", names, want)
	}
}

func TestParseSecrets_BracketNotation(t *testing.T) {
	e := workflowparse.Parse("run: echo ${{ secrets['DEPLOY_KEY'] }}")
	if len(e.Secrets) != 1 || e.Secrets[0].Name != "DEPLOY_KEY" {
		t.Errorf("secrets = %v, want DEPLOY_KEY", e.Secrets)
	}
}

func TestParseSecrets_Inherit(t *testing.T) {
	content := "jobs:\n  call:\n    uses: ./.github/workflows/shared.yml\n    secrets: inherit\n"
	e := workflowparse.Parse(content)
	var hasInherit bool
	for _, s := range e.Secrets {
		if s.Inherited {
			hasInherit = true
		}
	}
	if !hasInherit {
		t.Error("expected inherited secret sentinel")
	}
}

func TestParseSecrets_CommentedInheritNotMatched(t *testing.T) {
	content := "# secrets: inherit\njobs:\n  build:\n    steps:\n      - run: echo hello\n"
	e := workflowparse.Parse(content)
	for _, s := range e.Secrets {
		if s.Inherited {
			t.Error("commented secrets: inherit should not match")
		}
	}
}
