package workflowparse_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/jackson-asmith/gh-baseline/internal/workflowparse"
)

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// workflowSeeds are realistic workflow documents to start fuzzing from.
var workflowSeeds = []string{
	"on: push\npermissions:\n  contents: read\njobs: {}\n",
	"permissions: read-all\n",
	"jobs:\n  build:\n    permissions:\n      contents: read\n",
	"jobs:\n  a:\n    uses: ./.github/workflows/lint.yml\n",
	"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n      - uses: actions/setup-go@v6\n",
	"jobs:\n  b:\n    steps:\n      - name: quoted\n        uses: \"ludeeus/action-shellcheck@2.0.0\"\n",
	"jobs:\n  b:\n    steps:\n      - uses: docker://alpine:3.20\n      - uses: docker://alpine@sha256:0123456789abcdef\n",
	"jobs:\n  b:\n    steps:\n      - run: |\n          uses: not/an-action@v1\n",
}

// withCommentsAndBlanks puts a blank line and comment lines between every
// line of content. YAML ignores both, so the parser must too.
func withCommentsAndBlanks(content string) string {
	return strings.ReplaceAll(content, "\n", "\n\n# a comment\n      # - uses: commented/out@v1\n")
}

func FuzzParseActions(f *testing.F) {
	for _, s := range workflowSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		e := workflowparse.Parse(content)
		for _, a := range e.Actions {
			if a.Kind == workflowparse.ActionKindLocal && a.Pinned == false {
				t.Errorf("local reference %q reported as unpinned", a.Ref)
			}
			if strings.HasPrefix(a.Ref, "docker://") {
				if strings.Contains(a.Ref, "@sha256:") && !a.Pinned {
					t.Errorf("digest-pinned image %q reported as unpinned", a.Ref)
				}
			} else if a.Kind != workflowparse.ActionKindLocal {
				at := strings.LastIndex(a.Ref, "@")
				if at >= 0 && fullSHA.MatchString(a.Ref[at+1:]) && !a.Pinned {
					t.Errorf("SHA-pinned reference %q reported as unpinned", a.Ref)
				}
			}
		}
		// Comments and blank lines must not change the result.
		e2 := workflowparse.Parse(withCommentsAndBlanks(content))
		if len(e.Actions) != len(e2.Actions) {
			t.Errorf("comments and blank lines changed actions: %d vs %d", len(e.Actions), len(e2.Actions))
		}
	})
}

func FuzzParsePermissions(f *testing.F) {
	for _, s := range workflowSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		e := workflowparse.Parse(content)
		e2 := workflowparse.Parse(withCommentsAndBlanks(content))
		got := e.Permissions != nil
		got2 := e2.Permissions != nil
		if got != got2 {
			t.Errorf("comments and blank lines changed permissions presence: %v -> %v for %q", got, got2, content)
		}
	})
}
