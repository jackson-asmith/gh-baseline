package check

import (
	"slices"
	"strings"
	"testing"
)

// workflowSeeds are realistic workflow fragments to start fuzzing from.
var workflowSeeds = []string{
	"on: push\npermissions:\n  contents: read\njobs: {}\n",
	"permissions: read-all\n",
	"jobs:\n  build:\n    permissions:\n      contents: read\n",
	"jobs:\n  a:\n    uses: ./.github/workflows/lint.yml\n",
	"steps:\n  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n  - uses: actions/setup-go@v6\n",
	"steps:\n  - name: quoted\n    uses: \"ludeeus/action-shellcheck@2.0.0\"\n",
	"steps:\n  - uses: docker://alpine:3.20\n  - uses: docker://alpine@sha256:0123456789abcdef\n",
	"steps:\n  - run: |\n      echo uses: not/an-action@v1\n",
	"steps:\r\n  - uses: actions/cache@v4\r\n",
}

// withCommentsAndBlanks puts a blank line and comment lines between every
// line of content. YAML ignores both, so the parser must too. One comment is
// a commented-out `uses:` line, which must not be read as a step.
func withCommentsAndBlanks(content string) string {
	return strings.ReplaceAll(content, "\n", "\n\n# a comment\n      # - uses: commented/out@v1\n")
}

func FuzzUnpinnedUses(f *testing.F) {
	for _, s := range workflowSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		got := unpinnedUses(content)
		for _, ref := range got {
			if strings.HasPrefix(ref, "./") {
				t.Errorf("reported local reference %q", ref)
			}
			if strings.HasPrefix(ref, "docker://") {
				if strings.Contains(ref, "@sha256:") {
					t.Errorf("reported digest-pinned image %q", ref)
				}
			} else if at := strings.LastIndex(ref, "@"); at >= 0 && fullSHA.MatchString(ref[at+1:]) {
				t.Errorf("reported SHA-pinned reference %q", ref)
			}
		}
		if again := unpinnedUses(withCommentsAndBlanks(content)); !slices.Equal(got, again) {
			t.Errorf("comments and blank lines changed the result:\n%q\n  -> %q\nwith them: %q", content, got, again)
		}
	})
}

func FuzzHasTopLevelPermissions(f *testing.F) {
	for _, s := range workflowSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		got := hasTopLevelPermissions(content)
		if again := hasTopLevelPermissions(withCommentsAndBlanks(content)); got != again {
			t.Errorf("comments and blank lines changed the result for %q: %v -> %v", content, got, again)
		}
	})
}
