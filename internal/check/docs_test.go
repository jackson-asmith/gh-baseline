package check

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// TestDocsListEveryCheck keeps the check tables in README.md and
// docs/DESIGN.md in step with the catalog. Two checks shipped in v0.9.0 and
// v0.10.0 without being added to either table, and nothing noticed.
func TestDocsListEveryCheck(t *testing.T) {
	row := regexp.MustCompile("(?m)^\\| `((?:ruleset|security|workflow)\\.[a-z-]+)` \\|")

	var want []string
	for _, d := range Catalog() {
		want = append(want, d.ID)
	}

	for _, path := range []string{"../../README.md", "../../docs/DESIGN.md"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, m := range row.FindAllStringSubmatch(string(b), -1) {
			got = append(got, m[1])
		}
		for _, id := range want {
			if !slices.Contains(got, id) {
				t.Errorf("%s: check table is missing %s", path, id)
			}
		}
		for _, id := range got {
			if !slices.Contains(want, id) {
				t.Errorf("%s: check table lists %s, which isn't in the catalog", path, id)
			}
		}
	}
}
