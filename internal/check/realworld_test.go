package check

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/jackson-asmith/gh-baseline/internal/baseline"
	"github.com/jackson-asmith/gh-baseline/internal/snapshot"
)

// TestRealWorldFixture checks a snapshot of real repositories against
// findings from a manual audit rather than from the code. See
// testdata/real-world/README.md.
func TestRealWorldFixture(t *testing.T) {
	const dir = "../../testdata/real-world/"
	snap, err := snapshot.Load(dir + "snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := baseline.Load(dir + "baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dir + "expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Repos map[string]map[string]Status `json:"repos"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}

	// Evaluate as of collection time, so staleness doesn't drift.
	findings := Evaluate(snap, b, snap.GeneratedAt)

	seen := map[string]map[string]bool{}
	for _, f := range findings {
		want, ok := expected.Repos[f.Repo][f.Check]
		if !ok {
			t.Errorf("%s %s: no expectation in expected.json (got %s: %s)", f.Repo, f.Check, f.Status, f.Message)
			continue
		}
		if f.Status != want {
			t.Errorf("%s %s = %s (%s), audit expected %s", f.Repo, f.Check, f.Status, f.Message, want)
		}
		if seen[f.Repo] == nil {
			seen[f.Repo] = map[string]bool{}
		}
		seen[f.Repo][f.Check] = true
	}
	for repo, checks := range expected.Repos {
		for id := range checks {
			if !seen[repo][id] {
				t.Errorf("%s %s: expected by the audit but not evaluated", repo, id)
			}
		}
	}
}
