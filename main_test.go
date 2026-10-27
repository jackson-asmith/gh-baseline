package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "testdata/snapshot.json"

func writeBaseline(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "baseline.json")
	body := `{"defaultTier":"basic","tiers":{"basic":{},"ci":{"requirePullRequest":true,"requireStatusChecks":true}},"repos":{"service":"ci"}}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReplayTable(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--snapshot", fixture, "--baseline", writeBaseline(t)}, &out, &errOut)
	if code != exitFindings {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitFindings, errOut.String())
	}
	got := out.String()
	for _, want := range []string{
		"ruleset.check-source", "accepts any source: lint",
		"workflow.pinned-actions", "actions/checkout@v5",
		"How to fix:",
		"2 failed, 0 unknown",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "notes") {
		t.Errorf("passing repo shown without --all:\n%s", got)
	}
}

func TestReplaySARIF(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--snapshot", fixture, "--baseline", writeBaseline(t), "--format", "sarif"}, &out, &errOut)
	if code != exitFindings {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitFindings, errOut.String())
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					LogicalLocations []struct {
						Name string `json:"name"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, out.String())
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	results := doc.Runs[0].Results
	if len(results) == 0 {
		t.Fatal("expected at least one result in SARIF output")
	}
	// Logical locations must use owner/repo, not bare name.
	for _, r := range results {
		if len(r.Locations) == 0 || len(r.Locations[0].LogicalLocations) == 0 {
			t.Errorf("result %q has no logical location", r.RuleID)
			continue
		}
		name := r.Locations[0].LogicalLocations[0].Name
		if !strings.Contains(name, "/") {
			t.Errorf("result %q logicalLocation.name = %q, want owner/repo format", r.RuleID, name)
		}
	}
}

func TestReplayJSONAll(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--snapshot", fixture, "--baseline", writeBaseline(t), "--format", "json"}, &out, &errOut)
	if code != exitFindings {
		t.Fatalf("exit %d; stderr: %s", code, errOut.String())
	}
	var findings []struct {
		Repo, Tier, Check, Status string
	}
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatal(err)
	}
	tiers := map[string]string{}
	for _, f := range findings {
		tiers[f.Repo] = f.Tier
	}
	if tiers["service"] != "ci" || tiers["notes"] != "basic" {
		t.Errorf("tiers = %v", tiers)
	}
}

func TestSaveSnapshotRoundTrips(t *testing.T) {
	saved := filepath.Join(t.TempDir(), "copy.json")
	var out, errOut bytes.Buffer
	if code := run([]string{"--snapshot", fixture, "--save-snapshot", saved}, &out, &errOut); code == exitError {
		t.Fatalf("first run failed: %s", errOut.String())
	}
	if out.Len() == 0 {
		t.Fatal("first run produced no output")
	}

	var again bytes.Buffer
	if code := run([]string{"--snapshot", saved}, &again, &errOut); code == exitError {
		t.Fatalf("re-evaluating the saved snapshot failed: %s", errOut.String())
	}
	if again.String() != out.String() {
		t.Errorf("re-evaluating a saved snapshot changed the result:\n%s\nvs\n%s", out.String(), again.String())
	}
}

func TestUsageErrors(t *testing.T) {
	tests := map[string][]string{
		"bad format":       {"--snapshot", fixture, "--format", "xml"},
		"missing snapshot": {"--snapshot", "nope.json"},
		"missing baseline": {"--baseline", "nope.json"},
		"unknown flag":     {"--frobnicate"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(args, &out, &errOut); code != exitError {
				t.Errorf("exit %d, want %d", code, exitError)
			}
		})
	}
}

func TestNoOwner(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code != exitError || !strings.HasPrefix(errOut.String(), "gh-baseline: no owner") {
		t.Errorf("run() = %d, stderr %q; want %d and a \"gh-baseline: no owner\" message", code, errOut.String(), exitError)
	}
}
