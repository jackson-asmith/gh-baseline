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
	run([]string{"--snapshot", fixture, "--save-snapshot", saved}, &out, &errOut)

	var again bytes.Buffer
	run([]string{"--snapshot", saved}, &again, &errOut)
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
	if code := run(nil, &out, &errOut); code != exitError || !strings.Contains(errOut.String(), "no owner") {
		t.Errorf("exit %d, stderr %q", code, errOut.String())
	}
}
