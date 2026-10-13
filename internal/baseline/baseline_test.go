package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExample(t *testing.T) {
	b, err := Load("../../baseline.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if name, tier := b.TierFor("linuxconfig"); name != "ci" || !tier.RequireStatusChecks {
		t.Errorf("TierFor is case-insensitive: got %q %+v", name, tier)
	}
	if name, _ := b.TierFor("unlisted"); name != "basic" {
		t.Errorf("unlisted repo got tier %q, want basic", name)
	}
	if b.StaleDays != 365 {
		t.Errorf("StaleDays = %d", b.StaleDays)
	}
}

func TestLoadDefaultsStaleDays(t *testing.T) {
	b, err := Load(write(t, `{"defaultTier":"x","tiers":{"x":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if b.StaleDays != 365 || !b.IncludeForks {
		t.Errorf("defaults not applied: %+v", b)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	tests := map[string]string{
		"no tiers":          `{"defaultTier":"basic"}`,
		"bad default tier":  `{"defaultTier":"nope","tiers":{"basic":{}}}`,
		"repo unknown tier": `{"defaultTier":"basic","tiers":{"basic":{}},"repos":{"r":"ci"}}`,
		"bad staleDays":     `{"defaultTier":"basic","tiers":{"basic":{}},"staleDays":-1}`,
		"not json":          `{`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Error("want error")
			} else if !strings.Contains(err.Error(), "baseline.json") {
				t.Errorf("error should name the file: %v", err)
			}
		})
	}
}
