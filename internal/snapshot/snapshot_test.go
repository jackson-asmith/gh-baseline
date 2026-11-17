package snapshot_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackson-asmith/gh-baseline/internal/snapshot"
)

func TestLoadRejectsNewerSchema(t *testing.T) {
	content := `{"schemaVersion":9999,"owner":"acme","repos":[]}`
	p := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Load(p); err == nil {
		t.Fatal("Load should fail on a snapshot with a future schema version")
	}
}

func TestLoadAcceptsVersion0(t *testing.T) {
	content := `{"owner":"acme","repos":[]}`
	p := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Load(p)
	if err != nil {
		t.Fatalf("Load should accept a snapshot with no schemaVersion: %v", err)
	}
	if s.SchemaVersion != 0 {
		t.Errorf("schemaVersion = %d, want 0", s.SchemaVersion)
	}
}

func TestSaveStampsSchemaVersion(t *testing.T) {
	s := &snapshot.Snapshot{
		Owner:       "acme",
		GeneratedAt: time.Now().UTC(),
	}
	p := filepath.Join(t.TempDir(), "snap.json")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	loaded, err := snapshot.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SchemaVersion != snapshot.CurrentSchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", loaded.SchemaVersion, snapshot.CurrentSchemaVersion)
	}
}

func TestSaveRoundTrips(t *testing.T) {
	s := &snapshot.Snapshot{
		Owner:       "acme",
		GeneratedAt: time.Now().UTC(),
		Repos: []snapshot.Repo{
			{Name: "api", DefaultBranch: "main"},
		},
	}
	p := filepath.Join(t.TempDir(), "snap.json")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := snapshot.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != s.Owner || len(got.Repos) != 1 || got.Repos[0].Name != "api" {
		t.Errorf("round-trip changed content: %+v", got)
	}
}
