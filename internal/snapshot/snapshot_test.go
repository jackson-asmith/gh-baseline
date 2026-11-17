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

func TestLoadMigratesVersion0(t *testing.T) {
	content := `{"owner":"acme","repos":[{"name":"api","defaultBranch":"main","security":{"secret_scanning":"enabled","secret_scanning_push_protection":"enabled"},"vulnReporting":true,"securityPolicy":true,"rules":null,"workflows":[],"secrets":null}]}`
	p := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Load(p)
	if err != nil {
		t.Fatalf("Load should migrate a v0 snapshot: %v", err)
	}
	if s.SchemaVersion != 0 {
		t.Errorf("schemaVersion = %d, want 0 (Load preserves the original version)", s.SchemaVersion)
	}
	if len(s.Repos) != 1 {
		t.Fatalf("got %d repos, want 1", len(s.Repos))
	}
	r := s.Repos[0]
	if r.RepoSecurity.SecretScanning.State != snapshot.ObservationAvailable || r.RepoSecurity.SecretScanning.Value != snapshot.FeatureEnabled {
		t.Errorf("secretScanning = %v, want available/enabled", r.RepoSecurity.SecretScanning)
	}
	if r.VulnReporting.State != snapshot.ObservationAvailable || r.VulnReporting.Value != snapshot.FeatureEnabled {
		t.Errorf("vulnReporting = %v, want available/enabled", r.VulnReporting)
	}
	if r.SecurityPolicy.State != snapshot.ObservationAvailable || r.SecurityPolicy.Value != snapshot.PolicyPresent {
		t.Errorf("securityPolicy = %v, want available/present", r.SecurityPolicy)
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
