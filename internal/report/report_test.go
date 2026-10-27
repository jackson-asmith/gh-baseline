package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackson-asmith/gh-baseline/internal/check"
	"github.com/jackson-asmith/gh-baseline/internal/report"
)

var sampleFindings = []check.Finding{
	{Owner: "acme", Repo: "myrepo", Check: "ruleset.branch-safety", Status: check.Fail, Severity: check.High, Message: "master allows deletion"},
	{Owner: "acme", Repo: "myrepo", Check: "ruleset.pull-request", Status: check.Pass, Severity: check.Medium, Message: "pull request required"},
	{Owner: "acme", Repo: "myrepo", Check: "security.secret-scanning", Status: check.Unknown, Severity: check.High, Message: "couldn't read security"},
	{Owner: "acme", Repo: "myrepo", Check: "workflow.dependabot-actions", Status: check.Skip, Severity: check.Low, Message: "no workflows"},
	{Owner: "acme", Repo: "myrepo", Check: "workflow.token-permissions", Status: check.Fail, Severity: check.Medium, Message: "no top-level permissions: .github/workflows/ci.yml"},
}

func TestSARIF_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := report.SARIF(&buf, sampleFindings); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestSARIF_Version(t *testing.T) {
	var buf bytes.Buffer
	report.SARIF(&buf, sampleFindings)
	var doc map[string]any
	json.Unmarshal(buf.Bytes(), &doc)
	if got := doc["version"]; got != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", got)
	}
}

func TestSARIF_OnlyFailAndUnknownInResults(t *testing.T) {
	var buf bytes.Buffer
	report.SARIF(&buf, sampleFindings)

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	results := doc.Runs[0].Results

	// pass and skip must not appear
	for _, r := range results {
		if r.RuleID == "ruleset.pull-request" || r.RuleID == "workflow.dependabot-actions" {
			t.Errorf("result for %s should be omitted (pass/skip)", r.RuleID)
		}
	}

	// fail and unknown must appear
	found := map[string]string{}
	for _, r := range results {
		found[r.RuleID] = r.Level
	}
	if found["ruleset.branch-safety"] != "error" {
		t.Errorf("ruleset.branch-safety (high fail): want level error, got %q", found["ruleset.branch-safety"])
	}
	if found["workflow.token-permissions"] != "warning" {
		t.Errorf("workflow.token-permissions (medium fail): want level warning, got %q", found["workflow.token-permissions"])
	}
	if found["security.secret-scanning"] != "warning" {
		t.Errorf("security.secret-scanning (unknown): want level warning, got %q", found["security.secret-scanning"])
	}
}

func TestSARIF_DriverRulesMatchCatalog(t *testing.T) {
	var buf bytes.Buffer
	report.SARIF(&buf, sampleFindings)

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	catalog := check.Catalog()
	rules := doc.Runs[0].Tool.Driver.Rules
	if len(rules) != len(catalog) {
		t.Errorf("driver has %d rules, catalog has %d", len(rules), len(catalog))
	}
	for i, r := range rules {
		if r.ID != catalog[i].ID {
			t.Errorf("rule[%d] id = %q, want %q", i, r.ID, catalog[i].ID)
		}
	}
}

func TestSARIF_LogicalLocation(t *testing.T) {
	var buf bytes.Buffer
	report.SARIF(&buf, sampleFindings)

	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					LogicalLocations []struct {
						Name string `json:"name"`
						Kind string `json:"kind"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) == 0 {
			t.Error("result has no locations")
			continue
		}
		ll := r.Locations[0].LogicalLocations
		if len(ll) == 0 {
			t.Error("result has no logicalLocations")
			continue
		}
		if ll[0].Name != "acme/myrepo" {
			t.Errorf("logicalLocation.name = %q, want %q", ll[0].Name, "acme/myrepo")
		}
		if ll[0].Kind != "repository" {
			t.Errorf("logicalLocation.kind = %q, want %q", ll[0].Kind, "repository")
		}
	}
}

func TestSARIF_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := report.SARIF(&buf, nil); err != nil {
		t.Fatalf("SARIF with nil findings: %v", err)
	}
	if !strings.Contains(buf.String(), `"results"`) {
		t.Error("expected results key in output")
	}
}
