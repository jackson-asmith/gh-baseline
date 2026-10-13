// Package snapshot defines the collected state of an account's repositories.
// Checks read only from a Snapshot, never from the network.
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Snapshot is everything collected in one run.
type Snapshot struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Host        string    `json:"host"`
	Owner       string    `json:"owner"`
	Repos       []Repo    `json:"repos"`
}

// Repo is one repository's collected state. A field that could not be read
// has an entry in Errors keyed by the field name, and checks that depend on
// it report "unknown".
type Repo struct {
	Name          string    `json:"name"`
	DefaultBranch string    `json:"defaultBranch"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	PushedAt      time.Time `json:"pushedAt"`

	// Security holds security_and_analysis statuses, e.g.
	// "secret_scanning": "enabled".
	Security map[string]string `json:"security,omitempty"`

	// VulnReporting is private vulnerability reporting; nil if unknown.
	VulnReporting *bool `json:"vulnReporting,omitempty"`

	// Rules are the effective rules on the default branch, from every
	// ruleset that applies.
	Rules []Rule `json:"rules"`

	// RulesetsUnavailable is set when the repository's plan doesn't offer
	// rulesets (a private repository on a free plan), so Rules is empty by
	// necessity rather than by choice. See docs/adr/0002-plan-limited-rulesets.md.
	RulesetsUnavailable bool `json:"rulesetsUnavailable,omitempty"`

	Workflows  []File `json:"workflows"`
	Dependabot *File  `json:"dependabot,omitempty"`

	Errors map[string]string `json:"errors,omitempty"`
}

// Rule is one effective branch rule.
type Rule struct {
	Type       string          `json:"type"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
	RulesetID  int64           `json:"ruleset_id,omitempty"`
}

// RequiredCheck is one entry in a required_status_checks rule.
type RequiredCheck struct {
	Context       string `json:"context"`
	IntegrationID *int64 `json:"integration_id"`
}

// File is a repository file's path and decoded content.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Field names used as keys in Repo.Errors.
const (
	FieldRepo          = "repo" // the repository itself; every check is unknown
	FieldSecurity      = "security"
	FieldVulnReporting = "vulnReporting"
	FieldRules         = "rules"
	FieldWorkflows     = "workflows"
	FieldDependabot    = "dependabot"
)

// HasRule reports whether an effective rule of type t exists.
func (r Repo) HasRule(t string) bool {
	for _, rule := range r.Rules {
		if rule.Type == t {
			return true
		}
	}
	return false
}

// RequiredChecks returns every required status check across all rules.
func (r Repo) RequiredChecks() ([]RequiredCheck, error) {
	var out []RequiredCheck
	for _, rule := range r.Rules {
		if rule.Type != "required_status_checks" {
			continue
		}
		var p struct {
			Checks []RequiredCheck `json:"required_status_checks"`
		}
		if err := json.Unmarshal(rule.Parameters, &p); err != nil {
			return nil, fmt.Errorf("ruleset %d: required_status_checks parameters: %w", rule.RulesetID, err)
		}
		out = append(out, p.Checks...)
	}
	return out, nil
}

// Load reads a snapshot from a JSON file.
func Load(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Save writes a snapshot as indented JSON.
func (s *Snapshot) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
