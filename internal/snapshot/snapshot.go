// Package snapshot defines the collected state of an account's repositories.
// Checks read only from a Snapshot, never from the network.
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CurrentSchemaVersion is the schema version written by this build. Increment
// it whenever the Snapshot or Repo JSON representation changes in a way that
// would cause an older evaluator to misread a newer snapshot.
const CurrentSchemaVersion = 2

// ObservationState is the data-collection outcome for one field.
type ObservationState string

const (
	ObservationAvailable   ObservationState = "available"
	ObservationUnavailable ObservationState = "unavailable" // expected (plan limit, not applicable)
	ObservationError       ObservationState = "error"       // unexpected (token scope, network)
)

// ReasonCode is a stable domain concept explaining why an observation is
// unavailable or errored. Checks may branch on these; they must never parse
// Message strings to infer meaning.
type ReasonCode string

const (
	ReasonPlanUnavailable ReasonCode = "plan_unavailable" // feature needs a paid plan
	ReasonForbidden       ReasonCode = "forbidden"        // HTTP 403
	ReasonNotFound        ReasonCode = "not_found"        // HTTP 404
	ReasonMissingScope    ReasonCode = "missing_scope"    // token lacks required scope
	ReasonRateLimited     ReasonCode = "rate_limited"     // hit rate limit
	ReasonNotApplicable   ReasonCode = "not_applicable"   // check doesn't apply to this repo type
)

// Observation is a three-state collected field: the data was read (Available),
// couldn't be read for a known reason (Unavailable), or failed unexpectedly (Error).
type Observation[T any] struct {
	State      ObservationState `json:"state"`
	Value      T                `json:"value,omitempty"`
	ReasonCode ReasonCode       `json:"reasonCode,omitempty"`
	Message    string           `json:"message,omitempty"`
}

// FeatureState is the on/off state of a repository security feature.
type FeatureState string

const (
	FeatureEnabled  FeatureState = "enabled"
	FeatureDisabled FeatureState = "disabled"
)

// PolicyState is the present/absent state of a security policy file.
type PolicyState string

const (
	PolicyPresent PolicyState = "present"
	PolicyAbsent  PolicyState = "absent"
)

// RepositorySecurity holds the per-feature security_and_analysis observations.
type RepositorySecurity struct {
	SecretScanning Observation[FeatureState] `json:"secretScanning"`
	PushProtection Observation[FeatureState] `json:"pushProtection"`
}

// Snapshot is everything collected in one run.
type Snapshot struct {
	SchemaVersion int       `json:"schemaVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	Host          string    `json:"host"`
	Owner         string    `json:"owner"`
	Repos         []Repo    `json:"repos"`
}

// Repo is one repository's collected state. Fields that could not be read are
// encoded as Observation values with State set to ObservationError or
// ObservationUnavailable, with the reason in ReasonCode. The Errors map holds
// errors for non-observation fields (rules, workflows, secrets, etc.).
type Repo struct {
	Name          string    `json:"name"`
	DefaultBranch string    `json:"defaultBranch"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	PushedAt      time.Time `json:"pushedAt"`

	// RepoSecurity holds the security_and_analysis feature observations.
	RepoSecurity RepositorySecurity `json:"repoSecurity"`

	// VulnReporting is the private vulnerability reporting feature state.
	VulnReporting Observation[FeatureState] `json:"vulnReporting"`

	// SecurityPolicy reports whether a SECURITY.md exists in any location
	// GitHub recognises (root, .github/, or docs/). Unavailable for private
	// repositories (not applicable: external reporters can't reach them).
	SecurityPolicy Observation[PolicyState] `json:"securityPolicy"`

	// SecurityPolicySource is empty when the repository has its own
	// SECURITY.md, or "owner/.github" when GitHub uses the account's default.
	SecurityPolicySource string `json:"securityPolicySource,omitempty"`

	// Rules are the effective rules on the default branch, from every
	// ruleset that applies.
	Rules []Rule `json:"rules"`

	// RulesetsUnavailable is set when the repository's plan doesn't offer
	// rulesets (a private repository on a free plan), so Rules is empty by
	// necessity rather than by choice. See docs/adr/0002-plan-limited-rulesets.md.
	RulesetsUnavailable bool `json:"rulesetsUnavailable,omitempty"`

	Workflows  []File `json:"workflows"`
	Dependabot *File  `json:"dependabot,omitempty"`

	// Secrets names the Actions secrets this repository's workflows can read:
	// repository and environment secrets, plus organization secrets shared
	// with it. Empty means none exist; nil means they weren't collected, as
	// for a repository without workflows or a snapshot from before v0.2.0.
	Secrets []string `json:"secrets"`

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
	FieldRepo       = "repo" // the repository itself; every check is unknown
	FieldRules      = "rules"
	FieldWorkflows  = "workflows"
	FieldDependabot = "dependabot"
	FieldSecrets    = "secrets"
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

// Load reads a snapshot from a JSON file. Snapshots with no schemaVersion
// (v0) or schemaVersion 1 are automatically migrated to the current format.
// Snapshots from a future version that this build cannot interpret are rejected.
func Load(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var header struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(b, &header); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if header.SchemaVersion > CurrentSchemaVersion {
		return nil, fmt.Errorf("%s: snapshot schema version %d is newer than this build supports (%d); upgrade gh-baseline", path, header.SchemaVersion, CurrentSchemaVersion)
	}
	if header.SchemaVersion < CurrentSchemaVersion {
		var ls legacySnapshot
		if err := json.Unmarshal(b, &ls); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return migrateSnapshot(ls), nil
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Save writes a snapshot as indented JSON, stamping the current schema version.
func (s *Snapshot) Save(path string) error {
	s.SchemaVersion = CurrentSchemaVersion
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// legacySnapshot and legacyRepo hold the pre-v2 JSON layout for migration.
type legacySnapshot struct {
	SchemaVersion int          `json:"schemaVersion"`
	GeneratedAt   time.Time    `json:"generatedAt"`
	Host          string       `json:"host"`
	Owner         string       `json:"owner"`
	Repos         []legacyRepo `json:"repos"`
}

type legacyRepo struct {
	Name                 string            `json:"name"`
	DefaultBranch        string            `json:"defaultBranch"`
	Private              bool              `json:"private"`
	Fork                 bool              `json:"fork"`
	Archived             bool              `json:"archived"`
	PushedAt             time.Time         `json:"pushedAt"`
	Security             map[string]string `json:"security"`
	VulnReporting        *bool             `json:"vulnReporting"`
	SecurityPolicy       *bool             `json:"securityPolicy"`
	SecurityPolicySource string            `json:"securityPolicySource"`
	Rules                []Rule            `json:"rules"`
	RulesetsUnavailable  bool              `json:"rulesetsUnavailable"`
	Workflows            []File            `json:"workflows"`
	Dependabot           *File             `json:"dependabot"`
	Secrets              []string          `json:"secrets"`
	Errors               map[string]string `json:"errors"`
}

// migrateSnapshot converts a pre-v2 snapshot to the current format.
func migrateSnapshot(ls legacySnapshot) *Snapshot {
	s := &Snapshot{
		SchemaVersion: ls.SchemaVersion,
		GeneratedAt:   ls.GeneratedAt,
		Host:          ls.Host,
		Owner:         ls.Owner,
	}
	for _, lr := range ls.Repos {
		r := Repo{
			Name:                 lr.Name,
			DefaultBranch:        lr.DefaultBranch,
			Private:              lr.Private,
			Fork:                 lr.Fork,
			Archived:             lr.Archived,
			PushedAt:             lr.PushedAt,
			Rules:                lr.Rules,
			RulesetsUnavailable:  lr.RulesetsUnavailable,
			Workflows:            lr.Workflows,
			Dependabot:           lr.Dependabot,
			Secrets:              lr.Secrets,
			SecurityPolicySource: lr.SecurityPolicySource,
		}
		for k, v := range lr.Errors {
			switch k {
			case "security", "vulnReporting", "securityPolicy":
				// migrated below
			default:
				if r.Errors == nil {
					r.Errors = map[string]string{}
				}
				r.Errors[k] = v
			}
		}
		// Migrate security_and_analysis → RepoSecurity.
		if errMsg, ok := lr.Errors["security"]; ok {
			code := ReasonMissingScope
			if lr.Private {
				code = ReasonPlanUnavailable
			}
			unavail := Observation[FeatureState]{State: ObservationUnavailable, ReasonCode: code, Message: errMsg}
			r.RepoSecurity = RepositorySecurity{SecretScanning: unavail, PushProtection: unavail}
		} else {
			featureObs := func(key string) Observation[FeatureState] {
				v, ok := lr.Security[key]
				if !ok {
					return Observation[FeatureState]{State: ObservationUnavailable, ReasonCode: ReasonPlanUnavailable}
				}
				fs := FeatureDisabled
				if v == "enabled" {
					fs = FeatureEnabled
				}
				return Observation[FeatureState]{State: ObservationAvailable, Value: fs}
			}
			r.RepoSecurity = RepositorySecurity{
				SecretScanning: featureObs("secret_scanning"),
				PushProtection: featureObs("secret_scanning_push_protection"),
			}
		}
		// Migrate vulnReporting → VulnReporting.
		if errMsg, ok := lr.Errors["vulnReporting"]; ok {
			r.VulnReporting = Observation[FeatureState]{State: ObservationError, Message: errMsg}
		} else if lr.VulnReporting != nil {
			v := FeatureDisabled
			if *lr.VulnReporting {
				v = FeatureEnabled
			}
			r.VulnReporting = Observation[FeatureState]{State: ObservationAvailable, Value: v}
		}
		// Migrate securityPolicy → SecurityPolicy.
		if errMsg, ok := lr.Errors["securityPolicy"]; ok {
			r.SecurityPolicy = Observation[PolicyState]{State: ObservationError, Message: errMsg}
		} else if lr.Private {
			r.SecurityPolicy = Observation[PolicyState]{State: ObservationUnavailable, ReasonCode: ReasonNotApplicable}
		} else if lr.SecurityPolicy != nil {
			ps := PolicyAbsent
			if *lr.SecurityPolicy {
				ps = PolicyPresent
			}
			r.SecurityPolicy = Observation[PolicyState]{State: ObservationAvailable, Value: ps}
		}
		s.Repos = append(s.Repos, r)
	}
	return s
}
