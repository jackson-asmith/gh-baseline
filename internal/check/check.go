// Package check evaluates a snapshot against a baseline. Every check is a
// pure function of one repository's collected state and its tier.
package check

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackson-asmith/gh-baseline/internal/baseline"
	"github.com/jackson-asmith/gh-baseline/internal/snapshot"
	"github.com/jackson-asmith/gh-baseline/internal/workflowparse"
)

// Status is the outcome of one check on one repository.
type Status string

// Check outcomes.
const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Unknown Status = "unknown" // the data needed wasn't readable
	Skip    Status = "skip"    // the check doesn't apply
)

// Severity ranks failures.
type Severity string

// Severities, from most to least urgent.
const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
)

// Finding is one check's result for one repository.
type Finding struct {
	Owner       string   `json:"owner"`
	Repo        string   `json:"repo"`
	Tier        string   `json:"tier"`
	Check       string   `json:"check"`
	Status      Status   `json:"status"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
}

// Policy is the internal representation of what a repository should be
// checked against. It is derived from the baseline configuration at evaluation
// time and is independent of the baseline JSON format, so the config schema can
// evolve (e.g. per-check severity overrides) without touching individual checks.
type Policy struct {
	RequirePullRequest  bool
	RequireStatusChecks bool
}

// Input is what a check sees.
type Input struct {
	Repo      snapshot.Repo
	Policy    Policy
	Now       time.Time
	StaleDays int
}

// Check is one rule in the catalog.
type Check struct {
	ID          string
	Severity    Severity
	Remediation string
	Run         func(Input) (Status, string)
}

// Evaluate runs every check against every repository in the snapshot.
func Evaluate(s *snapshot.Snapshot, b *baseline.Baseline, now time.Time) []Finding {
	var out []Finding
	for _, r := range s.Repos {
		tierName, tier := b.TierFor(r.Name)
		policy := Policy{
			RequirePullRequest:  tier.RequirePullRequest,
			RequireStatusChecks: tier.RequireStatusChecks,
		}
		in := Input{Repo: r, Policy: policy, Now: now, StaleDays: b.StaleDays}
		repoErr, unreadable := r.Errors[snapshot.FieldRepo]
		for _, c := range catalog {
			var st Status
			var msg string
			if unreadable {
				st, msg = Unknown, "couldn't read repository: "+repoErr
			} else {
				st, msg = c.Run(in)
			}
			f := Finding{Owner: s.Owner, Repo: r.Name, Tier: tierName, Check: c.ID, Status: st, Severity: c.Severity, Message: msg}
			if st == Fail || st == Unknown {
				f.Remediation = c.Remediation
			}
			out = append(out, f)
		}
	}
	return out
}

// rulesUnreadable is unknownIf for the rules field, except that a repository
// whose plan doesn't offer rulesets is skipped: it can't be protected, so
// there is nothing to fix and nothing unknown. The collector decides which
// repositories those are.
func rulesUnreadable(r snapshot.Repo) (Status, string, bool) {
	if r.RulesetsUnavailable {
		return Skip, "rulesets need a paid plan for private repos", true
	}
	return unknownIf(r, snapshot.FieldRules)
}

// unknownIf returns Unknown with the recorded error when field couldn't be read.
func unknownIf(r snapshot.Repo, field string) (Status, string, bool) {
	if e, ok := r.Errors[field]; ok {
		return Unknown, "couldn't read " + field + ": " + e, true
	}
	return "", "", false
}

// Descriptor is the static metadata for one check, used by report formats
// that need the full rule catalog independent of which checks fired.
type Descriptor struct {
	ID          string
	Severity    Severity
	Remediation string
}

// Catalog returns the static metadata for every check in report order.
func Catalog() []Descriptor {
	out := make([]Descriptor, len(catalog))
	for i, c := range catalog {
		out[i] = Descriptor{ID: c.ID, Severity: c.Severity, Remediation: c.Remediation}
	}
	return out
}

// catalog is every check, in report order.
var catalog = []Check{
	{
		ID:          "ruleset.branch-safety",
		Severity:    High,
		Remediation: "Add a ruleset on the default branch with \"Restrict deletions\" and \"Block force pushes\".",
		Run: func(in Input) (Status, string) {
			if st, msg, ok := rulesUnreadable(in.Repo); ok {
				return st, msg
			}
			var missing []string
			if !in.Repo.HasRule("deletion") {
				missing = append(missing, "deletion")
			}
			if !in.Repo.HasRule("non_fast_forward") {
				missing = append(missing, "force push")
			}
			if len(missing) > 0 {
				return Fail, fmt.Sprintf("%s allows %s", in.Repo.DefaultBranch, strings.Join(missing, " and "))
			}
			return Pass, in.Repo.DefaultBranch + " blocks deletion and force pushes"
		},
	},
	{
		ID:          "ruleset.pull-request",
		Severity:    Medium,
		Remediation: "Add \"Require a pull request before merging\" to the default-branch ruleset.",
		Run: func(in Input) (Status, string) {
			if !in.Policy.RequirePullRequest {
				return Skip, "tier doesn't require pull requests"
			}
			if st, msg, ok := rulesUnreadable(in.Repo); ok {
				return st, msg
			}
			if !in.Repo.HasRule("pull_request") {
				return Fail, "changes can reach " + in.Repo.DefaultBranch + " without a pull request"
			}
			return Pass, "pull request required"
		},
	},
	{
		ID:          "ruleset.status-checks",
		Severity:    Medium,
		Remediation: "Add \"Require status checks to pass\" with the CI jobs that must succeed.",
		Run: func(in Input) (Status, string) {
			if !in.Policy.RequireStatusChecks {
				return Skip, "tier doesn't require status checks"
			}
			if st, msg, ok := rulesUnreadable(in.Repo); ok {
				return st, msg
			}
			checks, err := in.Repo.RequiredChecks()
			if err != nil {
				return Unknown, err.Error()
			}
			n := len(checks)
			if n == 0 {
				return Fail, "no status checks are required"
			}
			return Pass, count(n, "status check", "status checks") + " required"
		},
	},
	{
		ID:          "ruleset.check-source",
		Severity:    High,
		Remediation: "Edit each required check in the ruleset and set its source to the app that runs it (usually GitHub Actions).",
		Run: func(in Input) (Status, string) {
			if st, msg, ok := rulesUnreadable(in.Repo); ok {
				return st, msg
			}
			checks, err := in.Repo.RequiredChecks()
			if err != nil {
				return Unknown, err.Error()
			}
			if len(checks) == 0 {
				return Skip, "no required checks"
			}
			var anySource []string
			for _, c := range checks {
				if c.IntegrationID == nil {
					anySource = append(anySource, c.Context)
				}
			}
			if len(anySource) > 0 {
				return Fail, "accepts any source: " + strings.Join(anySource, ", ")
			}
			return Pass, pinnedMessage(len(checks))
		},
	},
	securityToggle("security.secret-scanning",
		func(s snapshot.RepositorySecurity) snapshot.Observation[snapshot.FeatureState] {
			return s.SecretScanning
		},
		"secret scanning",
		"Enable Secret Protection under Settings → Advanced Security."),
	securityToggle("security.push-protection",
		func(s snapshot.RepositorySecurity) snapshot.Observation[snapshot.FeatureState] {
			return s.PushProtection
		},
		"push protection",
		"Enable Push protection under Settings → Advanced Security → Secret Protection."),
	{
		ID:          "security.security-policy",
		Severity:    Low,
		Remediation: "Add a SECURITY.md describing how to report vulnerabilities, either to the repository (root, .github/, or docs/) or to the account's public .github repository as a default for all its repositories.",
		Run: func(in Input) (Status, string) {
			if in.Repo.Private {
				return Skip, "private repository"
			}
			switch o := in.Repo.SecurityPolicy; o.State {
			case snapshot.ObservationAvailable:
				if o.Value == snapshot.PolicyAbsent {
					return Fail, "no SECURITY.md found"
				}
				if src := in.Repo.SecurityPolicySource; src != "" {
					return Pass, "SECURITY.md exists (account default from " + src + ")"
				}
				return Pass, "SECURITY.md exists"
			case snapshot.ObservationError:
				return Unknown, "couldn't read securityPolicy: " + o.Message
			default:
				return Unknown, "security policy not collected"
			}
		},
	},
	{
		ID:          "security.vuln-reporting",
		Severity:    Low,
		Remediation: "Enable private vulnerability reporting under Settings → Advanced Security.",
		Run: func(in Input) (Status, string) {
			if in.Repo.Private {
				return Skip, "private repository"
			}
			switch o := in.Repo.VulnReporting; o.State {
			case snapshot.ObservationAvailable:
				if o.Value == snapshot.FeatureEnabled {
					return Pass, "private vulnerability reporting is on"
				}
				return Fail, "private vulnerability reporting is off"
			case snapshot.ObservationError:
				return Unknown, "couldn't read vulnReporting: " + o.Message
			default:
				return Unknown, "private vulnerability reporting status unknown"
			}
		},
	},
	{
		ID:          "workflow.token-permissions",
		Severity:    Medium,
		Remediation: "Declare `permissions:` explicitly at the top level. Default to `permissions: contents: read` and grant additional scopes per job only where needed.",
		Run: func(in Input) (Status, string) {
			if st, msg, ok := unknownIf(in.Repo, snapshot.FieldWorkflows); ok {
				return st, msg
			}
			if len(in.Repo.Workflows) == 0 {
				return Skip, "no workflows"
			}
			var missing []string
			for _, w := range in.Repo.Workflows {
				if w.Evidence.Permissions == nil {
					missing = append(missing, w.Path)
				}
			}
			if len(missing) > 0 {
				return Fail, "no top-level permissions: " + strings.Join(missing, ", ")
			}
			return Pass, "every workflow declares permissions"
		},
	},
	{
		ID:          "workflow.token-permissions-scope",
		Severity:    Medium,
		Remediation: "Replace `permissions: write-all` with an explicit scope map granting only the scopes each job needs.",
		Run: func(in Input) (Status, string) {
			if st, msg, ok := unknownIf(in.Repo, snapshot.FieldWorkflows); ok {
				return st, msg
			}
			if len(in.Repo.Workflows) == 0 {
				return Skip, "no workflows"
			}
			var broad []string
			for _, w := range in.Repo.Workflows {
				if w.Evidence.Permissions != nil && w.Evidence.Permissions.WriteAll {
					broad = append(broad, w.Path)
				}
			}
			if len(broad) > 0 {
				return Fail, "permissions: write-all in " + strings.Join(broad, ", ")
			}
			return Pass, "no workflow grants write-all"
		},
	},
	{
		ID:          "workflow.pinned-actions",
		Severity:    Medium,
		Remediation: "Reference actions by full commit SHA with the version in a comment, e.g. `actions/checkout@<sha> # v5.1.0`.",
		Run: func(in Input) (Status, string) {
			if st, msg, ok := unknownIf(in.Repo, snapshot.FieldWorkflows); ok {
				return st, msg
			}
			if len(in.Repo.Workflows) == 0 {
				return Skip, "no workflows"
			}
			var refs []string
			for _, w := range in.Repo.Workflows {
				for _, a := range w.Evidence.Actions {
					if !a.Pinned {
						refs = append(refs, a.Ref)
					}
				}
			}
			if len(refs) > 0 {
				slices.Sort(refs)
				refs = slices.Compact(refs)
				return Fail, "not pinned to a SHA: " + strings.Join(refs, ", ")
			}
			return Pass, "all actions pinned"
		},
	},
	{
		ID:          "workflow.reusable-callee-pinned",
		Severity:    Medium,
		Remediation: "Reference reusable workflows by full commit SHA with the version in a comment, e.g. `owner/repo/.github/workflows/ci.yml@<sha> # v2.3.0`.",
		Run: func(in Input) (Status, string) {
			if st, msg, ok := unknownIf(in.Repo, snapshot.FieldWorkflows); ok {
				return st, msg
			}
			if len(in.Repo.Workflows) == 0 {
				return Skip, "no workflows"
			}
			var refs []string
			for _, w := range in.Repo.Workflows {
				for _, a := range w.Evidence.Actions {
					if a.Kind == workflowparse.ActionKindReusable && !a.Pinned {
						refs = append(refs, a.Ref)
					}
				}
			}
			if len(refs) > 0 {
				slices.Sort(refs)
				refs = slices.Compact(refs)
				return Fail, "reusable workflow not pinned to a SHA: " + strings.Join(refs, ", ")
			}
			return Pass, "all reusable workflow calls pinned"
		},
	},
	{
		ID:          "workflow.dependabot-actions",
		Severity:    Low,
		Remediation: "Add a `github-actions` entry to .github/dependabot.yml so pinned SHAs get updated.",
		Run: func(in Input) (Status, string) {
			if st, msg, ok := unknownIf(in.Repo, snapshot.FieldWorkflows); ok {
				return st, msg
			}
			if len(in.Repo.Workflows) == 0 {
				return Skip, "no workflows"
			}
			if st, msg, ok := unknownIf(in.Repo, snapshot.FieldDependabot); ok {
				return st, msg
			}
			if in.Repo.Dependabot == nil {
				return Fail, "no dependabot.yml"
			}
			if !dependabotCoversActions(in.Repo.Dependabot.Content) {
				return Fail, "dependabot.yml doesn't cover github-actions"
			}
			return Pass, "Dependabot updates actions"
		},
	},
	{
		ID:          "workflow.stale-secrets",
		Severity:    High,
		Remediation: "If the repo is retired, archive it, delete its Actions secrets, and revoke the credentials behind them.",
		// A stale workflow is only dangerous if the secrets it names still
		// exist, so references in workflow text are checked against the
		// secrets collected for the repository.
		Run: func(in Input) (Status, string) {
			if st, msg, ok := unknownIf(in.Repo, snapshot.FieldWorkflows); ok {
				return st, msg
			}
			if len(in.Repo.Workflows) == 0 {
				return Skip, "no workflows"
			}
			if in.Repo.PushedAt.IsZero() {
				return Unknown, "no push date recorded"
			}
			days := int(in.Now.Sub(in.Repo.PushedAt).Hours() / 24)
			if days < in.StaleDays {
				return Pass, "last push " + count(days, "day", "days") + " ago"
			}
			var names []string
			var inherits, automatic bool
			for _, w := range in.Repo.Workflows {
				for _, s := range w.Evidence.Secrets {
					if s.Inherited {
						inherits = true
					} else {
						names = append(names, s.Name)
					}
				}
				if workflowparse.HasAutomaticTrigger(w.Evidence) {
					automatic = true
				}
			}
			slices.Sort(names)
			names = slices.Compact(names)
			if len(names) == 0 && !inherits {
				return Pass, fmt.Sprintf("stale (%s) but workflows use no secrets", count(days, "day", "days"))
			}
			if e, ok := in.Repo.Errors[snapshot.FieldSecrets]; ok {
				return Unknown, fmt.Sprintf("no push in %s; workflows use secrets; couldn't read which secrets exist: %s", count(days, "day", "days"), e)
			}
			if in.Repo.Secrets == nil {
				return Unknown, fmt.Sprintf("no push in %s; workflows use secrets; the snapshot doesn't record which secrets exist", count(days, "day", "days"))
			}
			if inherits && len(in.Repo.Secrets) > 0 {
				return Fail, fmt.Sprintf("no push in %s; a workflow uses secrets: inherit and %s still exist — audit the callee", count(days, "day", "days"), count(len(in.Repo.Secrets), "secret", "secrets"))
			}
			if len(names) == 0 {
				return Pass, fmt.Sprintf("stale (%s); a workflow uses secrets: inherit but no secrets exist", count(days, "day", "days"))
			}
			used := strings.Join(names, ", ")
			var live []string
			for _, n := range names {
				// Secret names are case-insensitive; GitHub stores them in upper case.
				if slices.ContainsFunc(in.Repo.Secrets, func(s string) bool { return strings.EqualFold(s, n) }) {
					live = append(live, n)
				}
			}
			if len(live) == 0 {
				return Pass, fmt.Sprintf("stale (%s); workflows use %s, but no such secrets exist", count(days, "day", "days"), used)
			}
			if automatic {
				return Fail, fmt.Sprintf("no push in %s; secrets %s still exist and a scheduled workflow uses them", count(days, "day", "days"), strings.Join(live, ", "))
			}
			return Fail, fmt.Sprintf("no push in %s; secrets %s still exist and workflows reference them (push-only triggers — reachable only on a future push)", count(days, "day", "days"), strings.Join(live, ", "))
		},
	},
}

// count formats n with the matching noun: "1 day", "3 days".
func count(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func pinnedMessage(n int) string {
	if n == 1 {
		return "the required check is pinned to a source"
	}
	return fmt.Sprintf("all %d required checks are pinned to a source", n)
}

func securityToggle(
	id string,
	field func(snapshot.RepositorySecurity) snapshot.Observation[snapshot.FeatureState],
	label, remediation string,
) Check {
	return Check{
		ID:          id,
		Severity:    High,
		Remediation: remediation,
		Run: func(in Input) (Status, string) {
			switch o := field(in.Repo.RepoSecurity); o.State {
			case snapshot.ObservationAvailable:
				if o.Value == snapshot.FeatureEnabled {
					return Pass, label + " is on"
				}
				return Fail, label + " is off"
			case snapshot.ObservationUnavailable:
				if in.Repo.Private {
					return Skip, "private repository (feature may require a paid plan)"
				}
				return Unknown, label + " status not returned"
			default:
				return Unknown, "couldn't read security_and_analysis"
			}
		},
	}
}
