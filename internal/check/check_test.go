package check

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackson-asmith/gh-baseline/internal/baseline"
	"github.com/jackson-asmith/gh-baseline/internal/snapshot"
)

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func byID(t *testing.T, id string) Check {
	t.Helper()
	for _, c := range catalog {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q", id)
	return Check{}
}

func rule(typ string, params any) snapshot.Rule {
	r := snapshot.Rule{Type: typ}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			panic(err) // test fixtures are static; this can't happen
		}
		r.Parameters = b
	}
	return r
}

func checksRule(sources ...*int64) snapshot.Rule {
	var cs []snapshot.RequiredCheck
	for i, s := range sources {
		cs = append(cs, snapshot.RequiredCheck{Context: "job" + string(rune('A'+i)), IntegrationID: s})
	}
	return rule("required_status_checks", map[string]any{"required_status_checks": cs})
}

func ptr[T any](v T) *T { return &v }

// healthy is a public repo that passes every check in the "ci" tier.
func healthy() snapshot.Repo {
	return snapshot.Repo{
		Name:          "good",
		DefaultBranch: "main",
		PushedAt:      now.AddDate(0, 0, -3),
		Security: map[string]string{
			"secret_scanning":                 "enabled",
			"secret_scanning_push_protection": "enabled",
		},
		VulnReporting: ptr(true),
		Rules: []snapshot.Rule{
			rule("deletion", nil),
			rule("non_fast_forward", nil),
			rule("pull_request", map[string]any{}),
			checksRule(ptr(int64(15368))),
		},
		Workflows: []snapshot.File{{
			Path:    ".github/workflows/ci.yml",
			Content: "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n      - run: echo ${{ secrets.TOKEN }}\n",
		}},
		Dependabot: &snapshot.File{Path: ".github/dependabot.yml", Content: "updates:\n  - package-ecosystem: github-actions\n"},
		Secrets:    []string{"TOKEN"},
	}
}

// planLimited is the error GitHub returns for rules on a free plan's private
// repo (observed 2026-10-13). Only the collector interprets it.
const planLimited = "HTTP 403: Upgrade to GitHub Pro or make this repository public to enable this feature."

var ciTier = baseline.Tier{RequirePullRequest: true, RequireStatusChecks: true}

func TestHealthyRepoPassesEverything(t *testing.T) {
	in := Input{Repo: healthy(), Tier: ciTier, Now: now, StaleDays: 365}
	for _, c := range catalog {
		if st, msg := c.Run(in); st != Pass {
			t.Errorf("%s: got %s (%s), want pass", c.ID, st, msg)
		}
	}
}

func TestChecks(t *testing.T) {
	tests := []struct {
		check  string
		name   string
		mutate func(*snapshot.Repo)
		tier   baseline.Tier
		want   Status
		detail string // substring expected in the message
	}{
		{"ruleset.branch-safety", "no rules", func(r *snapshot.Repo) { r.Rules = nil }, ciTier, Fail, "deletion and force push"},
		{"ruleset.branch-safety", "force pushes allowed", func(r *snapshot.Repo) { r.Rules = r.Rules[:1] }, ciTier, Fail, "force push"},
		{"ruleset.branch-safety", "rules unreadable", func(r *snapshot.Repo) { r.Errors = map[string]string{"rules": "HTTP 403"} }, ciTier, Unknown, "HTTP 403"},
		{"ruleset.branch-safety", "plan without rulesets", func(r *snapshot.Repo) {
			r.RulesetsUnavailable = true
		}, ciTier, Skip, "paid plan"},
		{"ruleset.branch-safety", "error text not interpreted", func(r *snapshot.Repo) { r.Errors = map[string]string{"rules": planLimited} }, ciTier, Unknown, "HTTP 403"}, // checks never interpret error text; the collector does
		{"ruleset.branch-safety", "private repo, rules not found", func(r *snapshot.Repo) {
			r.Private = true
			r.Errors = map[string]string{"rules": "HTTP 404: Not Found"}
		}, ciTier, Unknown, "HTTP 404"},
		{"ruleset.pull-request", "plan without rulesets", func(r *snapshot.Repo) {
			r.RulesetsUnavailable = true
		}, ciTier, Skip, "paid plan"},
		{"ruleset.status-checks", "plan without rulesets", func(r *snapshot.Repo) {
			r.RulesetsUnavailable = true
		}, ciTier, Skip, "paid plan"},
		{"ruleset.check-source", "plan without rulesets", func(r *snapshot.Repo) {
			r.RulesetsUnavailable = true
		}, ciTier, Skip, "paid plan"},

		{"ruleset.pull-request", "no pull request rule", func(r *snapshot.Repo) { r.Rules = r.Rules[:2] }, ciTier, Fail, "without a pull request"},
		{"ruleset.pull-request", "tier does not require", func(r *snapshot.Repo) { r.Rules = nil }, baseline.Tier{}, Skip, ""},

		{"ruleset.status-checks", "none required", func(r *snapshot.Repo) { r.Rules = r.Rules[:3] }, ciTier, Fail, "no status checks"},
		{"ruleset.status-checks", "tier does not require", func(r *snapshot.Repo) { r.Rules = nil }, baseline.Tier{RequirePullRequest: true}, Skip, ""},

		{"ruleset.check-source", "any source accepted", func(r *snapshot.Repo) { r.Rules[3] = checksRule(ptr(int64(15368)), nil) }, ciTier, Fail, "jobB"},
		{"ruleset.check-source", "no required checks", func(r *snapshot.Repo) { r.Rules = r.Rules[:3] }, ciTier, Skip, ""},

		{"security.secret-scanning", "off", func(r *snapshot.Repo) { r.Security["secret_scanning"] = "disabled" }, ciTier, Fail, "off"},
		{"security.secret-scanning", "private repo", func(r *snapshot.Repo) { r.Private = true }, ciTier, Skip, "private"},
		{"security.secret-scanning", "settings unreadable", func(r *snapshot.Repo) { r.Security = nil; r.Errors = map[string]string{"security": "x"} }, ciTier, Unknown, ""},
		{"security.push-protection", "status not returned", func(r *snapshot.Repo) { delete(r.Security, "secret_scanning_push_protection") }, ciTier, Unknown, "not returned"},

		{"security.vuln-reporting", "off", func(r *snapshot.Repo) { r.VulnReporting = ptr(false) }, ciTier, Fail, "off"},

		{"workflow.token-permissions", "no top-level permissions", func(r *snapshot.Repo) { r.Workflows[0].Content = "jobs: {}\n" }, ciTier, Fail, "ci.yml"},
		{"workflow.token-permissions", "no workflows", func(r *snapshot.Repo) { r.Workflows = nil }, ciTier, Skip, ""},

		{"workflow.pinned-actions", "tag reference", func(r *snapshot.Repo) { r.Workflows[0].Content += "      - uses: actions/cache@v4\n" }, ciTier, Fail, "actions/cache@v4"},

		{"workflow.dependabot-actions", "no dependabot config", func(r *snapshot.Repo) { r.Dependabot = nil }, ciTier, Fail, "no dependabot.yml"},
		{"workflow.dependabot-actions", "no actions ecosystem", func(r *snapshot.Repo) { r.Dependabot.Content = "- package-ecosystem: pip\n" }, ciTier, Fail, "github-actions"},

		{"ruleset.check-source", "malformed parameters", func(r *snapshot.Repo) { r.Rules[3].Parameters = []byte(`{"required_status_checks":"oops"}`) }, ciTier, Unknown, "required_status_checks"},
		{"ruleset.status-checks", "malformed parameters", func(r *snapshot.Repo) { r.Rules[3].Parameters = []byte(`not json`) }, ciTier, Unknown, "required_status_checks"},

		{"workflow.stale-secrets", "stale with secrets", func(r *snapshot.Repo) { r.PushedAt = now.AddDate(-3, 0, 0) }, ciTier, Fail, "TOKEN"},
		{"workflow.stale-secrets", "no push date", func(r *snapshot.Repo) { r.PushedAt = time.Time{} }, ciTier, Unknown, "no push date"},
		{"workflow.stale-secrets", "stale without secrets", func(r *snapshot.Repo) {
			r.PushedAt = now.AddDate(-3, 0, 0)
			r.Workflows[0].Content = "permissions: {}\n"
		}, ciTier, Pass, "no secrets"},
		{"workflow.stale-secrets", "referenced secrets don't exist", func(r *snapshot.Repo) {
			r.PushedAt = now.AddDate(-3, 0, 0)
			r.Secrets = []string{}
		}, ciTier, Pass, "no such secrets exist"},
		{"workflow.stale-secrets", "only referenced secrets count", func(r *snapshot.Repo) {
			r.PushedAt = now.AddDate(-3, 0, 0)
			r.Secrets = []string{"UNRELATED"}
		}, ciTier, Pass, "no such secrets exist"},
		{"workflow.stale-secrets", "secret names are case-insensitive", func(r *snapshot.Repo) {
			r.PushedAt = now.AddDate(-3, 0, 0)
			r.Secrets = []string{"token"}
		}, ciTier, Fail, "TOKEN still exist"},
		{"workflow.stale-secrets", "secrets not collected", func(r *snapshot.Repo) {
			r.PushedAt = now.AddDate(-3, 0, 0)
			r.Secrets = nil
		}, ciTier, Unknown, "doesn't record which secrets exist"},
		{"workflow.stale-secrets", "secrets unreadable", func(r *snapshot.Repo) {
			r.PushedAt = now.AddDate(-3, 0, 0)
			r.Secrets = nil
			r.Errors = map[string]string{snapshot.FieldSecrets: "HTTP 403: Resource not accessible"}
		}, ciTier, Unknown, "HTTP 403"},
		{"workflow.stale-secrets", "recent push needs no secret lookup", func(r *snapshot.Repo) { r.Secrets = nil }, ciTier, Pass, "last push"},
	}
	for _, tt := range tests {
		t.Run(tt.check+"/"+tt.name, func(t *testing.T) {
			r := healthy()
			tt.mutate(&r)
			st, msg := byID(t, tt.check).Run(Input{Repo: r, Tier: tt.tier, Now: now, StaleDays: 365})
			if st != tt.want {
				t.Fatalf("got %s (%s), want %s", st, msg, tt.want)
			}
			if !strings.Contains(msg, tt.detail) {
				t.Errorf("message %q doesn't mention %q", msg, tt.detail)
			}
		})
	}
}

func TestEvaluateUnreadableRepoIsUnknown(t *testing.T) {
	r := snapshot.Repo{Name: "ghost", Errors: map[string]string{snapshot.FieldRepo: "HTTP 502"}}
	b := &baseline.Baseline{DefaultTier: "basic", Tiers: map[string]baseline.Tier{"basic": {}}, StaleDays: 365}
	for _, f := range Evaluate(&snapshot.Snapshot{Repos: []snapshot.Repo{r}}, b, now) {
		if f.Status != Unknown || !strings.Contains(f.Message, "HTTP 502") {
			t.Errorf("%s: got %s (%s), want unknown mentioning HTTP 502", f.Check, f.Status, f.Message)
		}
	}
}

func TestCountMessages(t *testing.T) {
	tests := []struct {
		check  string
		mutate func(*snapshot.Repo)
		want   string
	}{
		{"ruleset.status-checks", func(r *snapshot.Repo) {}, "1 status check required"},
		{"ruleset.status-checks", func(r *snapshot.Repo) { r.Rules[3] = checksRule(ptr(int64(1)), ptr(int64(2))) }, "2 status checks required"},
		{"ruleset.check-source", func(r *snapshot.Repo) {}, "the required check is pinned to a source"},
		{"ruleset.check-source", func(r *snapshot.Repo) { r.Rules[3] = checksRule(ptr(int64(1)), ptr(int64(2))) }, "all 2 required checks are pinned to a source"},
		{"workflow.stale-secrets", func(r *snapshot.Repo) { r.PushedAt = now.AddDate(0, 0, -1) }, "last push 1 day ago"},
		{"workflow.stale-secrets", func(r *snapshot.Repo) { r.PushedAt = now.AddDate(0, 0, -3) }, "last push 3 days ago"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			r := healthy()
			tt.mutate(&r)
			if _, msg := byID(t, tt.check).Run(Input{Repo: r, Tier: ciTier, Now: now, StaleDays: 365}); msg != tt.want {
				t.Errorf("%s message = %q, want %q", tt.check, msg, tt.want)
			}
		})
	}
}

func TestEvaluateUsesTierAndAddsRemediation(t *testing.T) {
	bare := healthy()
	bare.Name = "Scratch"
	bare.Rules = []snapshot.Rule{rule("deletion", nil), rule("non_fast_forward", nil)}

	b := &baseline.Baseline{
		DefaultTier: "basic",
		Tiers:       map[string]baseline.Tier{"basic": {}, "ci": ciTier},
		Repos:       map[string]string{"good": "ci"},
		StaleDays:   365,
	}
	fs := Evaluate(&snapshot.Snapshot{Repos: []snapshot.Repo{healthy(), bare}}, b, now)

	if len(fs) != 2*len(catalog) {
		t.Fatalf("got %d findings, want %d", len(fs), 2*len(catalog))
	}
	for _, f := range fs {
		if f.Status == Fail || f.Status == Unknown {
			t.Errorf("%s %s: unexpected %s: %s", f.Repo, f.Check, f.Status, f.Message)
		}
		if f.Repo == "Scratch" && f.Tier != "basic" {
			t.Errorf("Scratch got tier %q, want basic", f.Tier)
		}
		if f.Remediation != "" {
			t.Errorf("%s %s: remediation set on a %s", f.Repo, f.Check, f.Status)
		}
	}

	bare.Security["secret_scanning"] = "disabled"
	fs = Evaluate(&snapshot.Snapshot{Repos: []snapshot.Repo{bare}}, b, now)
	for _, f := range fs {
		if f.Check == "security.secret-scanning" && (f.Status != Fail || f.Remediation == "") {
			t.Errorf("want a failure with remediation, got %+v", f)
		}
	}
}
