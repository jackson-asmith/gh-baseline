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
	for _, c := range Catalog {
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
		b, _ := json.Marshal(params)
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
	}
}

var ciTier = baseline.Tier{RequirePullRequest: true, RequireStatusChecks: true}

func TestHealthyRepoPassesEverything(t *testing.T) {
	in := Input{Repo: healthy(), Tier: ciTier, Now: now, StaleDays: 365}
	for _, c := range Catalog {
		if st, msg := c.Run(in); st != Pass {
			t.Errorf("%s: got %s (%s), want pass", c.ID, st, msg)
		}
	}
}

func TestChecks(t *testing.T) {
	tests := []struct {
		check  string
		mutate func(*snapshot.Repo)
		tier   baseline.Tier
		want   Status
		detail string // substring expected in the message
	}{
		{"ruleset.branch-safety", func(r *snapshot.Repo) { r.Rules = nil }, ciTier, Fail, "deletion and force push"},
		{"ruleset.branch-safety", func(r *snapshot.Repo) { r.Rules = r.Rules[:1] }, ciTier, Fail, "force push"},
		{"ruleset.branch-safety", func(r *snapshot.Repo) { r.Errors = map[string]string{"rules": "HTTP 403"} }, ciTier, Unknown, "HTTP 403"},

		{"ruleset.pull-request", func(r *snapshot.Repo) { r.Rules = r.Rules[:2] }, ciTier, Fail, "without a pull request"},
		{"ruleset.pull-request", func(r *snapshot.Repo) { r.Rules = nil }, baseline.Tier{}, Skip, ""},

		{"ruleset.status-checks", func(r *snapshot.Repo) { r.Rules = r.Rules[:3] }, ciTier, Fail, "no status checks"},
		{"ruleset.status-checks", func(r *snapshot.Repo) { r.Rules = nil }, baseline.Tier{RequirePullRequest: true}, Skip, ""},

		{"ruleset.check-source", func(r *snapshot.Repo) { r.Rules[3] = checksRule(ptr(int64(15368)), nil) }, ciTier, Fail, "jobB"},
		{"ruleset.check-source", func(r *snapshot.Repo) { r.Rules = r.Rules[:3] }, ciTier, Skip, ""},

		{"security.secret-scanning", func(r *snapshot.Repo) { r.Security["secret_scanning"] = "disabled" }, ciTier, Fail, "off"},
		{"security.secret-scanning", func(r *snapshot.Repo) { r.Private = true }, ciTier, Skip, "private"},
		{"security.secret-scanning", func(r *snapshot.Repo) { r.Security = nil; r.Errors = map[string]string{"security": "x"} }, ciTier, Unknown, ""},
		{"security.push-protection", func(r *snapshot.Repo) { delete(r.Security, "secret_scanning_push_protection") }, ciTier, Unknown, "not returned"},

		{"security.vuln-reporting", func(r *snapshot.Repo) { r.VulnReporting = ptr(false) }, ciTier, Fail, "off"},

		{"workflow.token-permissions", func(r *snapshot.Repo) { r.Workflows[0].Content = "jobs: {}\n" }, ciTier, Fail, "ci.yml"},
		{"workflow.token-permissions", func(r *snapshot.Repo) { r.Workflows = nil }, ciTier, Skip, ""},

		{"workflow.pinned-actions", func(r *snapshot.Repo) { r.Workflows[0].Content += "      - uses: actions/cache@v4\n" }, ciTier, Fail, "actions/cache@v4"},

		{"workflow.dependabot-actions", func(r *snapshot.Repo) { r.Dependabot = nil }, ciTier, Fail, "no dependabot.yml"},
		{"workflow.dependabot-actions", func(r *snapshot.Repo) { r.Dependabot.Content = "- package-ecosystem: pip\n" }, ciTier, Fail, "github-actions"},

		{"workflow.stale-secrets", func(r *snapshot.Repo) { r.PushedAt = now.AddDate(-3, 0, 0) }, ciTier, Fail, "TOKEN"},
		{"workflow.stale-secrets", func(r *snapshot.Repo) {
			r.PushedAt = now.AddDate(-3, 0, 0)
			r.Workflows[0].Content = "permissions: {}\n"
		}, ciTier, Pass, "no secrets"},
	}
	for _, tt := range tests {
		t.Run(tt.check+"/"+string(tt.want), func(t *testing.T) {
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

	if len(fs) != 2*len(Catalog) {
		t.Fatalf("got %d findings, want %d", len(fs), 2*len(Catalog))
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
