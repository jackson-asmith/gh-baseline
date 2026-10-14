package collect

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackson-asmith/gh-baseline/internal/ghapi"
	"github.com/jackson-asmith/gh-baseline/internal/snapshot"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// fakeAPI serves a small account: one healthy repo, one fork, one archived
// repo, and one repo whose vulnerability-reporting endpoint is forbidden.
func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	repo := func(name string, extra string) string {
		return fmt.Sprintf(`{"name":%q,"default_branch":"main","pushed_at":"2026-10-01T00:00:00Z",
			"security_and_analysis":{"secret_scanning":{"status":"enabled"}}%s}`, name, extra)
	}
	routes := map[string]string{
		"/user": `{"login":"me"}`,
		// The token's own account is listed from /user/repos; /users/me/repos
		// would only return public repositories.
		"/user/repos": "[" + repo("app", `,"private":true`) + "," + repo("forked", `,"fork":true`) + "," +
			repo("old", `,"archived":true`) + "]",
		"/users/me/repos": "[]",
		"/repos/me/app":   repo("app", ""),
		"/repos/me/app/private-vulnerability-reporting":   `{"enabled":true}`,
		"/repos/me/app/rules/branches/main":               `[{"type":"deletion"},{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"test","integration_id":15368}]}}]`,
		"/repos/me/app/contents/.github/workflows":        `[{"path":".github/workflows/ci.yml","type":"file"},{"path":".github/workflows/README.md","type":"file"}]`,
		"/repos/me/app/contents/.github/workflows/ci.yml": `{"encoding":"base64","content":"` + b64("permissions: {}\n") + `"}`,
		"/repos/me/app/contents/.github/dependabot.yaml":  `{"encoding":"base64","content":"` + b64("version: 2\n") + `"}`,
		"/repos/me/app/actions/secrets":                   `{"total_count":1,"secrets":[{"name":"DEPLOY_KEY"}]}`,
		"/repos/me/app/environments":                      `{"total_count":1,"environments":[{"name":"prod"}]}`,
		"/repos/me/app/environments/prod/secrets":         `{"total_count":1,"secrets":[{"name":"API_KEY"}]}`,
		"/repos/me/forked":                                repo("forked", `,"fork":true`),
		"/repos/me/forked/rules/branches/main":            `[]`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path == "/repos/me/forked/private-vulnerability-reporting" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"Resource not accessible"}`)
			return
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Not Found"}`)
			return
		}
		fmt.Fprint(w, body)
	}))
}

func newCollector(srv *httptest.Server) *Collector {
	return &Collector{API: &ghapi.Client{BaseURL: srv.URL, Token: "test-token", HTTP: srv.Client()}}
}

func TestCollectListsAndFilters(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()

	snap, err := newCollector(srv).Collect(context.Background(), Options{Owner: "me"})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Repos) != 1 || snap.Repos[0].Name != "app" {
		t.Fatalf("want only app (forks excluded, archived skipped), got %+v", snap.Repos)
	}

	r := snap.Repos[0]
	if r.Security["secret_scanning"] != "enabled" {
		t.Errorf("security = %v", r.Security)
	}
	if r.VulnReporting == nil || !*r.VulnReporting {
		t.Errorf("vulnReporting = %v", r.VulnReporting)
	}
	checks, err := r.RequiredChecks()
	if err != nil || !r.HasRule("deletion") || len(checks) != 1 || *checks[0].IntegrationID != 15368 {
		t.Errorf("rules = %+v", r.Rules)
	}
	if len(r.Workflows) != 1 || r.Workflows[0].Content != "permissions: {}\n" {
		t.Errorf("workflows = %+v (non-YAML files should be ignored)", r.Workflows)
	}
	if r.Dependabot == nil || r.Dependabot.Path != ".github/dependabot.yaml" {
		t.Errorf("dependabot = %+v (should fall back to .yaml)", r.Dependabot)
	}
	if want := []string{"API_KEY", "DEPLOY_KEY"}; !slices.Equal(r.Secrets, want) {
		t.Errorf("secrets = %q, want %q (repository and environment)", r.Secrets, want)
	}
	if r.Errors != nil {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
}

func TestCollectSecrets(t *testing.T) {
	tests := []struct {
		name      string
		ownerType string
		orgStatus int // response from the organization-secrets endpoint
		want      []string
		wantErr   string // substring of Errors["secrets"], or "" for none
		wantOrg   bool   // whether the organization endpoint should be asked
	}{
		{"user repository never asks for organization secrets", "User", http.StatusUnprocessableEntity, []string{"REPO_SECRET"}, "", false},
		{"organization secrets shared with the repository", "Organization", http.StatusOK, []string{"ORG_SECRET", "REPO_SECRET"}, "", true},
		{"unreadable secrets are recorded", "Organization", http.StatusForbidden, nil, "organization secrets: HTTP 403", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			askedOrg := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/repos/acme/app":
					fmt.Fprintf(w, `{"name":"app","default_branch":"main","owner":{"type":%q}}`, tt.ownerType)
				case "/repos/acme/app/contents/.github/workflows":
					fmt.Fprint(w, `[{"path":".github/workflows/ci.yml","type":"file"}]`)
				case "/repos/acme/app/contents/.github/workflows/ci.yml":
					fmt.Fprint(w, `{"encoding":"base64","content":"`+b64("on: push\n")+`"}`)
				case "/repos/acme/app/actions/secrets":
					fmt.Fprint(w, `{"secrets":[{"name":"REPO_SECRET"}]}`)
				case "/repos/acme/app/environments":
					fmt.Fprint(w, `{"environments":[]}`)
				case "/repos/acme/app/actions/organization-secrets":
					askedOrg = true
					w.WriteHeader(tt.orgStatus)
					fmt.Fprint(w, `{"message":"canned","secrets":[{"name":"ORG_SECRET"}]}`)
				case "/repos/acme/app/rules/branches/main":
					fmt.Fprint(w, `[]`)
				default:
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprint(w, `{"message":"Not Found"}`)
				}
			}))
			defer srv.Close()

			snap, err := newCollector(srv).Collect(context.Background(), Options{Owner: "acme", Repos: []string{"app"}})
			if err != nil {
				t.Fatal(err)
			}
			r := snap.Repos[0]
			if !slices.Equal(r.Secrets, tt.want) {
				t.Errorf("secrets = %q, want %q", r.Secrets, tt.want)
			}
			if got := r.Errors[snapshot.FieldSecrets]; !strings.Contains(got, tt.wantErr) || (tt.wantErr == "" && got != "") {
				t.Errorf("secrets error = %q, want %q", got, tt.wantErr)
			}
			if askedOrg != tt.wantOrg {
				t.Errorf("asked for organization secrets = %v, want %v", askedOrg, tt.wantOrg)
			}
		})
	}
}

func TestCollectRecordsUnreadableFields(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()

	snap, err := newCollector(srv).Collect(context.Background(), Options{
		Owner: "me", Repos: []string{"forked", "app"}, Exclude: []string{"APP"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Repos) != 1 {
		t.Fatalf("exclude is case-insensitive: got %d repos", len(snap.Repos))
	}
	r := snap.Repos[0]
	if !strings.Contains(r.Errors[snapshot.FieldVulnReporting], "403") {
		t.Errorf("want a recorded 403, got errors %v", r.Errors)
	}
	if len(r.Workflows) != 0 || r.Errors[snapshot.FieldWorkflows] != "" {
		t.Errorf("a missing workflows dir means no workflows, not an error: %+v %v", r.Workflows, r.Errors)
	}
	if r.Secrets != nil || r.Errors[snapshot.FieldSecrets] != "" {
		t.Errorf("a repository without workflows shouldn't be asked for secrets: %q %v", r.Secrets, r.Errors)
	}
}

func TestCollectRecordsMissingRepoAndContinues(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()

	snap, err := newCollector(srv).Collect(context.Background(), Options{Owner: "me", Repos: []string{"ghost", "app"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Repos) != 2 {
		t.Fatalf("want ghost and app, got %+v", snap.Repos)
	}
	if ghost := snap.Repos[0]; ghost.Name != "ghost" || !strings.Contains(ghost.Errors[snapshot.FieldRepo], "404") {
		t.Errorf("ghost = %+v, want a recorded 404", ghost)
	}
	if app := snap.Repos[1]; app.Errors != nil {
		t.Errorf("app errors = %v, want none", app.Errors)
	}
}

func TestCollectStopsWhenContextEnds(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newCollector(srv).Collect(ctx, Options{Owner: "me", Repos: []string{"app"}}); err == nil {
		t.Error("Collect(cancelled ctx) = nil error, want failure")
	}
}

func TestListReposEndpointByAccount(t *testing.T) {
	tests := []struct {
		owner, want string
	}{
		{"me", "/user/repos"},
		{"ME", "/user/repos"},
		{"acme", "/orgs/acme/repos"},
		{"someone", "/users/someone/repos"},
	}
	for _, tt := range tests {
		t.Run(tt.owner, func(t *testing.T) {
			var listed string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/user":
					fmt.Fprint(w, `{"login":"me"}`)
				case "/users/acme":
					fmt.Fprint(w, `{"type":"Organization"}`)
				case "/users/someone":
					fmt.Fprint(w, `{"type":"User"}`)
				default:
					listed = r.URL.Path
					fmt.Fprint(w, `[]`)
				}
			}))
			defer srv.Close()

			if _, err := newCollector(srv).Collect(context.Background(), Options{Owner: tt.owner}); err != nil {
				t.Fatal(err)
			}
			if listed != tt.want {
				t.Errorf("Collect(owner %q) listed %q, want %q", tt.owner, listed, tt.want)
			}
		})
	}
}

func TestCollectStopsOnRateLimit(t *testing.T) {
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/me/app":
			fmt.Fprint(w, `{"name":"app","default_branch":"main"}`)
		case "/repos/me/app/private-vulnerability-reporting":
			fmt.Fprint(w, `{"enabled":true}`)
		default: // the budget runs out partway through the repo
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", reset)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
		}
	}))
	defer srv.Close()

	_, err := newCollector(srv).Collect(context.Background(), Options{Owner: "me", Repos: []string{"app"}})
	if !ghapi.IsRateLimited(err) {
		t.Errorf("Collect() error = %v, want a rate limit error, not a recorded field error", err)
	}
}

func TestCollectClassifiesPlanLimitedRulesets(t *testing.T) {
	// Responses and where they came from (see docs/adr/0002):
	//   upgrade: observed 2026-10-13, branch rules on a private repo on a free plan.
	//   404:     observed 2026-10-13, a fine-grained token without access to the
	//            private repo. GitHub hides the repo; it does not answer 403.
	//   saml:    GitHub's general message for organization SAML enforcement; not
	//            observed on this endpoint, kept as an example of another 403.
	const (
		upgrade = "Upgrade to GitHub Pro or make this repository public to enable this feature."
		saml    = "Resource protected by organization SAML enforcement. You must grant your Personal Access token access to this organization."
	)
	tests := []struct {
		name        string
		private     bool
		status      int
		message     string
		unavailable bool
		recorded    string // substring expected in Errors["rules"], or "" for none
	}{
		{"private repo on a free plan", true, http.StatusForbidden, upgrade, true, ""},
		{"private repo, token without access", true, http.StatusNotFound, "Not Found", false, "404"},
		{"private repo, another 403", true, http.StatusForbidden, saml, false, "SAML"},
		{"public repo is never plan-limited", false, http.StatusForbidden, upgrade, false, "Upgrade"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/repos/me/app":
					fmt.Fprintf(w, `{"name":"app","default_branch":"main","private":%t}`, tt.private)
				case "/repos/me/app/rules/branches/main":
					w.WriteHeader(tt.status)
					fmt.Fprintf(w, `{"message":%q}`, tt.message)
				default:
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprint(w, `{"message":"Not Found"}`)
				}
			}))
			defer srv.Close()

			snap, err := newCollector(srv).Collect(context.Background(), Options{Owner: "me", Repos: []string{"app"}})
			if err != nil {
				t.Fatal(err)
			}
			r := snap.Repos[0]
			if r.RulesetsUnavailable != tt.unavailable {
				t.Errorf("RulesetsUnavailable = %t, want %t", r.RulesetsUnavailable, tt.unavailable)
			}
			got := r.Errors[snapshot.FieldRules]
			if (tt.recorded == "") != (got == "") || !strings.Contains(got, tt.recorded) {
				t.Errorf("Errors[rules] = %q, want it to contain %q", got, tt.recorded)
			}
		})
	}
}
