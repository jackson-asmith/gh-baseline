package collect

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	if r.Errors != nil {
		t.Errorf("unexpected errors: %v", r.Errors)
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
