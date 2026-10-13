// Package collect reads repository state from the GitHub API into a snapshot.
package collect

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackson-asmith/gh-baseline/internal/ghapi"
	"github.com/jackson-asmith/gh-baseline/internal/snapshot"
)

// Options controls which repositories are collected.
type Options struct {
	Owner        string
	Repos        []string // explicit list; empty means every repo the owner has
	IncludeForks bool
	Exclude      []string
}

// Collector gathers snapshots.
type Collector struct {
	API *ghapi.Client
}

type apiRepo struct {
	Name          string    `json:"name"`
	DefaultBranch string    `json:"default_branch"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	PushedAt      time.Time `json:"pushed_at"`
	Security      map[string]struct {
		Status string `json:"status"`
	} `json:"security_and_analysis"`
}

// Collect builds a snapshot for the requested repositories.
func (c *Collector) Collect(ctx context.Context, opt Options) (*snapshot.Snapshot, error) {
	names := opt.Repos
	if len(names) == 0 {
		listed, err := c.listRepos(ctx, opt)
		if err != nil {
			return nil, fmt.Errorf("list repositories for %s: %w", opt.Owner, err)
		}
		names = listed
	}
	skip := map[string]bool{}
	for _, e := range opt.Exclude {
		skip[strings.ToLower(e)] = true
	}

	snap := &snapshot.Snapshot{GeneratedAt: time.Now().UTC(), Host: c.API.Host, Owner: opt.Owner}
	for _, name := range names {
		if skip[strings.ToLower(name)] {
			continue
		}
		r, err := c.repo(ctx, opt.Owner, name)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", opt.Owner, name, err)
		}
		snap.Repos = append(snap.Repos, r)
	}
	return snap, nil
}

func (c *Collector) listRepos(ctx context.Context, opt Options) ([]string, error) {
	next, err := c.reposPath(ctx, opt.Owner)
	if err != nil {
		return nil, err
	}
	var names []string
	for next != "" {
		var page []apiRepo
		n, err := c.API.Get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		for _, r := range page {
			if r.Archived || (r.Fork && !opt.IncludeForks) {
				continue
			}
			names = append(names, r.Name)
		}
		next = n
	}
	return names, nil
}

// reposPath picks the listing endpoint for owner. /users/{owner}/repos returns
// only public repositories, even for the token's own account, so the
// authenticated user and organizations need their own endpoints.
func (c *Collector) reposPath(ctx context.Context, owner string) (string, error) {
	var me struct {
		Login string `json:"login"`
	}
	if _, err := c.API.Get(ctx, "user", &me); err != nil {
		return "", fmt.Errorf("identify the token's user: %w", err)
	}
	if strings.EqualFold(me.Login, owner) {
		return "user/repos?affiliation=owner&per_page=100", nil
	}
	var account struct {
		Type string `json:"type"`
	}
	if _, err := c.API.Get(ctx, "users/"+url.PathEscape(owner), &account); err != nil {
		return "", err
	}
	if account.Type == "Organization" {
		return fmt.Sprintf("orgs/%s/repos?type=all&per_page=100", url.PathEscape(owner)), nil
	}
	// Another user's private repositories aren't listable by anyone else.
	return fmt.Sprintf("users/%s/repos?type=owner&per_page=100", url.PathEscape(owner)), nil
}

func (c *Collector) repo(ctx context.Context, owner, name string) (snapshot.Repo, error) {
	base := fmt.Sprintf("repos/%s/%s", url.PathEscape(owner), url.PathEscape(name))

	var ar apiRepo
	if _, err := c.API.Get(ctx, base, &ar); err != nil {
		return snapshot.Repo{}, err // without the repo itself there is nothing to check
	}
	r := snapshot.Repo{
		Name:          ar.Name,
		DefaultBranch: ar.DefaultBranch,
		Private:       ar.Private,
		Fork:          ar.Fork,
		Archived:      ar.Archived,
		PushedAt:      ar.PushedAt,
		Errors:        map[string]string{},
	}
	if ar.Security != nil {
		r.Security = map[string]string{}
		for k, v := range ar.Security {
			r.Security[k] = v.Status
		}
	} else {
		r.Errors[snapshot.FieldSecurity] = "security_and_analysis not returned (token may lack admin access)"
	}

	var pvr struct {
		Enabled bool `json:"enabled"`
	}
	if _, err := c.API.Get(ctx, base+"/private-vulnerability-reporting", &pvr); err != nil {
		r.Errors[snapshot.FieldVulnReporting] = err.Error()
	} else {
		r.VulnReporting = &pvr.Enabled
	}

	rules, err := c.rules(ctx, base+"/rules/branches/"+url.PathEscape(ar.DefaultBranch))
	if err != nil {
		r.Errors[snapshot.FieldRules] = err.Error()
	}
	r.Rules = rules

	wf, err := c.workflows(ctx, base)
	if err != nil {
		r.Errors[snapshot.FieldWorkflows] = err.Error()
	}
	r.Workflows = wf

	for _, p := range []string{".github/dependabot.yml", ".github/dependabot.yaml"} {
		f, err := c.file(ctx, base, p)
		if err == nil {
			r.Dependabot = f
			break
		}
		if !ghapi.IsNotFound(err) {
			r.Errors[snapshot.FieldDependabot] = err.Error()
			break
		}
	}

	if len(r.Errors) == 0 {
		r.Errors = nil
	}
	return r, nil
}

func (c *Collector) rules(ctx context.Context, path string) ([]snapshot.Rule, error) {
	out := []snapshot.Rule{}
	next := path + "?per_page=100"
	for next != "" {
		var page []snapshot.Rule
		n, err := c.API.Get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		next = n
	}
	return out, nil
}

func (c *Collector) workflows(ctx context.Context, base string) ([]snapshot.File, error) {
	var entries []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}
	if _, err := c.API.Get(ctx, base+"/contents/.github/workflows", &entries); err != nil {
		if ghapi.IsNotFound(err) {
			return []snapshot.File{}, nil
		}
		return nil, err
	}
	out := []snapshot.File{}
	for _, e := range entries {
		if e.Type != "file" || !(strings.HasSuffix(e.Path, ".yml") || strings.HasSuffix(e.Path, ".yaml")) {
			continue
		}
		f, err := c.file(ctx, base, e.Path)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, nil
}

func (c *Collector) file(ctx context.Context, base, path string) (*snapshot.File, error) {
	var f struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if _, err := c.API.Get(ctx, base+"/contents/"+escapePath(path), &f); err != nil {
		return nil, err
	}
	if f.Encoding != "base64" {
		return nil, fmt.Errorf("%s: unexpected encoding %q", path, f.Encoding)
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &snapshot.File{Path: path, Content: string(b)}, nil
}

// escapePath escapes each segment of a slash-separated repository path.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
