// Package workflowparse extracts domain facts from GitHub Actions workflow YAML.
// The parsed Evidence structs are stored in the snapshot and consumed by checks,
// which never need to parse raw YAML themselves.
package workflowparse

import (
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Evidence is the parsed domain facts from one workflow file.
type Evidence struct {
	Triggers    []string     `json:"triggers,omitempty"`
	Permissions *Permissions `json:"permissions,omitempty"` // nil when not declared
	Actions     []ActionRef  `json:"actions,omitempty"`
	Secrets     []SecretRef  `json:"secrets,omitempty"`
}

// Permissions is the top-level permissions block. A nil pointer means the key
// was not declared. A non-nil value with empty Scopes means permissions: {} or
// a shorthand that wasn't a named scope map.
type Permissions struct {
	WriteAll bool              `json:"writeAll,omitempty"`
	ReadAll  bool              `json:"readAll,omitempty"`
	Scopes   map[string]string `json:"scopes,omitempty"` // scope → "read", "write", or "none"
}

// ActionKind classifies a uses: reference.
type ActionKind string

const (
	ActionKindRemote   ActionKind = "remote"   // owner/repo@ref (action)
	ActionKindReusable ActionKind = "reusable" // owner/repo/.github/workflows/...@ref
	ActionKindLocal    ActionKind = "local"    // ./path
	ActionKindDocker   ActionKind = "docker"   // docker://image
)

// ActionRef is one uses: reference found in a workflow job or step.
type ActionRef struct {
	Kind   ActionKind `json:"kind"`
	Ref    string     `json:"ref"`             // the full uses: value
	Owner  string     `json:"owner,omitempty"` // set for remote and reusable
	Repo   string     `json:"repo,omitempty"`  // set for remote and reusable
	Pinned bool       `json:"pinned"`
}

// SecretRef is one secret reference found in a workflow.
type SecretRef struct {
	Name      string `json:"name"`
	Inherited bool   `json:"inherited,omitempty"` // true when a job uses `secrets: inherit`
}

var (
	secretRef = regexp.MustCompile(`\$\{\{[^}]*\bsecrets(?:\.([A-Za-z0-9_]+)|\[['"]([A-Za-z0-9_]+)['"])`)
	fullSHA   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Parse extracts Evidence from raw workflow YAML content. It never returns an
// error; malformed content produces empty evidence.
func Parse(content string) Evidence {
	return Evidence{
		Triggers:    parseTriggers(content),
		Permissions: parsePermissions(content),
		Actions:     parseActions(content),
		Secrets:     parseSecrets(content),
	}
}

// HasAutomaticTrigger reports whether any trigger can fire without a human push
// (schedule or repository_dispatch).
func HasAutomaticTrigger(e Evidence) bool {
	for _, t := range e.Triggers {
		if t == "schedule" || t == "repository_dispatch" {
			return true
		}
	}
	return false
}

// parseTriggers returns the event names from the on: block.
func parseTriggers(content string) []string {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}
	switch v := doc["on"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, t := range v {
			if s, ok := t.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(v))
		for k := range v {
			out = append(out, k)
		}
		return out
	}
	return nil
}

// parsePermissions returns a Permissions pointer if the top-level permissions
// key is present, nil otherwise.
func parsePermissions(content string) *Permissions {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}
	raw, ok := doc["permissions"]
	if !ok {
		return nil
	}
	p := &Permissions{}
	switch v := raw.(type) {
	case string:
		switch v {
		case "write-all":
			p.WriteAll = true
		case "read-all":
			p.ReadAll = true
		}
	case map[string]any:
		p.Scopes = make(map[string]string, len(v))
		for scope, perm := range v {
			if s, ok := perm.(string); ok {
				p.Scopes[scope] = s
			}
		}
	}
	return p
}

type wfDoc struct {
	Jobs map[string]wfJob `yaml:"jobs"`
}

type wfJob struct {
	Uses    string `yaml:"uses"`
	Secrets any    `yaml:"secrets"`
	Steps   []struct {
		Uses string `yaml:"uses"`
	} `yaml:"steps"`
}

// parseActions returns every uses: reference found in jobs and steps.
// Jobs are iterated in sorted name order for deterministic output.
func parseActions(content string) []ActionRef {
	var doc wfDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Jobs))
	for name := range doc.Jobs {
		names = append(names, name)
	}
	slices.Sort(names)

	var out []ActionRef
	for _, name := range names {
		job := doc.Jobs[name]
		if ref := job.Uses; ref != "" {
			out = append(out, classifyRef(ref))
		}
		for _, step := range job.Steps {
			if ref := step.Uses; ref != "" {
				out = append(out, classifyRef(ref))
			}
		}
	}
	return out
}

// classifyRef classifies a uses: value and returns an ActionRef.
func classifyRef(ref string) ActionRef {
	switch {
	case strings.HasPrefix(ref, "./"):
		return ActionRef{Kind: ActionKindLocal, Ref: ref, Pinned: true}
	case strings.HasPrefix(ref, "docker://"):
		return ActionRef{
			Kind:   ActionKindDocker,
			Ref:    ref,
			Pinned: strings.Contains(ref, "@sha256:"),
		}
	default:
		// Remote action or reusable workflow.
		at := strings.LastIndex(ref, "@")
		pinned := at >= 0 && fullSHA.MatchString(ref[at+1:])
		owner, repo := ownerRepo(ref)
		kind := ActionKindRemote
		path := ref
		if at >= 0 {
			path = ref[:at]
		}
		if strings.Contains(path, "/.github/workflows/") {
			kind = ActionKindReusable
		}
		return ActionRef{Kind: kind, Ref: ref, Owner: owner, Repo: repo, Pinned: pinned}
	}
}

// ownerRepo extracts the owner and repo name from a remote action reference.
func ownerRepo(ref string) (owner, repo string) {
	// Drop the @ref suffix first.
	path := ref
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		path = ref[:at]
	}
	parts := strings.SplitN(path, "/", 3)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

// parseSecrets extracts secret references from raw workflow content. It
// returns both named secret references (${{ secrets.NAME }}) and an
// inheritance sentinel (secrets: inherit) for each job that uses it.
func parseSecrets(content string) []SecretRef {
	seen := map[string]bool{}
	var out []SecretRef

	// Named secret references via expression syntax.
	for _, m := range secretRef.FindAllStringSubmatch(content, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if name == "GITHUB_TOKEN" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, SecretRef{Name: name})
	}

	// secrets: inherit at the job level.
	var doc wfDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return out
	}
	for _, job := range doc.Jobs {
		if s, ok := job.Secrets.(string); ok && s == "inherit" {
			// Add a single inherit sentinel (deduplicated).
			if !seen[""] {
				seen[""] = true
				out = append(out, SecretRef{Inherited: true})
			}
			break
		}
	}
	return out
}
