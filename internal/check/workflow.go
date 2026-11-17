package check

import (
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// hasTopLevelPermissions and unpinnedUses use gopkg.in/yaml.v3 so that block
// scalars, flow-style mappings, and anchors are handled correctly.
// secretsUsed searches for ${{ secrets.X }} template expressions inside string
// values; a YAML parser doesn't improve that, so it stays regex-based.
// See docs/adr/0004-yaml-parser-for-workflows.md.

var (
	// secretRef matches both ${{ secrets.NAME }} and ${{ secrets['NAME'] }} / ${{ secrets["NAME"] }}.
	secretRef = regexp.MustCompile(`\$\{\{[^}]*\bsecrets(?:\.([A-Za-z0-9_]+)|\[['"]([A-Za-z0-9_]+)['"])`)
	fullSHA   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func hasTopLevelPermissions(content string) bool {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return false
	}
	_, ok := doc["permissions"]
	return ok
}

type workflowDoc struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Uses    string         `yaml:"uses"`
	Secrets any            `yaml:"secrets"`
	Steps   []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Uses string `yaml:"uses"`
}

// unpinnedUses returns every `uses:` reference that isn't pinned to an
// immutable version: a full commit SHA for actions and reusable workflows, a
// digest for Docker images. Local references (./...) are always fine.
// Jobs are iterated in sorted name order for deterministic output.
func unpinnedUses(content string) []string {
	var doc workflowDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Jobs))
	for name := range doc.Jobs {
		names = append(names, name)
	}
	slices.Sort(names)

	var out []string
	for _, name := range names {
		job := doc.Jobs[name]
		if ref := job.Uses; ref != "" && !pinned(ref) {
			out = append(out, ref)
		}
		for _, step := range job.Steps {
			if ref := step.Uses; ref != "" && !pinned(ref) {
				out = append(out, ref)
			}
		}
	}
	return out
}

func pinned(ref string) bool {
	switch {
	case strings.HasPrefix(ref, "./"):
		return true
	case strings.HasPrefix(ref, "docker://"):
		return strings.Contains(ref, "@sha256:")
	default:
		at := strings.LastIndex(ref, "@")
		return at >= 0 && fullSHA.MatchString(ref[at+1:])
	}
}

// secretsUsed returns the names of repository secrets a workflow references,
// excluding the automatic GITHUB_TOKEN. Matches both dot notation
// (${{ secrets.NAME }}) and bracket notation (${{ secrets['NAME'] }}).
func secretsUsed(content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range secretRef.FindAllStringSubmatch(content, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if name == "GITHUB_TOKEN" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// secretsInherit reports whether any job in the workflow passes all secrets to
// a reusable workflow via `secrets: inherit`.
func secretsInherit(content string) bool {
	var doc workflowDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return false
	}
	for _, job := range doc.Jobs {
		if s, ok := job.Secrets.(string); ok && s == "inherit" {
			return true
		}
	}
	return false
}

// dependabotCoversActions reports whether dependabot.yml has a github-actions
// entry in its updates list. Parses the YAML to avoid false positives from
// comments that contain the string.
func dependabotCoversActions(content string) bool {
	var doc struct {
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return false
	}
	for _, u := range doc.Updates {
		if u.Ecosystem == "github-actions" {
			return true
		}
	}
	return false
}
