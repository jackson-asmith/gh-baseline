package check

import (
	"regexp"
	"strings"
)

// Workflow parsing is deliberately line-based: it understands conventionally
// formatted YAML (top-level keys at column 0, one `uses:` per line). A YAML
// parser is the upgrade path if this proves too loose.

var (
	topLevelPermissions = regexp.MustCompile(`(?m)^permissions\s*:`)
	usesLine            = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses\s*:\s*["']?([^\s"'#]+)`)
	secretRef           = regexp.MustCompile(`\$\{\{[^}]*\bsecrets\.([A-Za-z0-9_]+)`)
	fullSHA             = regexp.MustCompile(`^[0-9a-f]{40}$`)
	dependabotActions   = regexp.MustCompile(`package-ecosystem\s*:\s*["']?github-actions\b`)
)

func hasTopLevelPermissions(content string) bool {
	return topLevelPermissions.MatchString(content)
}

// unpinnedUses returns every `uses:` reference that isn't pinned to an
// immutable version: a full commit SHA for actions and reusable workflows, a
// digest for Docker images. Local references (./...) are always fine.
func unpinnedUses(content string) []string {
	var out []string
	for _, m := range usesLine.FindAllStringSubmatch(content, -1) {
		ref := m[1]
		switch {
		case strings.HasPrefix(ref, "./"):
			continue
		case strings.HasPrefix(ref, "docker://"):
			if !strings.Contains(ref, "@sha256:") {
				out = append(out, ref)
			}
		default:
			at := strings.LastIndex(ref, "@")
			if at < 0 || !fullSHA.MatchString(ref[at+1:]) {
				out = append(out, ref)
			}
		}
	}
	return out
}

// secretsUsed returns the names of repository secrets a workflow references,
// excluding the automatic GITHUB_TOKEN.
func secretsUsed(content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range secretRef.FindAllStringSubmatch(content, -1) {
		name := m[1]
		if name == "GITHUB_TOKEN" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}
