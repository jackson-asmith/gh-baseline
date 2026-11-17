package check

import "gopkg.in/yaml.v3"

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
