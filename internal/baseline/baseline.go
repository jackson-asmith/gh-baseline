// Package baseline loads the declared configuration repositories are checked
// against.
package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Tier is a level of protection a repository is expected to have. Every tier
// requires the default branch to block deletion and force pushes.
type Tier struct {
	RequirePullRequest  bool `json:"requirePullRequest"`
	RequireStatusChecks bool `json:"requireStatusChecks"`
}

// Baseline is the declared configuration.
type Baseline struct {
	Owner        string            `json:"owner"`
	DefaultTier  string            `json:"defaultTier"`
	Tiers        map[string]Tier   `json:"tiers"`
	Repos        map[string]string `json:"repos"`
	Exclude      []string          `json:"exclude"`
	IncludeForks bool              `json:"includeForks"`
	StaleDays    int               `json:"staleDays"`
}

// Default is used when no baseline file is given: every repo gets branch
// safety and the security checks, with no PR or status-check requirement.
func Default() *Baseline {
	return &Baseline{
		DefaultTier:  "basic",
		Tiers:        map[string]Tier{"basic": {}},
		IncludeForks: true,
		StaleDays:    365,
	}
}

// Load reads and validates a baseline file.
func Load(path string) (*Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b := Default()
	b.Tiers = nil
	if err := json.Unmarshal(raw, b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := b.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

func (b *Baseline) validate() error {
	if len(b.Tiers) == 0 {
		return errors.New("no tiers defined")
	}
	if _, ok := b.Tiers[b.DefaultTier]; !ok {
		return fmt.Errorf("defaultTier %q is not a defined tier", b.DefaultTier)
	}
	seen := map[string]string{}
	for repo, tier := range b.Repos {
		if _, ok := b.Tiers[tier]; !ok {
			return fmt.Errorf("repo %q uses undefined tier %q", repo, tier)
		}
		key := strings.ToLower(repo)
		if other, ok := seen[key]; ok {
			return fmt.Errorf("repos %q and %q are the same repository (names are case-insensitive)", other, repo)
		}
		seen[key] = repo
	}
	if b.StaleDays <= 0 {
		return errors.New("staleDays must be positive")
	}
	return nil
}

// TierFor returns the tier name and settings for a repository. Repository
// names match case-insensitively, as they do on GitHub.
func (b *Baseline) TierFor(repo string) (string, Tier) {
	for name, tier := range b.Repos {
		if strings.EqualFold(name, repo) {
			return tier, b.Tiers[tier]
		}
	}
	return b.DefaultTier, b.Tiers[b.DefaultTier]
}
