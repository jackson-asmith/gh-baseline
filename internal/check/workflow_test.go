package check

import "testing"

func TestDependabotCoversActions(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			"covers github-actions",
			"version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n",
			true,
		},
		{
			"covers npm only",
			"version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n",
			false,
		},
		{
			"comment mentioning github-actions is not a match",
			"version: 2\nupdates:\n  # package-ecosystem: github-actions\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n",
			false,
		},
		{
			"covers both npm and github-actions",
			"version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dependabotCoversActions(tt.content); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
