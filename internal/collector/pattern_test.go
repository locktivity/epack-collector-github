package collector

import "testing"

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		repoName string
		pattern  string
		want     bool
	}{
		{"wildcard matches all", "any-repo", "*", true},
		{"exact match", "my-repo", "my-repo", true},
		{"exact no match", "my-repo", "other-repo", false},
		{"prefix wildcard", "my-repo", "my-*", true},
		{"prefix wildcard no match", "other-repo", "my-*", false},
		{"suffix wildcard", "repo-archive", "*-archive", true},
		{"suffix wildcard no match", "repo-active", "*-archive", false},
		{"middle wildcard", "test-repo-v1", "test-*-v1", true},
		{"single char wildcard", "repo1", "repo?", true},
		{"single char wildcard no match", "repo12", "repo?", false},
		{"special chars escaped", "repo.name", "repo.name", true},
		{"special chars escaped no match", "repoXname", "repo.name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesPattern(tt.repoName, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.repoName, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestShouldIncludeRepo(t *testing.T) {
	tests := []struct {
		name            string
		repoName        string
		includePatterns []string
		excludePatterns []string
		want            bool
	}{
		{
			name:            "include all",
			repoName:        "any-repo",
			includePatterns: []string{"*"},
			excludePatterns: []string{},
			want:            true,
		},
		{
			name:            "exclude takes precedence",
			repoName:        "repo-archive",
			includePatterns: []string{"*"},
			excludePatterns: []string{"*-archive"},
			want:            false,
		},
		{
			name:            "specific include",
			repoName:        "frontend-app",
			includePatterns: []string{"frontend-*", "backend-*"},
			excludePatterns: []string{},
			want:            true,
		},
		{
			name:            "not in include list",
			repoName:        "random-repo",
			includePatterns: []string{"frontend-*", "backend-*"},
			excludePatterns: []string{},
			want:            false,
		},
		{
			name:            "multiple excludes",
			repoName:        "test-repo",
			includePatterns: []string{"*"},
			excludePatterns: []string{"*-archive", "test-*"},
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldIncludeRepo(tt.repoName, tt.includePatterns, tt.excludePatterns)
			if got != tt.want {
				t.Errorf("ShouldIncludeRepo(%q, %v, %v) = %v, want %v",
					tt.repoName, tt.includePatterns, tt.excludePatterns, got, tt.want)
			}
		})
	}
}
