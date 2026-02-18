package collector

import (
	"regexp"
	"strings"
)

// MatchesPattern checks if a name matches a glob pattern.
// Supports * (any characters) and ? (single character) wildcards.
func MatchesPattern(name, pattern string) bool {
	if pattern == "*" {
		return true
	}

	// Convert glob pattern to regex
	var regexPattern strings.Builder
	regexPattern.WriteString("^")

	for _, char := range pattern {
		switch char {
		case '*':
			regexPattern.WriteString(".*")
		case '?':
			regexPattern.WriteString(".")
		case '.', '+', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\':
			// Escape regex special characters
			regexPattern.WriteRune('\\')
			regexPattern.WriteRune(char)
		default:
			regexPattern.WriteRune(char)
		}
	}

	regexPattern.WriteString("$")

	re, err := regexp.Compile(regexPattern.String())
	if err != nil {
		return false
	}

	return re.MatchString(name)
}

// ShouldIncludeRepo determines if a repository should be included based on
// include and exclude patterns. Exclude patterns take precedence.
func ShouldIncludeRepo(repoName string, includePatterns, excludePatterns []string) bool {
	// Check if excluded first (exclusions take precedence)
	for _, pattern := range excludePatterns {
		if MatchesPattern(repoName, pattern) {
			return false
		}
	}

	// Check if included
	for _, pattern := range includePatterns {
		if MatchesPattern(repoName, pattern) {
			return true
		}
	}

	// If no include patterns matched, don't include
	return false
}
