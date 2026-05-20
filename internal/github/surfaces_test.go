package github

import "testing"

func TestHostOnly_StripsPathQueryAndScheme(t *testing.T) {
	cases := map[string]string{
		"https://hooks.example.com/webhook?secret=abc123": "hooks.example.com",
		"https://ci.example.com:8443/path/to/hook":        "ci.example.com:8443",
		"http://internal/notify":                          "internal",
		"not a url":                                       "",
		"":                                                "",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsSecurityRelevantAction(t *testing.T) {
	relevant := []string{"member_add", "repo.create", "protected_branch.update", "org.disable_two_factor_requirement"}
	for _, a := range relevant {
		if !isSecurityRelevantAction(a) {
			t.Errorf("isSecurityRelevantAction(%q) = false, want true", a)
		}
	}
	irrelevant := []string{"git.clone", "issue.comment", "project.create"}
	for _, a := range irrelevant {
		if isSecurityRelevantAction(a) {
			t.Errorf("isSecurityRelevantAction(%q) = true, want false", a)
		}
	}
}

func TestIs403FeatureDisabled(t *testing.T) {
	// Feature-disabled 403 bodies GitHub returns when scanning/Dependabot is off.
	featureOff := []string{
		`{"message":"Advanced Security must be enabled for this repository to use code scanning."}`,
		`{"message":"Dependabot alerts are disabled for this repository."}`,
		`{"message":"Secret scanning is disabled on this repository."}`,
		`{"message":"code scanning is not enabled for this repository"}`,
	}
	for _, b := range featureOff {
		if !is403FeatureDisabled(b) {
			t.Errorf("is403FeatureDisabled(%q) = false, want true", b)
		}
	}

	// Genuine missing-permission 403 body.
	permission := `{"message":"Resource not accessible by integration","documentation_url":"..."}`
	if is403FeatureDisabled(permission) {
		t.Errorf("is403FeatureDisabled(%q) = true, want false (this is a permission error)", permission)
	}
}

func TestLinkLastPageRegex(t *testing.T) {
	link := `<https://api.github.com/repositories/1/secret-scanning/alerts?state=open&per_page=1&page=2>; rel="next", ` +
		`<https://api.github.com/repositories/1/secret-scanning/alerts?state=open&per_page=1&page=42>; rel="last"`
	m := linkLastPageRe.FindStringSubmatch(link)
	if m == nil || m[1] != "42" {
		t.Errorf("expected last page 42, got %v", m)
	}
}
