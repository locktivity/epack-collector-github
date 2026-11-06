package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestGraphQLErrorsCarryTheirCode(t *testing.T) {
	tests := []struct {
		body string
		want componentsdk.Code
	}{
		{`{"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`, componentsdk.CodeRateLimited},
		{`{"errors":[{"type":"FORBIDDEN","message":"Resource protected by organization SAML enforcement."}]}`, componentsdk.CodePermissionDenied},
		{`{"data":{"organization":null},"errors":[{"type":"NOT_FOUND","message":"Could not resolve to an Organization."}]}`, componentsdk.CodeInvalidResponse},
		{`{"errors":[{"message":"Something went wrong while executing your query."}]}`, componentsdk.CodeVendorError},
		{`{"data":{"organization":{}}}`, componentsdk.CodeInvalidResponse},
		{`{}`, componentsdk.CodeInvalidResponse},
	}
	for _, tt := range tests {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(tt.body))
		}))
		client := NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql")
		err := client.FetchRepositories(context.Background(), "org", func([]Repository) error { return nil })
		server.Close()
		if got := componentsdk.Classify(err); got != tt.want {
			t.Errorf("%s: Classify(%v) = %s, want %s", tt.body, err, got, tt.want)
		}
	}
}

func TestNameOperationNamesOnlyTheTokenExchange(t *testing.T) {
	tests := []struct {
		method, url string
		want        bool
	}{
		{http.MethodPost, DefaultBaseURL + "/app/installations/7/access_tokens", true},
		{http.MethodGet, DefaultBaseURL + "/app/installations/7/access_tokens", false},
		{http.MethodPost, DefaultGraphQLURL, false},
		{http.MethodGet, DefaultBaseURL + "/orgs/test-org", false},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.url, nil)
		op, ok := NameOperation(req)
		if ok != tt.want || (ok && op != installationTokenOp) {
			t.Errorf("NameOperation(%s %s) = %+v, %v; want named: %v", tt.method, tt.url, op, ok, tt.want)
		}
	}
}

// secondaryRateLimitBody is the body of a response over a secondary rate
// limit.
const secondaryRateLimitBody = `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`

func TestSecondaryRateLimitIsRateLimited(t *testing.T) {
	// A 403 over a secondary rate limit can have Retry-After. It can also come
	// with requests remaining and only the message naming the limit.
	headers := map[string]map[string]string{
		"Retry-After":           {"Retry-After": "60"},
		"requests remaining":    {"X-RateLimit-Remaining": "4321"},
		"no rate limit headers": nil,
	}
	ctx := context.Background()
	calls := map[string]func(*Client) error{
		"sign-in": func(c *Client) error {
			_, err := c.FetchOrgSecurity(ctx, "org")
			return err
		},
		"runner list": func(c *Client) error {
			_, _, err := c.ListRepoRunners(ctx, "org", "repo")
			return err
		},
		"code scanning default setup": func(c *Client) error {
			settings, err := c.FetchSecuritySettings(ctx, "org", "repo")
			if err != nil {
				return err
			}
			return settings.CodeScanningErr
		},
	}
	for name, header := range headers {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/org/repo" {
				_, _ = w.Write([]byte(`{"name":"repo","security_and_analysis":{"secret_scanning":{"status":"enabled"}}}`))
				return
			}
			for k, v := range header {
				w.Header().Set(k, v)
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(secondaryRateLimitBody))
		}))
		for call, read := range calls {
			err := read(NewClientWithHTTP(server.Client(), server.URL))
			if got := componentsdk.Classify(err); got != componentsdk.CodeRateLimited || errors.Is(err, ErrPermissionDenied) {
				t.Errorf("%s with %s: Classify(%v) = %s, want rate_limited and no denial", call, name, err, got)
			}
		}
		server.Close()
	}
}

func TestClassifyResponseCodesASecondaryRateLimit(t *testing.T) {
	tests := []struct {
		status int
		body   string
		want   componentsdk.Code
	}{
		{http.StatusForbidden, secondaryRateLimitBody, componentsdk.CodeRateLimited},
		{http.StatusTooManyRequests, secondaryRateLimitBody, componentsdk.CodeRateLimited},
		{http.StatusForbidden, `{"message":"Resource not accessible by integration"}`, ""},
		{http.StatusForbidden, `not json`, ""},
		{http.StatusNotFound, secondaryRateLimitBody, ""},
	}
	for _, tt := range tests {
		got, ok := ClassifyResponse(&http.Response{StatusCode: tt.status}, []byte(tt.body))
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("ClassifyResponse(%d, %s) = %q, %t; want %q", tt.status, tt.body, got, ok, tt.want)
		}
	}
}
