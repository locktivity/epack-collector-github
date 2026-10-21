package github

import (
	"context"
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
