package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/locktivity/epack/componentsdk"
)

// APIError is a GitHub call that failed: a response with an error status, or
// a GraphQL response that carries errors. It keeps the status, headers, and
// GraphQL error type, so componentsdk.Classify can give the failure its code.
type APIError struct {
	StatusCode int
	Header     http.Header
	// Path is the request path, or "graphql" for a GraphQL query.
	Path string
	// Operation names the call, as its componentsdk.Operation does.
	Operation string
	Message   string
	// Type is the GraphQL error type, such as RATE_LIMITED. REST errors have
	// none.
	Type string

	featureOff bool
	// unreadable marks a 403 whose JSON body was cut off. GitHub uses the
	// body to say whether a 403 is a denial or a feature that is off, so
	// such a response cannot be told apart.
	unreadable bool
}

func (e *APIError) Error() string {
	var sb strings.Builder
	sb.WriteString(e.Path)
	if e.Type != "" {
		fmt.Fprintf(&sb, ": GraphQL error %s", e.Type)
	} else {
		fmt.Fprintf(&sb, " returned status %d", e.StatusCode)
	}
	if e.Message != "" {
		sb.WriteString(": ")
		sb.WriteString(e.Message)
	}
	return sb.String()
}

// HTTPStatus returns the response status.
func (e *APIError) HTTPStatus() int { return e.StatusCode }

// HTTPHeader returns the response headers.
func (e *APIError) HTTPHeader() http.Header { return e.Header }

// VendorCode returns the GraphQL error type.
func (e *APIError) VendorCode() string { return e.Type }

// CollectionCode returns the code for errors whose status does not tell it:
// GraphQL errors, which arrive with status 200, and a 403 that says the
// repository's plan lacks the feature.
func (e *APIError) CollectionCode() componentsdk.Code {
	switch {
	case e.unreadable:
		return componentsdk.CodeInvalidResponse
	case e.featureOff:
		return componentsdk.CodeNotLicensed
	case e.Type == "RATE_LIMITED":
		return componentsdk.CodeRateLimited
	case e.Type == "FORBIDDEN":
		return componentsdk.CodePermissionDenied
	case e.Type == "NOT_FOUND":
		return componentsdk.CodeInvalidResponse
	case e.Type != "":
		return componentsdk.CodeVendorError
	}
	return ""
}

// Unwrap lets callers test for ErrPermissionDenied, ErrFeatureUnavailable,
// and ErrNotFound with errors.Is.
func (e *APIError) Unwrap() error {
	switch {
	case e.unreadable:
		return nil
	case e.featureOff:
		return ErrFeatureUnavailable
	case e.StatusCode == http.StatusForbidden && !e.throttled(), e.Type == "FORBIDDEN":
		return ErrPermissionDenied
	case e.StatusCode == http.StatusNotFound, e.Type == "NOT_FOUND":
		return ErrNotFound
	}
	return nil
}

// throttled reports a 403 that is GitHub's rate limit, not a denial.
func (e *APIError) throttled() bool {
	return e.Header.Get("Retry-After") != "" || e.Header.Get("X-RateLimit-Remaining") == "0"
}

// newAPIError reads the message from an error response and closes its body.
func newAPIError(resp *http.Response, path string) *APIError {
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var body struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &body)
	e := &APIError{StatusCode: resp.StatusCode, Header: resp.Header, Path: path, Operation: operationOf(resp), Message: body.Message}
	if resp.StatusCode == http.StatusForbidden && !e.throttled() {
		trimmed := bytes.TrimSpace(raw)
		switch {
		case is403FeatureDisabled(string(raw)):
			e.featureOff = true
		case len(trimmed) > 0 && trimmed[0] == '{' && !json.Valid(trimmed):
			e.unreadable = true
		}
	}
	return e
}

type graphQLError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func newGraphQLError(resp *http.Response, errs []graphQLError) *APIError {
	first := errs[0]
	e := &APIError{StatusCode: resp.StatusCode, Header: resp.Header, Path: "graphql", Operation: operationOf(resp), Message: first.Message, Type: first.Type}
	if e.Type == "" {
		e.Type = "UNKNOWN"
	}
	return e
}

// operationOf names the call resp answered.
func operationOf(resp *http.Response) string {
	if resp.Request == nil {
		return ""
	}
	op, _ := componentsdk.OperationOf(resp.Request.Context())
	return op.Name
}

// invalidResponse reports a response without the shape the collector reads,
// such as a list response missing its list.
func invalidResponse(format string, args ...any) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf(format, args...))
}

// installationTokenError turns a failed installation token exchange into an
// error with the exchange's status, which ghinstallation reports only as text.
func installationTokenError(err error) error {
	var httpErr *ghinstallation.HTTPError
	if errors.As(err, &httpErr) && httpErr.Response != nil {
		return fmt.Errorf("exchanging the GitHub App key for an installation token: %w",
			newAPIError(httpErr.Response, "/app/installations/{installation_id}/access_tokens"))
	}
	return fmt.Errorf("exchanging the GitHub App key for an installation token: %w", err)
}
