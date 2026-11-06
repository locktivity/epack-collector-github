package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// appOnlyOperations are the calls GitHub accepts only from a GitHub App.
var appOnlyOperations = map[string]bool{
	"github.org_personal_access_tokens.list": true,
}

// appOnly reports whether err is a call that only a GitHub App can make.
func appOnly(err error) bool {
	var apiErr *github.APIError
	return errors.As(err, &apiErr) && appOnlyOperations[apiErr.Operation]
}

// withheldPermissions is the permission without which GitHub leaves each of
// these values out of a response it answers.
var withheldPermissions = []struct {
	err        error
	permission string
}{
	{errTwoFactorHidden, github.PermOrgAdministration},
	{errRepositoryCountHidden, github.PermOrgAdministration},
	{errOrgSettingsHidden, github.PermOrgAdministration},
	{github.ErrAnalysisHidden, github.PermAdministration},
}

// neededPermission returns the permission a denial in err's chain calls for,
// or "" when err is no denial the collector can name a permission for.
// withheld reports a value GitHub left out of a response rather than a call
// it refused.
func neededPermission(err error) (permission string, withheld bool) {
	for _, w := range withheldPermissions {
		if errors.Is(err, w.err) {
			return w.permission, true
		}
	}
	var apiErr *github.APIError
	if isDenied(err) && errors.As(err, &apiErr) {
		return github.OperationPermissions[apiErr.Operation], false
	}
	return "", false
}

// gapAdvice returns the advice for the gap that err left. Advice appears at
// every level, so it may contain permission and plan names but never a
// repository or a person. If the GitHub App lacks the required permission,
// the fix is to grant it, and the gap records the permission as missing. A
// token's permissions cannot be read. The fix for a token lists the
// permission it needs and does not claim the token lacks it. A call only a
// GitHub App can make has a fix that names the App alone. If the App holds
// the permission and the call was still refused, there is no known fix. The
// advice is then a warning that the App holds the permission. If the App
// holds the permission and a value is still withheld, there is no advice,
// because the error message states what is required. The customer gets a
// choice when a ruleset's bypass list is hidden.
func gapAdvice(err error, credential *github.Credential) []componentsdk.AdviceOption {
	if errors.Is(err, errBypassHidden) {
		return []componentsdk.AdviceOption{bypassChoice}
	}
	permission, withheld := neededPermission(err)
	if permission == "" || credential == nil {
		return nil
	}
	need := permission + ":read"
	switch credential.Kind {
	case github.CredentialAppInstallation:
		if granted := github.GrantedScope(credential.Scopes, permission); granted != "" {
			if withheld {
				return nil
			}
			return []componentsdk.AdviceOption{componentsdk.Warning(fmt.Sprintf("GitHub refused this although the GitHub App has %s.", granted))}
		}
		return []componentsdk.AdviceOption{
			componentsdk.Fix(fmt.Sprintf("Grant the GitHub App %s.", need)),
			componentsdk.MissingPermission(need),
		}
	case github.CredentialToken, github.CredentialInstallationToken:
		if appOnly(err) {
			return []componentsdk.AdviceOption{componentsdk.Fix(fmt.Sprintf("Use a GitHub App that has %s.", need))}
		}
		return []componentsdk.AdviceOption{componentsdk.Fix(fmt.Sprintf("Use a GitHub App or fine-grained token that has %s.", need))}
	}
	return nil
}

// bypassChoice is the customer's choice when a ruleset's bypass list is
// hidden. Only a credential with write access to a ruleset can read its
// bypass list.
var bypassChoice = componentsdk.Decide("Reading a ruleset's bypass list requires write access to the ruleset.",
	componentsdk.ChoiceOption{
		Label:       "Give the collector write access to rulesets",
		Consequence: "The collector's credential can then change rulesets. The next run reads their bypass lists.",
	},
	componentsdk.ChoiceOption{
		Label:       "Keep the collector read-only",
		Consequence: "Admin enforcement stays Not collected where those rulesets apply.",
	})

// auditLogChoice is the customer's choice when the organization's plan does
// not include the audit log API. The API requires GitHub Enterprise Cloud.
var auditLogChoice = componentsdk.Decide("Reading the audit log through GitHub's API requires GitHub Enterprise Cloud.",
	componentsdk.ChoiceOption{
		Label:       "Move the organization to GitHub Enterprise Cloud",
		Consequence: "Enterprise Cloud is billed per user. The next run reads the audit log.",
	},
	componentsdk.ChoiceOption{
		Label:       "Stay on the current plan",
		Consequence: "The audit log stays Not collected.",
	})
