package github

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// samlIdentitiesQuery fetches the organization's SAML identity provider and
// the external identities of its members, 100 per page. It reads the login
// of the member each identity belongs to and the identity's SAML NameID. It
// selects only the groups on each SCIM record, which shows whether the
// record exists without reading a name or an email.
const samlIdentitiesQuery = `query($cursor:String$org:String!){organization(login: $org){samlIdentityProvider{externalIdentities(first: 100, after: $cursor, membersOnly: true){nodes{samlIdentity{nameId},scimIdentity{groups},user{login}},pageInfo{hasNextPage,endCursor}}}}}`

// IdentityFetchCap bounds how many external identities the SAML read pages
// through. A read that reaches it comes back marked as possibly holding more.
const IdentityFetchCap = MemberFetchCap

// OrgSSO is the organization's SAML single sign-on, from GitHub's GraphQL
// API. Configured is false when the organization has no SAML identity
// provider, which is always so without GitHub Enterprise Cloud.
// LinkedMembers counts the members with a linked SAML identity, and
// SCIMMembers the members whose identity has a SCIM record. NameIDs maps
// each member's login to the NameID of their linked SAML identity, for the
// members whose identity has both. More marks a read that reached
// IdentityFetchCap, so the counts may be short.
type OrgSSO struct {
	Configured    bool
	LinkedMembers int
	SCIMMembers   int
	NameIDs       map[string]string
	More          bool
}

// FetchOrgSSO reads the organization's SAML identity provider and counts its
// members' external identities. The provider is visible to organization
// owners, to classic tokens with read:org, and to GitHub Apps with the
// members permission. Any other caller gets a FORBIDDEN error. GraphQL
// answers every field the query selects, so a provider, page info, or
// identity field it leaves out makes the answer invalid. A null provider is
// an organization without one, and a null samlIdentity or scimIdentity an
// identity without that record.
func (c *Client) FetchOrgSSO(ctx context.Context, org string) (*OrgSSO, error) {
	out := &OrgSSO{NameIDs: map[string]string{}}
	var cursor *string
	for read := 0; ; {
		var data struct {
			Organization *struct {
				SAMLIdentityProvider json.RawMessage `json:"samlIdentityProvider"`
			}
		}
		resp, err := c.graphQL(ctx, "github.saml_identities.list", samlIdentitiesQuery, map[string]any{"org": org, "cursor": cursor}, &data)
		if err != nil {
			return nil, err
		}
		if data.Organization == nil || data.Organization.SAMLIdentityProvider == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse("graphql SAML response has no organization or samlIdentityProvider"))
		}
		if string(data.Organization.SAMLIdentityProvider) == "null" {
			return out, nil
		}
		var provider struct {
			ExternalIdentities *struct {
				Nodes    *[]json.RawMessage
				PageInfo *pageInfo
			}
		}
		if err := json.Unmarshal(data.Organization.SAMLIdentityProvider, &provider); err != nil {
			return nil, componentsdk.ResponseError(resp, fmt.Errorf("graphql: decoding SAML identity provider: %w", err))
		}
		out.Configured = true
		if provider.ExternalIdentities == nil || provider.ExternalIdentities.Nodes == nil || provider.ExternalIdentities.PageInfo == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse("graphql SAML response has no external identity list or pageInfo"))
		}
		page := provider.ExternalIdentities
		for _, raw := range *page.Nodes {
			var node map[string]any
			if err := json.Unmarshal(raw, &node); err != nil || node == nil {
				return nil, componentsdk.ResponseError(resp, invalidResponse("graphql SAML response lists an identity that is not an object"))
			}
			if field := missingField(node, true, "samlIdentity", "scimIdentity"); field != "" {
				return nil, componentsdk.ResponseError(resp, invalidResponse("graphql SAML response lists an identity with no %s", field))
			}
			var n struct {
				SAMLIdentity *struct {
					NameID string `json:"nameId"`
				} `json:"samlIdentity"`
				SCIMIdentity *struct{} `json:"scimIdentity"`
				User         *struct {
					Login string `json:"login"`
				} `json:"user"`
			}
			if err := json.Unmarshal(raw, &n); err != nil {
				return nil, componentsdk.ResponseError(resp, fmt.Errorf("graphql: decoding SAML identity: %w", err))
			}
			if n.SAMLIdentity != nil {
				out.LinkedMembers++
				if n.User != nil && n.User.Login != "" && n.SAMLIdentity.NameID != "" {
					out.NameIDs[n.User.Login] = n.SAMLIdentity.NameID
				}
			}
			if n.SCIMIdentity != nil {
				out.SCIMMembers++
			}
		}
		read += len(*page.Nodes)
		if !page.PageInfo.HasNextPage {
			return out, nil
		}
		if read >= IdentityFetchCap {
			out.More = true
			return out, nil
		}
		next := page.PageInfo.EndCursor
		cursor = &next
	}
}
