package github

import "context"

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
// members permission. Any other caller gets a FORBIDDEN error.
func (c *Client) FetchOrgSSO(ctx context.Context, org string) (*OrgSSO, error) {
	out := &OrgSSO{NameIDs: map[string]string{}}
	var cursor *string
	for read := 0; ; {
		var data struct {
			Organization *struct {
				SAMLIdentityProvider *struct {
					ExternalIdentities *struct {
						Nodes *[]struct {
							SAMLIdentity *struct {
								NameID string `json:"nameId"`
							} `json:"samlIdentity"`
							SCIMIdentity *struct{} `json:"scimIdentity"`
							User         *struct {
								Login string `json:"login"`
							} `json:"user"`
						}
						PageInfo pageInfo
					}
				} `json:"samlIdentityProvider"`
			}
		}
		if err := c.graphQL(ctx, "github.saml_identities.list", samlIdentitiesQuery, map[string]any{"org": org, "cursor": cursor}, &data); err != nil {
			return nil, err
		}
		if data.Organization == nil {
			return nil, invalidResponse("graphql SAML response has no organization")
		}
		provider := data.Organization.SAMLIdentityProvider
		if provider == nil {
			return out, nil
		}
		out.Configured = true
		if provider.ExternalIdentities == nil || provider.ExternalIdentities.Nodes == nil {
			return nil, invalidResponse("graphql SAML response has no external identity list")
		}
		page := provider.ExternalIdentities
		for _, n := range *page.Nodes {
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
