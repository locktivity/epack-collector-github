package collector

import (
	"context"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// sharedLists holds the lists that the detailed artifact and the
// access-posture and vuln-scanning artifacts are built from. The first step
// that needs a list reads it, and later steps reuse it.
type sharedLists struct {
	// alerts holds each included repository's open alerts, in scan order.
	// withSecrets marks a read that listed secret scanning alerts too.
	alerts      []repoAlerts
	alertsRead  bool
	withSecrets bool

	// membership is the organization's rosters, or membershipErr why the
	// member list could not be read. withNames marks a read that also took
	// the names and pending invitations.
	membership     *github.OrgMembership
	membershipErr  error
	membershipRead bool
	withNames      bool

	keys     deployKeyList
	keysRead bool

	grants     []github.PATGrant
	grantsMore bool
	grantsErr  error
	grantsRead bool

	installs     []github.Installation
	installTotal int
	installsErr  error
	installsRead bool

	sso     *github.OrgSSO
	ssoErr  error
	ssoRead bool
}

// deployKeyList is the deploy keys of the included repositories. failed
// counts the repositories whose keys could not be listed, and truncated
// marks a repository whose list reached github.DeployKeyFetchCap.
type deployKeyList struct {
	keys      []github.DeployKey
	failed    perRepoFailures
	truncated bool
}

// readAlerts lists each included repository's open alerts, once. Secret
// scanning alerts are listed only when withSecrets is set, since only the
// detailed artifact counts them. It must not be called when the repository
// list could not be read.
func (c *Collector) readAlerts(ctx context.Context, m *metricsAggregator, withSecrets bool) []repoAlerts {
	l := &m.lists
	if l.alertsRead && (l.withSecrets || !withSecrets) {
		return l.alerts
	}
	alerts := make([]repoAlerts, 0, len(m.repos.included))
	for _, repo := range m.repos.included {
		alerts = append(alerts, c.listAlerts(ctx, repo, withSecrets))
	}
	l.alerts, l.alertsRead, l.withSecrets = alerts, true, withSecrets
	return alerts
}

// readMembership reads the organization's rosters, once. withNames also
// reads the member names and pending invitations, which only the detailed
// artifact holds.
func (c *Collector) readMembership(ctx context.Context, m *metricsAggregator, withNames bool) (*github.OrgMembership, error) {
	l := &m.lists
	if l.membershipRead && (l.withNames || !withNames) {
		return l.membership, l.membershipErr
	}
	if withNames {
		l.membership, l.membershipErr = c.client.GetOrgMembership(ctx, c.config.Organization)
	} else {
		l.membership, l.membershipErr = c.client.GetOrgRosters(ctx, c.config.Organization)
	}
	l.membershipRead, l.withNames = true, withNames
	return l.membership, l.membershipErr
}

// readDeployKeys lists the deploy keys of each included repository, once.
// It must not be called when the repository list could not be read.
func (c *Collector) readDeployKeys(ctx context.Context, m *metricsAggregator) deployKeyList {
	l := &m.lists
	if l.keysRead {
		return l.keys
	}
	var list deployKeyList
	for _, r := range m.repos.included {
		keys, more, err := c.client.ListRepoDeployKeys(ctx, r.Owner.Login, r.Name)
		if err != nil {
			list.failed.add(err)
			continue
		}
		list.truncated = list.truncated || more
		list.keys = append(list.keys, keys...)
	}
	l.keys, l.keysRead = list, true
	return list
}

// readGrants lists the fine-grained personal access tokens approved for the
// organization, once.
func (c *Collector) readGrants(ctx context.Context, m *metricsAggregator) ([]github.PATGrant, bool, error) {
	l := &m.lists
	if !l.grantsRead {
		l.grants, l.grantsMore, l.grantsErr = c.client.ListOrgPATs(ctx, c.config.Organization)
		l.grantsRead = true
	}
	return l.grants, l.grantsMore, l.grantsErr
}

// readInstallations lists the GitHub Apps installed on the organization,
// once, with the list's total_count.
func (c *Collector) readInstallations(ctx context.Context, m *metricsAggregator) ([]github.Installation, int, error) {
	l := &m.lists
	if !l.installsRead {
		l.installs, l.installTotal, l.installsErr = c.client.ListOrgInstallations(ctx, c.config.Organization)
		l.installsRead = true
	}
	return l.installs, l.installTotal, l.installsErr
}

// readSSO reads the organization's SAML single sign-on, once.
func (c *Collector) readSSO(ctx context.Context, m *metricsAggregator) (*github.OrgSSO, error) {
	l := &m.lists
	if !l.ssoRead {
		l.sso, l.ssoErr = c.client.FetchOrgSSO(ctx, c.config.Organization)
		l.ssoRead = true
	}
	return l.sso, l.ssoErr
}
