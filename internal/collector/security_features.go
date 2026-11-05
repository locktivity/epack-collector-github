package collector

import (
	"context"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// repoAlerts holds one repository's open alerts of each type, listed once for
// both its per-repo counts and the findings inventory, so the two agree.
type repoAlerts struct {
	secrets []github.SecretScanningAlert
	code    []github.CodeScanningAlert
	deps    []github.DependabotAlert
	lists   []alertList
}

// alertList is the outcome of listing one alert type for one repository.
type alertList struct {
	findings string // the findings list it fills, such as secret_scanning
	field    string // its count's field on the per-repo row
	listed   int
	// more marks a list that reached github.AlertFetchCap, which leaves the
	// count unknown.
	more bool
	err  error
}

// listAlerts lists a repository's open code scanning and Dependabot alerts,
// and its secret scanning alerts when withSecrets is set. A type that is not
// enabled for the repository has none.
func (c *Collector) listAlerts(ctx context.Context, repo github.Repository, withSecrets bool) repoAlerts {
	owner, name := repo.Owner.Login, repo.Name
	var a repoAlerts
	if withSecrets {
		secrets, more, err := c.client.ListSecretScanningAlerts(ctx, owner, name)
		a.secrets = secrets
		a.lists = append(a.lists, alertList{"secret_scanning", "open_secret_scanning_alerts", len(secrets), more, err})
	}
	code, moreC, errC := c.client.ListCodeScanningAlerts(ctx, owner, name)
	deps, moreD, errD := c.client.ListDependabotAlerts(ctx, owner, name)
	a.code, a.deps = code, deps
	a.lists = append(a.lists,
		alertList{"code_scanning", "open_code_scanning_alerts", len(code), moreC, errC},
		alertList{"dependabot", "open_dependabot_alerts", len(deps), moreD, errD},
	)
	return a
}

// list returns the outcome of listing the alert type that fills findings,
// such as dependabot, and false when it was not listed.
func (a repoAlerts) list(findings string) (alertList, bool) {
	for _, l := range a.lists {
		if l.findings == findings {
			return l, true
		}
	}
	return alertList{}, false
}

// augmentSecurityFeatures adds the audit-level per-repo feature rows (and, at
// internal, the findings inventory). The trust-level percentages on
// SecurityFeatures are left untouched.
func (c *Collector) augmentSecurityFeatures(p *collectionPass) {
	if err := p.metrics.reposErr; err != nil {
		c.gaps.leaveOut(err, "/security_features/per_repo")
		if p.internal() {
			c.gaps.leaveOut(err, "/security_features/findings")
		}
		return
	}

	rows := make([]SecurityFeaturesRow, 0, len(p.metrics.repos.included))
	listings := c.readAlerts(p.ctx, p.metrics, true)

	for i, repo := range p.metrics.repos.included {
		row := SecurityFeaturesRow{Repository: repo.Owner.Login + "/" + repo.Name}
		for _, f := range features {
			value, err := p.metrics.featureValue(repo, f)
			row.setFeature(f, value)
			if value == nil {
				c.gaps.leaveOut(err, rowPointer("/security_features/per_repo", i, f.field()))
			}
		}

		for _, l := range listings[i].lists {
			switch {
			case l.err == nil && l.more:
				// Left null; the schema's x-epack-null says why.
			case l.err == nil || isFeatureUnavailable(l.err):
				row.setOpenAlerts(l.field, l.listed)
			default:
				c.gaps.leaveOut(l.err, rowPointer("/security_features/per_repo", i, l.field))
			}
		}

		rows = append(rows, row)
	}

	noteAlertsOff(p, "security_features.alert_counts", listings)

	p.posture.SecurityFeatures.PerRepo = rows

	if p.internal() {
		c.collectFindings(p, listings)
	}
}

func (r *SecurityFeaturesRow) setFeature(f feature, value *bool) {
	switch f {
	case featureVulnerabilityAlerts:
		r.VulnerabilityAlerts = value
	case featureCodeScanning:
		r.CodeScanning = value
	case featureSecretScanning:
		r.SecretScanning = value
	case featureSecretScanningPushProtection:
		r.SecretScanningPushProtection = value
	case featureDependabotSecurityUpdates:
		r.DependabotSecurityUpdates = value
	}
}

func (r *SecurityFeaturesRow) setOpenAlerts(field string, n int) {
	switch field {
	case "open_secret_scanning_alerts":
		r.OpenSecretScanningAlerts = ptr(n)
	case "open_code_scanning_alerts":
		r.OpenCodeScanningAlerts = ptr(n)
	case "open_dependabot_alerts":
		r.OpenDependabotAlerts = ptr(n)
	}
}

// noteAlertsOff adds a note when some repository has code scanning, secret
// scanning, or Dependabot alerts turned off. That is the repository's
// setting, and nothing about the collector needs changing. A refused list
// gets no note. The values left out because of the refusal have gaps that
// record the permission.
func noteAlertsOff(p *collectionPass, surface string, listings []repoAlerts) {
	for _, a := range listings {
		for _, l := range a.lists {
			if isFeatureUnavailable(l.err) {
				p.metrics.notes.featureOff(surface, "code/secret scanning or Dependabot alerts not enabled on some repositories")
				return
			}
		}
	}
}
