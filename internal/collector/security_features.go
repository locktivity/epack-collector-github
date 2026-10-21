package collector

import "github.com/locktivity/epack-collector-github/internal/github"

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

// listAlerts lists a repository's open alerts of each type. A type GitHub
// reports as not enabled for the repository has none.
func (c *Collector) listAlerts(p *collectionPass, repo github.Repository) repoAlerts {
	owner, name := repo.Owner.Login, repo.Name
	var a repoAlerts
	var moreS, moreC, moreD bool
	var errS, errC, errD error
	a.secrets, moreS, errS = c.client.ListSecretScanningAlerts(p.ctx, owner, name)
	a.code, moreC, errC = c.client.ListCodeScanningAlerts(p.ctx, owner, name)
	a.deps, moreD, errD = c.client.ListDependabotAlerts(p.ctx, owner, name)
	a.lists = []alertList{
		{"secret_scanning", "open_secret_scanning_alerts", len(a.secrets), moreS, errS},
		{"code_scanning", "open_code_scanning_alerts", len(a.code), moreC, errC},
		{"dependabot", "open_dependabot_alerts", len(a.deps), moreD, errD},
	}
	return a
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
	listings := make([]repoAlerts, 0, len(p.metrics.repos.included))

	for i, repo := range p.metrics.repos.included {
		row := SecurityFeaturesRow{Repository: repo.Owner.Login + "/" + repo.Name}
		for _, f := range features {
			value, err := p.metrics.featureValue(repo, f)
			row.setFeature(f, value)
			if value == nil {
				c.gaps.leaveOut(err, rowPointer("/security_features/per_repo", i, f.field()))
			}
		}

		alerts := c.listAlerts(p, repo)
		for _, l := range alerts.lists {
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
		listings = append(listings, alerts)
	}

	permissionDenied, featureOff := alertListProblems(listings)
	recordAlertDiagnostic(p, "security_features.alert_counts", permissionDenied, featureOff)

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

// alertListProblems reports whether any alert list was refused for a missing
// permission, and whether any found its feature off.
func alertListProblems(listings []repoAlerts) (permissionDenied, featureOff bool) {
	for _, a := range listings {
		for _, l := range a.lists {
			switch {
			case isFeatureUnavailable(l.err):
				featureOff = true
			case isDenied(l.err):
				permissionDenied = true
			}
		}
	}
	return permissionDenied, featureOff
}

// recordAlertDiagnostic records the right diagnostic for a security-alert
// surface. A genuine permission denial is actionable (grant the scope); a
// feature-not-enabled 403 is informational (the repo just doesn't have code /
// secret scanning or Dependabot alerts on). Permission denial takes precedence.
func recordAlertDiagnostic(p *collectionPass, surface string, permissionDenied, featureOff bool) {
	switch {
	case permissionDenied:
		p.metrics.diag.surfacePermissionDenied(surface,
			"secret_scanning_alerts:read, code_scanning_alerts:read, dependabot_alerts:read")
	case featureOff:
		p.metrics.diag.surfaceUnavailable(surface,
			"code/secret scanning or Dependabot alerts not enabled on some repositories")
	}
}
