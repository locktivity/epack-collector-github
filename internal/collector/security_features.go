package collector

// augmentSecurityFeatures adds the audit-level per-repo feature rows (and, at
// internal, the findings inventory). The trust-level percentages on
// SecurityFeatures are left untouched.
func (c *Collector) augmentSecurityFeatures(p *collectionPass) {
	rows := make([]SecurityFeaturesRow, 0, len(p.metrics.repos.included))
	permissionDenied := false
	featureOff := false

	for _, repo := range p.metrics.repos.included {
		owner := repo.Owner.Login
		key := owner + "/" + repo.Name
		settings := p.metrics.repos.settingsFor(owner, repo.Name)

		row := SecurityFeaturesRow{
			Repository:          key,
			VulnerabilityAlerts: repo.HasVulnerabilityAlertsEnabled,
		}
		if settings != nil {
			row.CodeScanning = settings.CodeScanningEnabled
			row.SecretScanning = settings.SecretScanning
			row.SecretScanningPushProtection = settings.SecretScanningPushProtection
			row.DependabotSecurityUpdates = settings.DependabotSecurityUpdates
		}

		counts, err := c.client.GetOpenAlertCounts(p.ctx, owner, repo.Name)
		switch {
		case isDenied(err):
			permissionDenied = true
		case isFeatureUnavailable(err):
			featureOff = true
		}
		if counts != nil {
			row.OpenSecretScanningAlerts = counts.SecretScanningOpen
			row.OpenCodeScanningAlerts = counts.CodeScanningOpen
			row.OpenDependabotAlerts = counts.DependabotOpen
		}

		rows = append(rows, row)
	}

	recordAlertDiagnostic(p, "security_features.alert_counts", permissionDenied, featureOff)

	p.posture.SecurityFeatures.PerRepo = rows

	if p.internal() {
		c.collectFindings(p)
	}
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
