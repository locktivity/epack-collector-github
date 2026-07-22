package collector

import (
	"strings"
	"time"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// Per-surface truncation caps bounding output size and pagination.
const (
	MembersCap  = 10000
	ReposCap    = 5000
	AuditLogCap = 5000
)

// AuditLogWindowDays bounds the audit-log lookback.
const AuditLogWindowDays = 7

// collectRepositories builds the repo inventory from the GraphQL data already
// captured during the trust pass (no extra API calls). Audit emits inventory +
// branch-protection detail; internal adds low-sensitivity metadata.
func (c *Collector) collectRepositories(p *collectionPass) {
	repos := &Repositories{}
	rows := make([]RepoRow, 0, len(p.metrics.repos.included))

	for _, r := range p.metrics.repos.included {
		repos.TotalCount++
		switch strings.ToUpper(r.Visibility) {
		case "PUBLIC":
			repos.PublicCount++
		case "PRIVATE":
			repos.PrivateCount++
		case "INTERNAL":
			repos.InternalCount++
		}
		if r.IsArchived {
			repos.ArchivedCount++
		}
		if r.DefaultBranchRef.BranchProtectionRule != nil {
			repos.DefaultProtected++
		}

		row := RepoRow{
			Name:          r.Owner.Login + "/" + r.Name,
			Visibility:    r.Visibility,
			Archived:      r.IsArchived,
			IsTemplate:    r.IsTemplate,
			DefaultBranch: r.DefaultBranchRef.Name,
			CreatedAt:     formatTime(r.CreatedAt.Time),
			UpdatedAt:     formatTime(r.UpdatedAt.Time),
			PushedAt:      formatTime(r.PushedAt.Time),
			SizeKB:        r.DiskUsage,
		}
		if r.PrimaryLanguage != nil {
			row.PrimaryLanguage = r.PrimaryLanguage.Name
		}
		if bp := r.DefaultBranchRef.BranchProtectionRule; bp != nil {
			row.BranchProtection = &BranchProtectionDetail{
				RequiresApprovingReviews:       bp.RequiresApprovingReviews,
				RequiredApprovingReviewCount:   bp.RequiredApprovingReviewCount,
				DismissesStaleReviews:          bp.DismissesStaleReviews,
				RequiresCodeOwnerReviews:       bp.RequiresCodeOwnerReviews,
				RequiresStatusChecks:           bp.RequiresStatusChecks,
				RequiresCommitSignatures:       bp.RequiresCommitSignatures,
				IsAdminEnforced:                bp.IsAdminEnforced,
				RequiresLinearHistory:          bp.RequiresLinearHistory,
				AllowsForcePushes:              bp.AllowsForcePushes,
				AllowsDeletions:                bp.AllowsDeletions,
				RequiresConversationResolution: bp.RequiresConversationResolution,
			}
		}
		if p.internal() {
			row.Description = r.Description
			row.StargazerCount = r.StargazerCount
			if r.LicenseInfo != nil {
				row.LicenseSPDX = r.LicenseInfo.SpdxID
			}
			for _, t := range r.RepositoryTopics.Nodes {
				row.Topics = append(row.Topics, t.Topic.Name)
			}
		}
		rows = append(rows, row)
	}

	kept, dropped, truncated := Truncate(rows, ReposCap, func(a, b RepoRow) bool {
		// Private first, then most-recently-pushed first.
		ap, bp := a.Visibility == "PRIVATE", b.Visibility == "PRIVATE"
		if ap != bp {
			return ap
		}
		return a.PushedAt > b.PushedAt
	})
	repos.PerRepo = kept
	repos.Truncated = truncated
	repos.TruncatedDropped = dropped
	p.posture.Repositories = repos
}

// collectCodeowners checks each repo for a CODEOWNERS file. Audit emits
// presence + path; internal adds a content hash (bytes never emitted).
func (c *Collector) collectCodeowners(p *collectionPass) {
	wantHash := p.internal()
	rows := make([]CodeownersRow, 0, len(p.metrics.repos.included))
	permissionDenied := false

	for _, r := range p.metrics.repos.included {
		present, path, hash, err := c.client.GetCodeownersInfo(p.ctx, r.Owner.Login, r.Name, wantHash)
		if err != nil {
			permissionDenied = permissionDenied || isDenied(err)
			continue
		}
		rows = append(rows, CodeownersRow{
			Repository: r.Owner.Login + "/" + r.Name,
			Present:    present,
			Path:       path,
			Hash:       hash,
		})
	}
	if permissionDenied {
		p.metrics.diag.surfacePermissionDenied("codeowners", "contents:read")
	}
	p.posture.Codeowners = &Codeowners{PerRepo: rows}
}

// collectWebhooks gathers org + repo webhooks. Audit emits counts + by-event
// breakdown; internal adds per-hook rows (host only).
func (c *Collector) collectWebhooks(p *collectionPass) {
	w := &Webhooks{CountByEvent: map[string]int{}}
	permissionDenied := false

	orgHooks, err := c.client.ListOrgHooks(p.ctx, p.org)
	if err != nil {
		permissionDenied = permissionDenied || isDenied(err)
	} else {
		w.OrgCount = len(orgHooks)
		for _, h := range orgHooks {
			tallyHookEvents(w.CountByEvent, h.Events)
			if p.internal() {
				w.Org = append(w.Org, toWebhookRow("", h))
			}
		}
	}

	for _, r := range p.metrics.repos.included {
		hooks, herr := c.client.ListRepoHooks(p.ctx, r.Owner.Login, r.Name)
		if herr != nil {
			permissionDenied = permissionDenied || isDenied(herr)
			continue
		}
		w.RepoCount += len(hooks)
		repoKey := r.Owner.Login + "/" + r.Name
		for _, h := range hooks {
			tallyHookEvents(w.CountByEvent, h.Events)
			if p.internal() {
				w.Repo = append(w.Repo, toWebhookRow(repoKey, h))
			}
		}
	}

	if permissionDenied {
		p.metrics.diag.surfacePermissionDenied("webhooks", "organization_hooks:read, repository_hooks:read")
	}
	p.posture.Webhooks = w
}

func tallyHookEvents(counts map[string]int, events []string) {
	for _, e := range events {
		counts[e]++
	}
}

func toWebhookRow(repo string, h github.Hook) WebhookRow {
	return WebhookRow{
		Repository:         repo,
		ID:                 h.ID,
		Active:             h.Active,
		ContentType:        h.ContentType,
		Events:             h.Events,
		URLHost:            h.URLHost,
		LastResponseCode:   h.LastResponseCode,
		LastResponseStatus: h.LastResponseStatus,
	}
}

// collectDeployKeys gathers per-repo deploy keys. Audit emits counts; internal
// adds per-key rows (public key fingerprinted, never emitted).
func (c *Collector) collectDeployKeys(p *collectionPass) {
	dk := &DeployKeys{}
	permissionDenied := false

	for _, r := range p.metrics.repos.included {
		keys, err := c.client.ListRepoDeployKeys(p.ctx, r.Owner.Login, r.Name)
		if err != nil {
			permissionDenied = permissionDenied || isDenied(err)
			continue
		}
		repoKey := r.Owner.Login + "/" + r.Name
		for _, k := range keys {
			dk.TotalCount++
			if !k.ReadOnly {
				dk.ReadWriteCount++
			}
			if p.internal() {
				dk.PerKey = append(dk.PerKey, DeployKeyRow{
					Repository:  repoKey,
					ID:          k.ID,
					Title:       k.Title,
					ReadOnly:    k.ReadOnly,
					CreatedAt:   k.CreatedAt,
					LastUsed:    k.LastUsed,
					Fingerprint: k.Fingerprint,
				})
			}
		}
	}
	if permissionDenied {
		p.metrics.diag.surfacePermissionDenied("deploy_keys", "administration:read")
	}
	p.posture.DeployKeys = dk
}

// collectActions gathers self-hosted runners + org Actions secret names. Audit
// emits counts; internal adds per-runner rows + secret names.
func (c *Collector) collectActions(p *collectionPass) {
	a := &Actions{}
	permissionDenied := false

	if orgRunners, err := c.client.ListOrgRunners(p.ctx, p.org); err != nil {
		permissionDenied = permissionDenied || isDenied(err)
	} else {
		a.OrgRunnerCount = len(orgRunners)
		if p.internal() {
			for _, r := range orgRunners {
				a.OrgRunners = append(a.OrgRunners, toRunnerRow("", r))
			}
		}
	}

	if names, err := c.client.ListOrgActionsSecretNames(p.ctx, p.org); err != nil {
		permissionDenied = permissionDenied || isDenied(err)
	} else {
		a.OrgSecretCount = len(names)
		if p.internal() {
			a.OrgSecretNames = names
		}
	}

	for _, r := range p.metrics.repos.included {
		runners, err := c.client.ListRepoRunners(p.ctx, r.Owner.Login, r.Name)
		if err != nil {
			permissionDenied = permissionDenied || isDenied(err)
			continue
		}
		a.RepoRunnerCount += len(runners)
		if p.internal() {
			repoKey := r.Owner.Login + "/" + r.Name
			for _, rn := range runners {
				a.RepoRunners = append(a.RepoRunners, toRunnerRow(repoKey, rn))
			}
		}
	}

	if permissionDenied {
		p.metrics.diag.surfacePermissionDenied("actions",
			"actions:read, organization_self_hosted_runners:read, organization_secrets:read")
	}
	p.posture.Actions = a
}

func toRunnerRow(repo string, r github.Runner) RunnerRow {
	return RunnerRow{
		Repository: repo,
		ID:         r.ID,
		Name:       r.Name,
		OS:         r.OS,
		Status:     r.Status,
		Busy:       r.Busy,
		Labels:     r.Labels,
	}
}

// collectAuditLog fetches security-relevant audit events (Enterprise Cloud
// only). Audit emits counts by category; internal adds the event slice. It
// returns the actor→last-activity map (login → most recent event unix time),
// which collectMembers consumes for per-member last-activity. Returns nil when
// the surface is skipped (feature unavailable or permission denied).
func (c *Collector) collectAuditLog(p *collectionPass) map[string]int64 {
	since := time.Now().UTC().AddDate(0, 0, -AuditLogWindowDays).Format("2006-01-02")
	events, more, err := c.client.GetOrgAuditLog(p.ctx, p.org, since, AuditLogCap)
	if err != nil {
		if isFeatureUnavailable(err) {
			p.metrics.diag.surfaceUnavailable("audit_log", "requires GitHub Enterprise Cloud")
		} else if isDenied(err) {
			p.metrics.diag.surfacePermissionDenied("audit_log", "organization_administration:read")
		}
		return nil
	}

	al := &AuditLog{WindowDays: AuditLogWindowDays, CountByCategory: map[string]int{}}
	activity := map[string]int64{}

	for _, e := range events {
		al.CountByCategory[categoryOf(e.Action)]++
		if e.Actor != "" && e.CreatedAt > activity[e.Actor] {
			activity[e.Actor] = e.CreatedAt
		}
		if p.internal() {
			al.Events = append(al.Events, AuditLogRow{
				Action:    e.Action,
				Actor:     e.Actor,
				Repo:      e.Repo,
				Timestamp: e.CreatedAt,
			})
		}
	}
	if more {
		al.Truncated = true
	}
	p.posture.AuditLog = al
	return activity
}

// categoryOf maps an audit action to a coarse category for the count breakdown.
func categoryOf(action string) string {
	if i := strings.IndexAny(action, "._"); i > 0 {
		return action[:i]
	}
	return action
}

// collectApps gathers GitHub Apps installed in the org. Audit emits count +
// per-installation summary; internal adds timestamps + repo selection + events.
func (c *Collector) collectApps(p *collectionPass) {
	installs, err := c.client.ListOrgInstallations(p.ctx, p.org)
	if err != nil {
		if isDenied(err) {
			p.metrics.diag.surfacePermissionDenied("apps", "organization_administration:read")
		}
		return
	}
	apps := &Apps{InstallationCount: len(installs)}
	for _, i := range installs {
		row := AppRow{
			AppSlug:     i.AppSlug,
			AppID:       i.AppID,
			Suspended:   i.Suspended,
			Permissions: i.Permissions,
		}
		if p.internal() {
			row.CreatedAt = i.CreatedAt
			row.UpdatedAt = i.UpdatedAt
			row.RepositorySelection = i.RepositorySelection
			row.Events = i.Events
		}
		apps.PerInstallation = append(apps.PerInstallation, row)
	}
	p.posture.Apps = apps
}

// collectTokens gathers fine-grained PAT grants (Enterprise / FGT-policy orgs
// only). Audit emits the count; internal adds per-token metadata (no values).
func (c *Collector) collectTokens(p *collectionPass) {
	grants, _, err := c.client.ListOrgPATs(p.ctx, p.org)
	if err != nil {
		if isFeatureUnavailable(err) {
			p.metrics.diag.surfaceUnavailable("tokens", "requires a fine-grained personal-access-token policy")
		} else if isDenied(err) {
			p.metrics.diag.surfacePermissionDenied("tokens", "organization_personal_access_tokens:read")
		}
		return
	}
	tokens := &Tokens{GrantCount: len(grants)}
	if p.internal() {
		for _, g := range grants {
			tokens.PerToken = append(tokens.PerToken, TokenRow{
				ID:          g.ID,
				Owner:       g.Owner,
				TokenName:   g.TokenName,
				Permissions: g.Permissions,
				LastUsed:    g.LastUsed,
				ExpiresAt:   g.ExpiresAt,
			})
		}
	}
	p.posture.Tokens = tokens
}

// collectMembers builds the member inventory. Audit emits counts + per-member
// login/name/role; internal adds per-member 2FA + last-activity. The activity map
// (login → most recent audit-log event unix time) comes from collectAuditLog;
// it may be nil when the audit-log surface was skipped.
func (c *Collector) collectMembers(p *collectionPass, activity map[string]int64) {
	membership, err := c.client.GetOrgMembership(p.ctx, p.org)
	if err != nil {
		if isDenied(err) {
			p.metrics.diag.surfacePermissionDenied("members", "members:read")
		}
		return
	}

	for _, reason := range membership.NamesIncomplete {
		p.metrics.diag.memberNamesIncomplete(reason)
	}

	adminSet := toSet(membership.Admins)
	ocSet := toSet(membership.OutsideCollaborators)

	m := &Members{
		MemberCount:              len(membership.Members),
		AdminCount:               len(membership.Admins),
		OutsideCollaboratorCount: len(membership.OutsideCollaborators),
		HasPendingInvitations:    membership.PendingInvitations > 0,
	}

	// Union of members + outside collaborators for the per-member rows.
	logins := append([]string{}, membership.Members...)
	for _, oc := range membership.OutsideCollaborators {
		if !contains3(membership.Members, oc) {
			logins = append(logins, oc)
		}
	}

	rows := make([]MemberRow, 0, len(logins))
	for _, login := range logins {
		row := MemberRow{Login: login, Name: membership.Names[login], Role: roleFor(login, adminSet, ocSet)}
		if p.internal() {
			if membership.TwoFADisabled != nil {
				enabled := !membership.TwoFADisabled[login]
				row.TwoFactorEnabled = &enabled
			}
			if ts, ok := activity[login]; ok && ts > 0 {
				row.LastActivity = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		}
		rows = append(rows, row)
	}

	kept, dropped, truncated := Truncate(rows, MembersCap, func(a, b MemberRow) bool {
		ra, rb := roleRank(a.Role), roleRank(b.Role)
		if ra != rb {
			return ra < rb
		}
		return a.Login < b.Login
	})
	m.PerMember = kept
	m.Truncated = truncated
	m.TruncatedDropped = dropped
	p.posture.Members = m
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, i := range items {
		set[i] = true
	}
	return set
}

func contains3(items []string, target string) bool {
	for _, i := range items {
		if i == target {
			return true
		}
	}
	return false
}

func roleFor(login string, adminSet, ocSet map[string]bool) string {
	switch {
	case adminSet[login]:
		return "admin"
	case ocSet[login]:
		return "outside_collaborator"
	default:
		return "member"
	}
}

func roleRank(role string) int {
	switch role {
	case "admin":
		return 0
	case "member":
		return 1
	default:
		return 2
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
