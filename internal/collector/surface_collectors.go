package collector

import (
	"cmp"
	"errors"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// Per-surface truncation caps bounding output size and pagination.
const (
	MembersCap      = 10000
	ReposCap        = 5000
	AuditLogCap     = 5000
	EnvironmentsCap = 5000
)

// AuditLogWindowDays bounds the audit-log lookback.
const AuditLogWindowDays = 7

// perRepoFailures tallies the repositories whose read failed for one value,
// with the first failure as the reason.
type perRepoFailures struct {
	count int
	err   error
}

func (f *perRepoFailures) add(err error) {
	f.count++
	if f.err == nil {
		f.err = err
	}
}

// reposUnknown records a gap at each pointer and reports true when the
// repository list could not be read, leaving per-repo surfaces unknown.
func (c *Collector) reposUnknown(p *collectionPass, pointers ...string) bool {
	if p.metrics.reposErr == nil {
		return false
	}
	c.gaps.leaveOut(p.metrics.reposErr, pointers...)
	return true
}

// collectRepositories builds the repo inventory from the data already
// captured during the trust pass (no extra API calls). Audit emits inventory,
// classic branch-protection detail, effective protection, and the rulesets on
// the default branch; internal adds low-sensitivity metadata.
func (c *Collector) collectRepositories(p *collectionPass) {
	if c.reposUnknown(p, "/repositories") {
		return
	}
	repos := &Repositories{ArchivedCount: p.metrics.archivedRepos}
	rows := make([]RepoRow, 0, len(p.metrics.repos.included))
	protections := make(map[string]*repoProtection, len(p.metrics.repos.included))
	protected, protectedUnknown := 0, false

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
		protection := p.metrics.repos.protectionFor(r)
		protections[repoKey(r)] = protection
		switch v := protection.protected(); {
		case v == nil:
			protectedUnknown = true
		case *v:
			protected++
		}

		row := RepoRow{
			Name:          r.Owner.Login + "/" + r.Name,
			Visibility:    r.Visibility,
			Archived:      r.IsArchived,
			IsTemplate:    r.IsTemplate,
			DefaultBranch: r.DefaultBranchRef.Name,
			CreatedAt:     formatTime(r.CreatedAt),
			UpdatedAt:     formatTime(r.UpdatedAt),
			PushedAt:      formatTime(r.PushedAt),
			SizeKB:        r.DiskUsage,

			EffectiveBranchProtection: protection.toEffective(),
			Rulesets:                  protection.toRulesetRows(),
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

	if !protectedUnknown {
		repos.DefaultProtected = &protected
	} else {
		unknown := perRepoFailures{}
		for _, r := range p.metrics.repos.included {
			if prot := protections[repoKey(r)]; prot.protected() == nil {
				unknown.add(p.metrics.unknownProtectionReason(repoKey(r), prot, false))
			}
		}
		c.gaps.partial(unknown.count, unknown.err, "/repositories/default_branch_protected_count")
	}

	kept, dropped, truncated := Truncate(rows, ReposCap, func(a, b RepoRow) bool {
		// Private first, then most-recently-pushed first.
		ap, bp := a.Visibility == "PRIVATE", b.Visibility == "PRIVATE"
		if ap != bp {
			return ap
		}
		return a.PushedAt > b.PushedAt
	})
	for i, row := range kept {
		c.recordRepoProtectionGaps(i, row, protections[row.Name], p.metrics)
	}
	repos.PerRepo = kept
	repos.Truncated = truncated
	repos.TruncatedDropped = dropped
	p.posture.Repositories = repos
}

// collectCodeowners checks each repo for a CODEOWNERS file. Audit emits
// presence + path; internal adds a content hash (bytes never emitted).
func (c *Collector) collectCodeowners(p *collectionPass) {
	if c.reposUnknown(p, "/codeowners") {
		return
	}
	wantHash := p.internal()
	rows := make([]CodeownersRow, 0, len(p.metrics.repos.included))

	for i, r := range p.metrics.repos.included {
		row := CodeownersRow{Repository: r.Owner.Login + "/" + r.Name}
		present, path, hash, err := c.client.GetCodeownersInfo(p.ctx, r.Owner.Login, r.Name, wantHash)
		if err != nil {
			c.gaps.leaveOut(err, rowPointer("/codeowners/per_repo", i, "present"), rowPointer("/codeowners/per_repo", i, "path"))
			if wantHash {
				c.gaps.leaveOut(err, rowPointer("/codeowners/per_repo", i, "hash"))
			}
		} else {
			row.Present = ptr(present)
			row.Path = path
			row.Hash = hash
		}
		rows = append(rows, row)
	}
	p.posture.Codeowners = &Codeowners{PerRepo: rows}
}

// collectWebhooks gathers org + repo webhooks. Audit emits counts + by-event
// breakdown; internal adds per-hook rows (host only).
func (c *Collector) collectWebhooks(p *collectionPass) {
	w := &Webhooks{}
	countByEvent := map[string]int{}
	// truncated reports a list that reached github.HookFetchCap, so it may
	// hold more webhooks than it read. Its count and the breakdown are left
	// null or out, as the schema explains.
	truncated := false

	orgHooks, orgMore, orgErr := c.client.ListOrgHooks(p.ctx, p.org)
	if orgErr != nil {
		c.gaps.leaveOut(orgErr, "/webhooks/org_count", "/webhooks/count_by_event")
		if p.internal() {
			c.gaps.leaveOut(orgErr, "/webhooks/org")
		}
	} else {
		truncated = orgMore
		if !orgMore {
			w.OrgCount = ptr(len(orgHooks))
		}
		for _, h := range orgHooks {
			tallyHookEvents(countByEvent, h.Events)
			if p.internal() {
				w.Org = append(w.Org, toWebhookRow("", h))
			}
		}
	}

	repoPointers := []string{"/webhooks/repo_count", "/webhooks/count_by_event"}
	if p.internal() {
		repoPointers = append(repoPointers, "/webhooks/repo")
	}
	failed := perRepoFailures{}
	if !c.reposUnknown(p, repoPointers...) {
		repoCount, repoMore := 0, false
		for _, r := range p.metrics.repos.included {
			hooks, more, herr := c.client.ListRepoHooks(p.ctx, r.Owner.Login, r.Name)
			if herr != nil {
				failed.add(herr)
				continue
			}
			repoCount += len(hooks)
			repoMore = repoMore || more
			repoKey := r.Owner.Login + "/" + r.Name
			for _, h := range hooks {
				tallyHookEvents(countByEvent, h.Events)
				if p.internal() {
					w.Repo = append(w.Repo, toWebhookRow(repoKey, h))
				}
			}
		}
		switch {
		case failed.count > 0:
			w.Repo = nil
			c.gaps.partial(failed.count, failed.err, repoPointers...)
		case repoMore:
			truncated = true
		default:
			w.RepoCount = ptr(repoCount)
		}
	}

	if orgErr == nil && p.metrics.reposErr == nil && failed.count == 0 && !truncated && len(countByEvent) > 0 {
		w.CountByEvent = countByEvent
	}
	// The flag describes the rows, which only internal emits.
	if p.internal() {
		w.Truncated = truncated
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
	if c.reposUnknown(p, "/deploy_keys") {
		return
	}
	dk := &DeployKeys{}
	list := c.readDeployKeys(p.ctx, p.metrics)
	failed := list.failed
	total, readWrite := 0, 0
	// truncated reports a list that reached github.DeployKeyFetchCap, so it
	// may hold more keys than it read. The counts are then left null, as the
	// schema explains.
	truncated := list.truncated

	for _, k := range list.keys {
		total++
		if !k.ReadOnly {
			readWrite++
		}
		if p.internal() {
			dk.PerKey = append(dk.PerKey, DeployKeyRow{
				Repository:  k.Repository,
				ID:          k.ID,
				Title:       k.Title,
				ReadOnly:    k.ReadOnly,
				CreatedAt:   k.CreatedAt,
				LastUsed:    k.LastUsed,
				Fingerprint: k.Fingerprint,
			})
		}
	}
	switch {
	case failed.count > 0:
		dk.PerKey = nil
		c.gaps.partial(failed.count, failed.err, "/deploy_keys/total_count", "/deploy_keys/read_write_count")
		if p.internal() {
			c.gaps.partial(failed.count, failed.err, "/deploy_keys/per_key")
		}
	case truncated:
		// The flag describes the rows, which only internal emits.
		dk.Truncated = p.internal()
	default:
		dk.TotalCount = ptr(total)
		dk.ReadWriteCount = ptr(readWrite)
	}
	p.posture.DeployKeys = dk
}

// collectActions gathers self-hosted runners + org Actions secret names. Audit
// emits counts; internal adds per-runner rows + secret names.
func (c *Collector) collectActions(p *collectionPass) {
	a := &Actions{}
	// truncated reports a list read short of the count GitHub gives for it.
	// unknown is the first list failure, which leaves truncated undecided
	// unless another list was cut short.
	truncated := false
	var unknown error

	if orgRunners, total, err := c.client.ListOrgRunners(p.ctx, p.org); err != nil {
		unknown = err
		c.gaps.leaveOut(err, "/actions/org_runner_count")
		if p.internal() {
			c.gaps.leaveOut(err, "/actions/org_runners")
		}
	} else {
		a.OrgRunnerCount = ptr(total)
		truncated = total > len(orgRunners)
		if p.internal() {
			for _, r := range orgRunners {
				a.OrgRunners = append(a.OrgRunners, toRunnerRow("", r))
			}
		}
	}

	if names, total, err := c.client.ListOrgActionsSecretNames(p.ctx, p.org); err != nil {
		unknown = cmp.Or(unknown, err)
		c.gaps.leaveOut(err, "/actions/org_secret_count")
		if p.internal() {
			c.gaps.leaveOut(err, "/actions/org_secret_names")
		}
	} else {
		a.OrgSecretCount = ptr(total)
		truncated = truncated || total > len(names)
		if p.internal() {
			a.OrgSecretNames = names
		}
	}

	repoPointers := []string{"/actions/repo_runner_count"}
	if p.internal() {
		repoPointers = append(repoPointers, "/actions/repo_runners")
	}
	if c.reposUnknown(p, repoPointers...) {
		unknown = cmp.Or(unknown, p.metrics.reposErr)
	} else {
		failed := perRepoFailures{}
		repoRunners, repoTruncated := 0, false
		for _, r := range p.metrics.repos.included {
			runners, total, err := c.client.ListRepoRunners(p.ctx, r.Owner.Login, r.Name)
			if err != nil {
				failed.add(err)
				continue
			}
			repoRunners += total
			repoTruncated = repoTruncated || total > len(runners)
			if p.internal() {
				repoKey := r.Owner.Login + "/" + r.Name
				for _, rn := range runners {
					a.RepoRunners = append(a.RepoRunners, toRunnerRow(repoKey, rn))
				}
			}
		}
		if failed.count > 0 {
			a.RepoRunners = nil
			c.gaps.partial(failed.count, failed.err, repoPointers...)
			unknown = cmp.Or(unknown, failed.err)
		} else {
			a.RepoRunnerCount = ptr(repoRunners)
			truncated = truncated || repoTruncated
		}
	}

	// The flag describes the rows, which only internal emits.
	if p.internal() {
		a.Truncated = truncated
		if !truncated {
			c.gaps.leaveOut(unknown, "/actions/truncated")
		}
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

// collectEnvironments gathers per-repo deployment environments and their
// protection configuration: required reviewers, self-review prevention, wait
// timers, deployment branch policies, admin bypass, and protection-rule Apps.
// Everything emits at audit; internal adds nothing.
func (c *Collector) collectEnvironments(p *collectionPass) {
	if c.reposUnknown(p, "/environments") {
		return
	}
	e := &Environments{}
	var rows []EnvironmentRow
	fetchDropped := 0
	failed := perRepoFailures{}
	total, withReviewers := 0, 0

	for _, r := range p.metrics.repos.included {
		envs, repoTotal, err := c.client.ListRepoEnvironments(p.ctx, r.Owner.Login, r.Name)
		if err != nil {
			failed.add(err)
			continue
		}
		total += repoTotal
		if repoTotal > len(envs) {
			fetchDropped += repoTotal - len(envs)
		}
		repoKey := r.Owner.Login + "/" + r.Name
		for _, env := range envs {
			if env.HasRequiredReviewers {
				withReviewers++
			}
			rows = append(rows, toEnvironmentRow(repoKey, env))
		}
	}

	if failed.count > 0 {
		c.gaps.partial(failed.count, failed.err,
			"/environments/total_count", "/environments/with_required_reviewers_count", "/environments/per_environment")
		p.posture.Environments = e
		return
	}
	e.TotalCount = ptr(total)
	e.WithRequiredReviewersCount = ptr(withReviewers)

	kept, dropped, truncated := Truncate(rows, EnvironmentsCap, func(a, b EnvironmentRow) bool {
		// Reviewer-gated environments first: on cap-hit the release gates stick.
		if a.RequiresReviewers != b.RequiresReviewers {
			return a.RequiresReviewers
		}
		if a.Repository != b.Repository {
			return a.Repository < b.Repository
		}
		return a.Name < b.Name
	})

	// Per-environment sub-resources are fetched only for kept rows, bounding
	// the extra API calls at the truncation cap.
	for i := range kept {
		owner, repo, _ := strings.Cut(kept[i].Repository, "/")
		if kept[i].BranchPolicy == github.BranchPolicyCustom {
			patterns, err := c.client.ListEnvironmentBranchPolicies(p.ctx, owner, repo, kept[i].Name)
			if err != nil {
				c.gaps.leaveOut(err, rowPointer("/environments/per_environment", i, "branch_policy_patterns"))
			}
			for _, pat := range patterns {
				kept[i].BranchPolicyPatterns = append(kept[i].BranchPolicyPatterns,
					EnvironmentBranchPattern{Name: pat.Name, Type: pat.Type})
			}
		}
		apps, err := c.client.ListEnvironmentProtectionApps(p.ctx, owner, repo, kept[i].Name)
		if err != nil {
			c.gaps.leaveOut(err, rowPointer("/environments/per_environment", i, "protection_apps"))
			continue
		}
		kept[i].ProtectionApps = apps
	}

	e.PerEnvironment = kept
	e.Truncated = truncated || fetchDropped > 0
	e.TruncatedDropped = dropped + fetchDropped
	p.posture.Environments = e
}

func toEnvironmentRow(repo string, env github.Environment) EnvironmentRow {
	row := EnvironmentRow{
		Repository:        repo,
		Name:              env.Name,
		RequiresReviewers: env.HasRequiredReviewers,
		PreventSelfReview: env.PreventSelfReview,
		WaitTimerMinutes:  env.WaitTimerMinutes,
		BranchPolicy:      env.BranchPolicy,
		CanAdminsBypass:   env.CanAdminsBypass,
		CreatedAt:         env.CreatedAt,
		UpdatedAt:         env.UpdatedAt,
	}
	for _, rv := range env.Reviewers {
		row.Reviewers = append(row.Reviewers, EnvironmentReviewerRow{
			Type:  rv.Type,
			Login: rv.Login,
			Slug:  rv.Slug,
			Name:  rv.Name,
		})
	}
	return row
}

// errAuditLogCut is why a person with no event in an audit log read cut
// short at AuditLogCap has no last activity. Their last event in the window
// can be older than the events read.
var errAuditLogCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
	errors.New("only the 5,000 most recent audit log events were read, and this person's last event may be older"))

// collectAuditLog fetches security-relevant audit events (Enterprise Cloud
// only). Audit emits counts by category; internal adds the event slice. It
// returns the actor→last-activity map (login → most recent event, in epoch
// milliseconds as GitHub reports it),
// which collectMembers consumes for per-member last-activity. The error is
// why a login missing from the map has no last activity. It is the error
// that kept the audit log from being read, or errAuditLogCut when the read
// stopped at AuditLogCap.
func (c *Collector) collectAuditLog(p *collectionPass) (map[string]int64, error) {
	// The window starts at the run's time of day. A date with no time would
	// mean the start of that day.
	since := c.now().UTC().AddDate(0, 0, -AuditLogWindowDays).Format("2006-01-02T15:04:05-07:00")
	events, more, err := c.client.GetOrgAuditLog(p.ctx, p.org, since, AuditLogCap)
	if err != nil {
		if isFeatureUnavailable(err) {
			c.gaps.leaveOutAdvised(err, []componentsdk.AdviceOption{auditLogChoice}, "/audit_log")
			return nil, err
		}
		c.gaps.leaveOut(err, "/audit_log")
		return nil, err
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
	p.posture.AuditLog = al
	if more {
		al.Truncated = true
		return activity, errAuditLogCut
	}
	return activity, nil
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
	installs, total, err := c.readInstallations(p.ctx, p.metrics)
	if err != nil {
		c.gaps.leaveOut(err, "/apps")
		return
	}
	apps := &Apps{InstallationCount: total, Truncated: total > len(installs)}
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
	grants, more, err := c.readGrants(p.ctx, p.metrics)
	if err != nil {
		c.gaps.leaveOut(err, "/tokens")
		return
	}
	tokens := &Tokens{}
	// A list that reached github.TokenGrantFetchCap may hold more grants, so
	// the count is left null, as the schema explains.
	if !more {
		tokens.GrantCount = ptr(len(grants))
	}
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
		tokens.Truncated = more
	}
	p.posture.Tokens = tokens
}

// collectMembers builds the member inventory. Audit emits counts + per-member
// login/name/role; internal adds per-member 2FA + last-activity. The activity map
// (login → most recent audit-log event, in epoch milliseconds) comes from collectAuditLog;
// activityErr is why a login missing from it has unknown last activity.
func (c *Collector) collectMembers(p *collectionPass, activity map[string]int64, activityErr error) {
	membership, err := c.readMembership(p.ctx, p.metrics, true)
	if err != nil {
		c.gaps.leaveOut(err, "/members")
		return
	}

	for _, reason := range membership.NamesIncomplete {
		p.metrics.notes.memberNamesIncomplete(reason)
	}

	// A roster that reached github.MemberFetchCap may hold more logins, so its
	// count is left null, as the schema explains.
	m := &Members{}
	if !membership.MembersMore {
		m.MemberCount = ptr(len(membership.Members))
	}
	if membership.AdminsErr == nil && !membership.AdminsMore {
		m.AdminCount = ptr(len(membership.Admins))
	}
	if membership.OutsideCollaboratorsErr == nil && !membership.OutsideCollaboratorsMore {
		m.OutsideCollaboratorCount = ptr(len(membership.OutsideCollaborators))
	}
	if membership.InvitationsErr == nil {
		m.HasPendingInvitations = ptr(membership.PendingInvitations > 0)
	}
	c.gaps.leaveOut(membership.AdminsErr, "/members/admin_count")
	c.gaps.leaveOut(membership.OutsideCollaboratorsErr, "/members/outside_collaborator_count")
	c.gaps.leaveOut(membership.InvitationsErr, "/members/has_pending_invitations")
	p.posture.Members = m

	// Without the outside collaborators the rows would read as the full roster.
	if membership.OutsideCollaboratorsErr != nil {
		c.gaps.leaveOut(membership.OutsideCollaboratorsErr, "/members/per_member")
		return
	}

	memberSet := toSet(membership.Members)
	adminSet := toSet(membership.Admins)
	ocSet := toSet(membership.OutsideCollaborators)
	unnamed := toSet(membership.UnnamedCollaborators)

	// Union of members + outside collaborators for the per-member rows.
	logins := append([]string{}, membership.Members...)
	for _, oc := range membership.OutsideCollaborators {
		if !memberSet[oc] {
			logins = append(logins, oc)
		}
	}

	rows := make([]MemberRow, 0, len(logins))
	for _, login := range logins {
		row := MemberRow{Login: login, Name: membership.Names[login]}
		if membership.AdminsErr == nil || ocSet[login] {
			row.Role = roleFor(login, adminSet, ocSet)
		}
		if p.internal() {
			if disabled := twoFactorRoster(membership, memberSet[login]); disabled != nil {
				enabled := !disabled[login]
				row.TwoFactorEnabled = &enabled
			}
			if ts, ok := activity[login]; ok && ts > 0 {
				row.LastActivity = time.UnixMilli(ts).UTC().Format(time.RFC3339)
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
	for i, row := range kept {
		member := memberSet[row.Login]
		if row.Role == "" {
			c.gaps.leaveOut(membership.AdminsErr, rowPointer("/members/per_member", i, "role"))
		}
		switch {
		case member && membership.NamesErr != nil:
			c.gaps.leaveOut(membership.NamesErr, rowPointer("/members/per_member", i, "name"))
		case !member && unnamed[row.Login]:
			c.gaps.leaveOut(membership.NameLookupErr, rowPointer("/members/per_member", i, "name"))
		}
		if p.internal() {
			switch {
			case member && membership.TwoFADisabled == nil:
				c.gaps.leaveOut(membership.TwoFAErr, rowPointer("/members/per_member", i, "two_factor_enabled"))
			case !member && membership.CollaboratorsTwoFADisabled == nil:
				c.gaps.leaveOut(membership.CollaboratorsTwoFAErr, rowPointer("/members/per_member", i, "two_factor_enabled"))
			}
			if row.LastActivity == "" {
				c.gaps.leaveOut(activityErr, rowPointer("/members/per_member", i, "last_activity"))
			}
		}
	}
	m.PerMember = kept
	m.Truncated = truncated || membership.MembersMore || membership.OutsideCollaboratorsMore
	m.TruncatedDropped = dropped
}

// twoFactorRoster is the set of people without two-factor authentication
// on the roster that covers a member, or an outside collaborator when member
// is false. It is nil when that roster could not be read in full.
func twoFactorRoster(membership *github.OrgMembership, member bool) map[string]bool {
	if member {
		return membership.TwoFADisabled
	}
	return membership.CollaboratorsTwoFADisabled
}

// collectSAMLIdentities reads the organization's SAML identities and adds
// the NameID of each member's linked identity to their row. A member's
// NameID is left out with a gap when the identities could not be read, or
// when the read stopped at github.IdentityFetchCap. Outside collaborators
// have no SAML identity in the organization.
func (c *Collector) collectSAMLIdentities(p *collectionPass) {
	sso, err := c.readSSO(p.ctx, p.metrics)
	m := p.posture.Members
	if m == nil {
		return
	}
	if err == nil && sso.More {
		err = errIdentitiesCut
	}
	for i := range m.PerMember {
		row := &m.PerMember[i]
		if row.Role == "outside_collaborator" {
			continue
		}
		if sso != nil {
			row.SAMLNameID = sso.NameIDs[row.Login]
		}
		if row.SAMLNameID == "" {
			c.gaps.leaveOut(err, rowPointer("/members/per_member", i, "saml_name_id"))
		}
	}
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, i := range items {
		set[i] = true
	}
	return set
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

// roleRank orders the rows the per_member cap keeps. A row with no role is a
// member whose owner status could not be read, so it ranks with the members.
func roleRank(role string) int {
	switch role {
	case "admin":
		return 0
	case "member", "":
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
