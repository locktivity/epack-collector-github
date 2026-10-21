package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// jsonStringPattern reads a JSON string whole, so a quote inside it is not
// taken as its end.
const jsonStringPattern = `"(?:[^"\\]|\\.)*"`

const (
	// zeroSHA stands in for a git object ID.
	zeroSHA = "0000000000000000000000000000000000000000"
	// placeholderName stands in for a member's display name.
	placeholderName = "Example Name"
)

// recordScrubPatterns remove from a recording what the collector never reads
// and a public repository must not hold: what people and the organization
// wrote on their profiles, avatar hashes, and git object IDs, which GitHub's
// search finds in public repositories. GitHub writes a profile's name just
// before its company, and the organization's description just before its
// name. tenantIdentifiers handles IDs and logins, which requests carry too.
var recordScrubPatterns = []collectortest.ScrubPattern{
	scrubMember("company|blog|location|twitter_username|bio", jsonStringPattern, "null"),
	scrubMember("gravatar_id", jsonStringPattern, `""`),
	{Pattern: regexp.MustCompile(`"name"\s*:\s*` + jsonStringPattern + `(\s*,\s*"company"\s*:)`), Replace: `"name":null${1}`},
	{Pattern: regexp.MustCompile(`"description"\s*:\s*` + jsonStringPattern + `(\s*,\s*"name"\s*:)`), Replace: `"description":null${1}`},
	{Pattern: regexp.MustCompile(`("login"\s*:\s*` + jsonStringPattern + `\s*,\s*"name"\s*:\s*)` + jsonStringPattern), Replace: `${1}"` + placeholderName + `"`},
	{Pattern: gitObjectID, Replace: zeroSHA},
}

var gitObjectID = regexp.MustCompile(`\b[0-9a-f]{40}\b`)

// scrubMember replaces the value of each JSON member whose name matches keys
// and whose value matches value.
func scrubMember(keys, value, replacement string) collectortest.ScrubPattern {
	return collectortest.ScrubPattern{
		Pattern: regexp.MustCompile(`"(` + keys + `)"\s*:\s*` + value),
		Replace: `"${1}":` + replacement,
	}
}

// idKeys name the JSON members that hold a GitHub ID.
var idKeys = map[string]bool{
	"id": true, "target_id": true, "actor_id": true, "app_id": true, "ruleset_id": true,
	"repository_id": true, "installation_id": true, "user_id": true,
}

// urlID finds the IDs GitHub writes into URLs: avatars, pagination links,
// and settings pages.
var urlID = regexp.MustCompile(`/(?:u|user|users|organizations|repositories|installations)/([0-9]{6,})\b`)

// cursorParams are the query parameters of GitHub's cursor pagination links.
var cursorParams = []string{"after", "before", "cursor"}

// Kinds of identifier tenantIdentifiers finds, each with the form of its
// fakes.
var identifierKinds = map[string]string{
	"login":     "member-%d",
	"node_id":   "node-%d",
	"app_slug":  "sandbox-app-%d",
	"client_id": "client-id-%d",
	"cursor":    "cursor-%d",
}

// kindLabels name each kind in errors and guard problems.
var kindLabels = map[string]string{
	"login":     "a login",
	"node_id":   "a node ID",
	"app_slug":  "an App slug",
	"client_id": "an App client ID",
	"cursor":    "a pagination cursor",
}

var fakeForms = func() map[string]*regexp.Regexp {
	out := map[string]*regexp.Regexp{}
	for kind, form := range identifierKinds {
		out[kind] = regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(form), "%d", `[0-9]+`) + "$")
	}
	return out
}()

// minIdentifier is the shortest login, node ID, slug, client ID, or cursor
// that can be replaced as an identifier, which happens wherever its text
// appears.
const minIdentifier = 4

// tenantIdentifiers finds what in a recording names the tenant or a person
// and may be carried by the recording's requests too: GitHub IDs of six
// digits or more, node IDs, logins, App slugs and client IDs, and pagination
// cursors, which can encode IDs. It maps each one not already in known, as
// an identifier or a fake, to a fake of its own. An identifier too short to
// replace safely, or one a JSON member name contains, is an error, which
// never names the value.
func tenantIdentifiers(sc collectortest.Scenario, known map[string]string) (map[string]string, error) {
	f := identifierFinder{known: map[string]bool{}, numbers: map[string]bool{}, found: map[string]string{}, keys: map[string]bool{}}
	for value, fake := range known {
		f.known[strings.ToLower(value)], f.known[strings.ToLower(fake)] = true, true
	}
	for _, r := range sc.Responses {
		f.text(r.URL)
		for _, values := range r.Header {
			for _, v := range values {
				f.text(v)
			}
		}
		f.text(r.RequestBody)
		f.text(r.Body)
		f.json(r.Body)
	}
	return f.fakes()
}

type identifierFinder struct {
	known   map[string]bool   // lowercase
	numbers map[string]bool   // digits
	found   map[string]string // value to kind
	keys    map[string]bool   // every JSON member name, lowercase
}

func (f *identifierFinder) number(v string) {
	if len(v) >= 6 && isDigits(v) && !f.known[v] {
		f.numbers[v] = true
	}
}

func (f *identifierFinder) add(v, kind string) {
	if v != "" && !f.known[strings.ToLower(v)] {
		f.found[v] = kind
	}
}

func (f *identifierFinder) text(s string) {
	for _, m := range urlID.FindAllStringSubmatch(s, -1) {
		f.number(m[1])
	}
	for _, link := range strings.Split(s, ",") {
		start, end := strings.Index(link, "<"), strings.Index(link, ">")
		if start < 0 || end < start {
			continue
		}
		u, err := url.Parse(link[start+1 : end])
		if err != nil {
			continue
		}
		for _, p := range cursorParams {
			f.add(u.Query().Get(p), "cursor")
		}
	}
}

func (f *identifierFinder) json(body string) {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var doc any
	if dec.Decode(&doc) == nil {
		f.walk(doc)
	}
}

func (f *identifierFinder) walk(node any) {
	switch n := node.(type) {
	case map[string]any:
		for key, value := range n {
			f.keys[strings.ToLower(key)] = true
			switch v := value.(type) {
			case json.Number:
				if idKeys[key] {
					f.number(v.String())
				}
			case string:
				switch {
				case idKeys[key]:
					f.number(v)
				case key == "endCursor":
					f.add(v, "cursor")
				case identifierKinds[key] != "":
					f.add(v, key)
				}
			}
			f.walk(value)
		}
	case []any:
		for _, v := range n {
			f.walk(v)
		}
	}
}

// fakes gives each identifier found a fake: digits of the same length that
// start with 9 then zeros for an ID, and a numbered name of its kind for the
// rest, numbered in sorted order.
func (f *identifierFinder) fakes() (map[string]string, error) {
	out := map[string]string{}
	taken := map[string]bool{}
	for v := range f.known {
		taken[v] = true
	}
	for v := range f.numbers {
		taken[v] = true
	}
	for v := range f.found {
		taken[strings.ToLower(v)] = true
	}

	numbers := make([]string, 0, len(f.numbers))
	for v := range f.numbers {
		numbers = append(numbers, v)
	}
	sort.Slice(numbers, func(i, j int) bool {
		if len(numbers[i]) != len(numbers[j]) {
			return len(numbers[i]) < len(numbers[j])
		}
		return numbers[i] < numbers[j]
	})
	n := 0
	for _, v := range numbers {
		for {
			n++
			fake := fakeNumber(len(v), n)
			if !taken[fake] {
				taken[fake], out[v] = true, fake
				break
			}
		}
	}

	values := make([]string, 0, len(f.found))
	for v := range f.found {
		values = append(values, v)
	}
	sort.Strings(values)
	counts := map[string]int{}
	var errs []error
	for _, v := range values {
		kind := f.found[v]
		if len(v) < minIdentifier {
			errs = append(errs, fmt.Errorf("%s is shorter than %d characters, too short to replace wherever it appears", kindLabels[kind], minIdentifier))
			continue
		}
		for key := range f.keys {
			if strings.Contains(key, strings.ToLower(v)) {
				errs = append(errs, fmt.Errorf("a JSON member name contains %s, so replacing it would rename the member", kindLabels[kind]))
				break
			}
		}
		for {
			counts[kind]++
			fake := fmt.Sprintf(identifierKinds[kind], counts[kind])
			if !taken[fake] {
				taken[fake], out[v] = true, fake
				break
			}
		}
	}
	return out, errors.Join(errs...)
}

// fakeNumber is the nth fake ID of length digits: a 9, zeros, then n.
func fakeNumber(length, n int) string {
	s := strconv.Itoa(n)
	return "9" + strings.Repeat("0", max(length-1-len(s), 0)) + s
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

var (
	fakeID        = regexp.MustCompile(`^90*[1-9][0-9]*$`)
	recordedEmail = regexp.MustCompile(`[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	kitFakeEmail  = regexp.MustCompile(`^user[0-9]+@example\.com$`)
	// gitSSHUser is the user of every repository's ssh_url, not a person.
	gitSSHUser      = "git@github.com"
	profileFreeText = map[string]bool{"company": true, "blog": true, "location": true, "twitter_username": true, "bio": true}
)

// isFakeID reports whether an ID of six digits or more is one the record
// test put there.
func isFakeID(v string) bool {
	return fakeID.MatchString(v) || v == strconv.Itoa(kitAppID) || v == strconv.Itoa(kitInstallationID)
}

// recordingFile is the part of a recording file the scrub guard reads.
type recordingFile struct {
	Responses []struct {
		URL         string              `json:"url"`
		Header      map[string][]string `json:"header"`
		Body        json.RawMessage     `json:"body"`
		RequestBody json.RawMessage     `json:"request_body"`
	} `json:"responses"`
}

// unscrubbed lists each place in a recording file that holds what the record
// test removes: an ID, node ID, login, App slug or client ID, or cursor that
// is not a fake, profile text, a git object ID, or an email address other
// than the kit's fakes. It names where each is, never the value.
func unscrubbed(raw []byte) ([]string, error) {
	var file recordingFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	var g scrubGuard
	for i, r := range file.Responses {
		at := fmt.Sprintf("responses[%d]", i)
		g.text(at+".url", r.URL)
		for name, values := range r.Header {
			for _, v := range values {
				g.text(at+".header."+name, v)
			}
		}
		g.raw(at+".request_body", r.RequestBody)
		g.raw(at+".body", r.Body)
	}
	return g.problems, nil
}

type scrubGuard struct {
	problems []string
}

func (g *scrubGuard) flag(at, what string) {
	g.problems = append(g.problems, at+" "+what)
}

func (g *scrubGuard) raw(at string, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		g.flag(at, "is not JSON")
		return
	}
	g.walk(at, doc)
}

func (g *scrubGuard) walk(at string, node any) {
	switch n := node.(type) {
	case map[string]any:
		g.object(at, n)
		for key, value := range n {
			here := at + "/" + key
			g.member(here, key, value)
			g.walk(here, value)
		}
	case []any:
		for i, v := range n {
			g.walk(fmt.Sprintf("%s/%d", at, i), v)
		}
	case string:
		g.text(at, n)
	}
}

// object checks the display names and descriptions of people and the
// organization. A repository has a name and a description too, so the
// members beside them tell these apart.
func (g *scrubGuard) object(at string, obj map[string]any) {
	if _, ok := obj["company"]; ok && obj["name"] != nil {
		g.flag(at+"/name", "is a profile's display name")
	}
	if _, ok := obj["login"]; ok && obj["description"] != nil {
		g.flag(at+"/description", "is an account's description")
	}
	if _, ok := obj["login"]; ok && len(obj) == 2 {
		if name, ok := obj["name"]; ok && name != nil && name != placeholderName {
			g.flag(at+"/name", "is a member's display name")
		}
	}
}

func (g *scrubGuard) member(at, key string, value any) {
	v, isString := value.(string)
	if num, ok := value.(json.Number); ok {
		v, isString = num.String(), true
	}
	if !isString {
		return
	}
	switch {
	case idKeys[key]:
		if len(v) >= 6 && isDigits(v) && !isFakeID(v) {
			g.flag(at, "is a GitHub ID")
		}
	case key == "endCursor":
		if v != "" && !fakeForms["cursor"].MatchString(v) {
			g.flag(at, "is a pagination cursor")
		}
	case key == "login":
		if v != kitOrg && !fakeForms["login"].MatchString(v) {
			g.flag(at, "is a login")
		}
	case identifierKinds[key] != "":
		if v != "" && !fakeForms[key].MatchString(v) {
			g.flag(at, "is "+kindLabels[key])
		}
	case profileFreeText[key]:
		if _, ok := value.(string); ok {
			g.flag(at, "is profile text")
		}
	case key == "gravatar_id":
		if v != "" {
			g.flag(at, "is an avatar hash")
		}
	}
}

func (g *scrubGuard) text(at, s string) {
	for _, m := range gitObjectID.FindAllString(s, -1) {
		if m != zeroSHA {
			g.flag(at, "holds a git object ID")
			break
		}
	}
	for _, m := range urlID.FindAllStringSubmatch(s, -1) {
		if !isFakeID(m[1]) {
			g.flag(at, "holds a GitHub ID in a URL")
			break
		}
	}
	for _, m := range recordedEmail.FindAllString(s, -1) {
		if !kitFakeEmail.MatchString(strings.ToLower(m)) && m != gitSSHUser {
			g.flag(at, "holds an email address")
			break
		}
	}
	for _, link := range strings.Split(s, ",") {
		start, end := strings.Index(link, "<"), strings.Index(link, ">")
		if start < 0 || end < start {
			continue
		}
		u, err := url.Parse(link[start+1 : end])
		if err != nil {
			continue
		}
		for _, p := range cursorParams {
			if c := u.Query().Get(p); c != "" && !fakeForms["cursor"].MatchString(c) {
				g.flag(at, "holds a pagination cursor")
			}
		}
	}
}

// Responses shaped as GitHub sends them, indented, for the sandbox owner
// account, a member, the organization, a repository, the collector's App,
// and a code scanning analysis.
const (
	rawOrg = `{
  "login": "test-org",
  "id": 147464937,
  "node_id": "O_kgDOCMoK6Q",
  "url": "https://api.github.com/orgs/test-org",
  "avatar_url": "https://avatars.githubusercontent.com/u/147464937?v=4",
  "description": "Where the sandbox lives",
  "name": "Sandbox Org",
  "company": "Example Corp",
  "blog": "https://blog.example",
  "location": "Springfield",
  "email": null,
  "twitter_username": "sandboxorg",
  "html_url": "https://github.com/test-org",
  "type": "Organization",
  "billing_email": "user1@example.com",
  "two_factor_requirement_enabled": true
}`
	rawMembers = `[
  {
    "login": "sandbox-owner-account",
    "id": 231876502,
    "node_id": "U_kgDODdIqFg",
    "avatar_url": "https://avatars.githubusercontent.com/u/231876502?v=4",
    "gravatar_id": "205e460b479e2e5b48aec07710c08d50",
    "url": "https://api.github.com/users/sandbox-owner-account",
    "html_url": "https://github.com/sandbox-owner-account",
    "type": "User",
    "site_admin": false
  }
]`
	rawGraphQLMembers = `{"data":{"organization":{"membersWithRole":{"nodes":[{"login":"sandbox-owner-account","name":"Pat Example"},{"login":"borrowed-machine","name":null}],"pageInfo":{"hasNextPage":false,"endCursor":"Y3Vyc29yOnYyOpHODdIqFg=="}}}}}`
	rawRepo           = `{
  "id": 1072854411,
  "node_id": "R_kgDOP_jDiw",
  "name": "classic-protected",
  "full_name": "test-org/classic-protected",
  "owner": {
    "login": "test-org",
    "id": 147464937,
    "node_id": "O_kgDOCMoK6Q",
    "avatar_url": "https://avatars.githubusercontent.com/u/147464937?v=4",
    "gravatar_id": "",
    "type": "Organization"
  },
  "description": "Default branch protected by a classic branch protection rule.",
  "fork": false
}`
	rawInstallations = `{
  "total_count": 1,
  "installations": [
    {
      "id": 78901234,
      "client_id": "Iv23liQwErTy1234ab5c",
      "app_id": 123456,
      "app_slug": "sandbox-collector-xyz",
      "target_id": 147464937,
      "html_url": "https://github.com/organizations/test-org/settings/installations/78901234"
    }
  ]
}`
	rawAnalysis = `[
  {
    "ref": "refs/heads/main",
    "commit_sha": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "id": 812345678,
    "url": "https://api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/analyses/812345678"
  }
]`
	rawDependabotLink = `<https://api.github.com/repositories/1072854411/dependabot/alerts?per_page=100&after=Y3Vyc29yOjQyMTA5>; rel="next"`
)

// rawScenario is a recording's responses before tenantIdentifiers' pass:
// the kit's fakes stand for the organization and the App already.
func rawScenario() collectortest.Scenario {
	return collectortest.Scenario{Responses: []collectortest.Response{
		{URL: kitOrgURL(""), Body: rawOrg},
		{URL: kitOrgURL("/members?per_page=100"), Body: rawMembers},
		{URL: kitGraphQL, Method: "POST", Body: rawGraphQLMembers},
		{URL: kitRepoURL("classic-protected", ""), Body: rawRepo},
		{URL: kitOrgURL("/installations?per_page=100"), Body: rawInstallations},
		{URL: kitRepoURL("ruleset-pr-no-approvals", "/code-scanning/analyses?per_page=1"), Body: rawAnalysis},
		{URL: kitAlertListURL("classic-protected", "dependabot"), Header: map[string][]string{"Link": {rawDependabotLink}}, Body: `[]`},
	}}
}

// kitKnown is what the record test's EnvIdentifiers replaced already, keyed
// by values that stand in for the sandbox's own.
var kitKnown = map[string]string{
	"real-org-login":   kitOrg,
	"1234567":          strconv.Itoa(kitAppID),
	"98765432":         strconv.Itoa(kitInstallationID),
	"real-sandbox-var": "sandbox-var",
}

// scrubLike applies identifiers and recordScrubPatterns the way Record does,
// identifiers first, for tests that cannot reach GitHub.
func scrubLike(body string, identifiers map[string]string) string {
	values := make([]string, 0, len(identifiers))
	for v := range identifiers {
		values = append(values, v)
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, v := range values {
		if isDigits(v) {
			body = regexp.MustCompile(`(^|[^0-9])`+v+`([^0-9]|$)`).ReplaceAllString(body, "${1}"+identifiers[v]+"${2}")
			continue
		}
		body = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(v)).ReplaceAllString(body, identifiers[v])
	}
	for _, p := range recordScrubPatterns {
		body = p.Pattern.ReplaceAllString(body, p.Replace)
	}
	n := 0
	return recordedEmail.ReplaceAllStringFunc(body, func(m string) string {
		if m == gitSSHUser || kitFakeEmail.MatchString(m) {
			return m
		}
		n++
		return fmt.Sprintf("user%d@example.com", n)
	})
}

func TestTenantIdentifiersFindsWhatNamesTheTenant(t *testing.T) {
	found, err := tenantIdentifiers(rawScenario(), kitKnown)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"147464937":                "900000001",
		"231876502":                "900000002",
		"812345678":                "900000003",
		"1072854411":               "9000000004",
		"O_kgDOCMoK6Q":             "node-1",
		"R_kgDOP_jDiw":             "node-2",
		"U_kgDODdIqFg":             "node-3",
		"borrowed-machine":         "member-1",
		"sandbox-owner-account":    "member-2",
		"Iv23liQwErTy1234ab5c":     "client-id-1",
		"sandbox-collector-xyz":    "sandbox-app-1",
		"Y3Vyc29yOjQyMTA5":         "cursor-1",
		"Y3Vyc29yOnYyOpHODdIqFg==": "cursor-2",
	}
	for v, fake := range want {
		if found[v] != fake {
			t.Errorf("%s: fake %q, want %q", v, found[v], fake)
		}
	}
	for v := range found {
		if _, ok := want[v]; !ok {
			t.Errorf("found %q, which is not an identifier", v)
		}
	}
}

func TestTenantIdentifiersRefusesWhatCannotBeReplaced(t *testing.T) {
	short := collectortest.Scenario{Responses: []collectortest.Response{{URL: kitOrgURL("/members"), Body: `[{"login":"ab"}]`}}}
	if _, err := tenantIdentifiers(short, nil); err == nil || strings.Contains(err.Error(), `"ab"`) {
		t.Errorf("err = %v, want a refusal that does not name the login", err)
	}
	inKey := collectortest.Scenario{Responses: []collectortest.Response{{URL: kitOrgURL("/members"), Body: `[{"login":"site","site_admin":false}]`}}}
	if _, err := tenantIdentifiers(inKey, nil); err == nil {
		t.Error("a login inside a member name should be refused")
	}
}

func TestRecordScrubPatterns(t *testing.T) {
	scrubbed := scrubLike(rawOrg, nil)
	var org map[string]any
	if err := json.Unmarshal([]byte(scrubbed), &org); err != nil {
		t.Fatalf("scrubbed JSON does not parse: %v\n%s", err, scrubbed)
	}
	for _, key := range []string{"description", "name", "company", "blog", "location", "twitter_username"} {
		if org[key] != nil {
			t.Errorf("%s = %v, want null", key, org[key])
		}
	}
	if org["login"] != kitOrg || org["two_factor_requirement_enabled"] != true {
		t.Errorf("the scrub changed values the collector reads: %v", org)
	}

	var members struct {
		Data struct {
			Organization struct {
				MembersWithRole struct {
					Nodes []map[string]any
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(scrubLike(rawGraphQLMembers, nil)), &members); err != nil {
		t.Fatal(err)
	}
	nodes := members.Data.Organization.MembersWithRole.Nodes
	if nodes[0]["name"] != placeholderName || nodes[1]["name"] != nil {
		t.Errorf("display names = %v and %v, want the placeholder and null", nodes[0]["name"], nodes[1]["name"])
	}

	var repo map[string]any
	if err := json.Unmarshal([]byte(scrubLike(rawRepo, nil)), &repo); err != nil {
		t.Fatal(err)
	}
	if repo["description"] == nil || repo["name"] != "classic-protected" {
		t.Errorf("the scrub changed the repository: %v", repo)
	}
	if !strings.Contains(scrubLike(rawAnalysis, nil), zeroSHA) {
		t.Error("the commit SHA should be zeroed")
	}
}

func TestUnscrubbedFindsEachLeak(t *testing.T) {
	sc := rawScenario()
	raw := recordingJSON(t, sc)
	problems, err := unscrubbed(raw)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	for _, what := range []string{
		"is a GitHub ID", "is a node ID", "is a login", "is an App client ID", "is an App slug", "is a pagination cursor",
		"holds a pagination cursor", "is profile text", "is an avatar hash", "is a profile's display name",
		"is an account's description", "is a member's display name", "holds a git object ID", "holds a GitHub ID in a URL",
	} {
		if !strings.Contains(joined, what) {
			t.Errorf("no problem says %q:\n%s", what, joined)
		}
	}
	for _, secret := range []string{"147464937", "sandbox-owner-account", "Pat Example"} {
		if strings.Contains(joined, secret) {
			t.Errorf("a problem names the value %q", secret)
		}
	}

	found, err := tenantIdentifiers(sc, kitKnown)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range sc.Responses {
		sc.Responses[i].Body = scrubLike(r.Body, found)
		for name, values := range r.Header {
			for j, v := range values {
				sc.Responses[i].Header[name][j] = scrubLike(v, found)
			}
		}
	}
	problems, err = unscrubbed(recordingJSON(t, sc))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Errorf("a scrubbed recording still holds:\n%s", strings.Join(problems, "\n"))
	}
}

// recordingJSON writes responses as a recording file holds them.
func recordingJSON(t *testing.T, sc collectortest.Scenario) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"name": "test", "responses": sc.Responses})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestRecordingsScrubbed fails while a committed recording holds what the
// record test removes.
func TestRecordingsScrubbed(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "recordings", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		problems, err := unscrubbed(raw)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, p := range problems {
			t.Errorf("%s: %s", path, p)
		}
	}
}
