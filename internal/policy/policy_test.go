package policy

import (
	"context"
	"strings"
	"testing"
)

var servers = []string{"tickets", "shepherd"}

// The rules from the README's example policy, plus a few that exercise single fields.
func exampleRules(t *testing.T) *Rules {
	t.Helper()
	r, err := New([]Rule{
		{Name: "contractors-no-writes", Effect: Deny, When: When{Groups: []string{"contractors"}},
			Server: "*", Tools: []string{"*_create", "*_delete", "lane_open"}},
		{Name: "devs-read-shepherd", Effect: Allow, When: When{Groups: []string{"developers", "contractors"}},
			Server: "shepherd", Tools: []string{"shepherd_status", "lane_list"}},
		{Name: "devs-tickets-own-project", Effect: Allow,
			When:   When{Groups: []string{"developers"}, Clients: []string{"claude-code", "cursor"}},
			Server: "tickets", Tools: []string{"*"}, Args: map[string]string{"project": "myorg/*"},
			AuditArgs: []string{"project"}},
		{Name: "carol-anything", Effect: Allow, When: When{Users: []string{"carol"}},
			Server: "*", Tools: []string{"*"}},
		{Name: "no-shepherd-deletes-for-anyone", Effect: Deny, Server: "shepherd", Tools: []string{"*_delete"}},
	}, servers)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var (
	alice = Principal{User: "alice", Groups: []string{"developers"}, Client: "claude-code"}
	bob   = Principal{User: "bob", Groups: []string{"contractors"}, Client: "cursor"}
	carol = Principal{User: "carol", Client: "custom"}
	dave  = Principal{User: "dave", Groups: []string{"developers"}, Client: "opencode"}
	eve   = Principal{User: "eve"}
)

func TestDecide(t *testing.T) {
	r := exampleRules(t)
	proj := func(p string) map[string]any { return map[string]any{"project": p} }
	cases := []struct {
		name   string
		p      Principal
		server string
		tool   string
		args   map[string]any
		want   Effect
		rule   string
	}{
		{"group and client and args match", alice, "tickets", "ticket_create", proj("myorg/web"), Allow, "devs-tickets-own-project"},
		{"arg glob fails", alice, "tickets", "ticket_create", proj("other/repo"), Deny, DefaultDeny},
		{"arg missing", alice, "tickets", "ticket_create", nil, Deny, DefaultDeny},
		{"arg not a string", alice, "tickets", "ticket_create", map[string]any{"project": 7}, Deny, DefaultDeny},
		{"star does not cross a slash", alice, "tickets", "ticket_create", proj("myorg/web/../../other"), Deny, DefaultDeny},
		// The documented limit: the glob sees the raw string, so "myorg/.." matches
		// "myorg/*" even though an upstream might resolve it to something else.
		{"traversal segment still matches the raw glob", alice, "tickets", "ticket_create", proj("myorg/.."), Allow, "devs-tickets-own-project"},
		{"client not listed", dave, "tickets", "ticket_list", proj("myorg/web"), Deny, DefaultDeny},
		{"deny wins over a later allow", bob, "tickets", "ticket_delete", proj("myorg/web"), Deny, "contractors-no-writes"},
		{"deny wins over an allow listed first", bob, "shepherd", "lane_open", nil, Deny, "contractors-no-writes"},
		{"group any-of", bob, "shepherd", "lane_list", nil, Allow, "devs-read-shepherd"},
		{"tool not listed", bob, "shepherd", "run_list", nil, Deny, DefaultDeny},
		{"user match", carol, "tickets", "ticket_delete", nil, Allow, "carol-anything"},
		{"deny without when applies to everyone", carol, "shepherd", "lane_delete", nil, Deny, "no-shepherd-deletes-for-anyone"},
		{"nobody matches", eve, "shepherd", "shepherd_status", nil, Deny, DefaultDeny},
		{"server must match", alice, "shepherd", "ticket_create", proj("myorg/web"), Deny, DefaultDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := r.Decide(context.Background(), Request{Principal: c.p, Server: c.server, Tool: c.tool, Args: c.args})
			if err != nil {
				t.Fatal(err)
			}
			if d.Effect != c.want || d.Rule != c.rule {
				t.Errorf("got %s by %q, want %s by %q", d.Effect, d.Rule, c.want, c.rule)
			}
			if d.Allowed() != (c.want == Allow) {
				t.Errorf("Allowed() = %v", d.Allowed())
			}
		})
	}
}

func TestDecideAuditArgs(t *testing.T) {
	r := exampleRules(t)
	d, _ := r.Decide(context.Background(), Request{Principal: alice, Server: "tickets", Tool: "ticket_list",
		Args: map[string]any{"project": "myorg/web", "title": "secret"}})
	if len(d.AuditArgs) != 1 || d.AuditArgs[0] != "project" {
		t.Errorf("AuditArgs = %v, want [project]", d.AuditArgs)
	}
	d, _ = r.Decide(context.Background(), Request{Principal: bob, Server: "tickets", Tool: "ticket_delete"})
	if d.AuditArgs != nil {
		t.Errorf("a deny keeps no argument values, got %v", d.AuditArgs)
	}
}

func TestVisible(t *testing.T) {
	r := exampleRules(t)
	cases := []struct {
		p      Principal
		server string
		tool   string
		want   bool
	}{
		// Listed although some argument values will be denied at call time.
		{alice, "tickets", "ticket_create", true},
		{alice, "shepherd", "lane_list", true},
		{alice, "shepherd", "run_list", false},
		{dave, "tickets", "ticket_list", false}, // client not allowed
		{bob, "tickets", "ticket_list", false},
		{bob, "shepherd", "lane_list", true},
		{bob, "shepherd", "lane_open", false}, // allowed by name, but a deny without args hides it
		{carol, "tickets", "anything", true},
		{carol, "shepherd", "lane_delete", false},
		{eve, "shepherd", "shepherd_status", false},
	}
	for _, c := range cases {
		if got := r.Visible(c.p, c.server, c.tool); got != c.want {
			t.Errorf("Visible(%s, %s__%s) = %v, want %v", c.p.User, c.server, c.tool, got, c.want)
		}
	}
}

// A deny rule with argument constraints does not hide a tool: it only denies some calls.
func TestVisibleDenyWithArgs(t *testing.T) {
	r, err := New([]Rule{
		{Name: "no-prod", Effect: Deny, Server: "*", Tools: []string{"*"}, Args: map[string]string{"env": "prod"}},
		{Name: "all", Effect: Allow, Server: "*", Tools: []string{"*"}},
	}, servers)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Visible(eve, "tickets", "deploy") {
		t.Error("tool should be listed")
	}
	d, _ := r.Decide(context.Background(), Request{Principal: eve, Server: "tickets", Tool: "deploy", Args: map[string]any{"env": "prod"}})
	if d.Rule != "no-prod" {
		t.Errorf("got %q, want no-prod", d.Rule)
	}
}

func TestEmptyPolicyDeniesEverything(t *testing.T) {
	r, err := New(nil, servers)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := r.Decide(context.Background(), Request{Principal: carol, Server: "tickets", Tool: "x"})
	if d.Allowed() || d.Rule != DefaultDeny || r.Visible(carol, "tickets", "x") {
		t.Errorf("empty policy must deny and hide: %+v", d)
	}
}

func TestNewRejects(t *testing.T) {
	ok := Rule{Name: "ok", Effect: Allow, Server: "*", Tools: []string{"*"}}
	with := func(f func(*Rule)) Rule { r := ok; f(&r); return r }
	cases := []struct {
		name  string
		rules []Rule
		want  string
	}{
		{"no name", []Rule{with(func(r *Rule) { r.Name = "" })}, "name is required"},
		{"reserved name", []Rule{with(func(r *Rule) { r.Name = DefaultDeny })}, "reserved"},
		{"reserved unknown-tool", []Rule{with(func(r *Rule) { r.Name = UnknownTool })}, "reserved"},
		{"duplicate", []Rule{ok, ok}, "earlier rule"},
		{"bad effect", []Rule{with(func(r *Rule) { r.Effect = "maybe" })}, "effect must be"},
		{"no server", []Rule{with(func(r *Rule) { r.Server = "" })}, "server is required"},
		{"unknown server", []Rule{with(func(r *Rule) { r.Server = "jira" })}, "matches no configured upstream"},
		{"bad server glob", []Rule{with(func(r *Rule) { r.Server = "[" })}, "not a valid glob"},
		{"no tools", []Rule{with(func(r *Rule) { r.Tools = nil })}, "tools is required"},
		{"bad tool glob", []Rule{with(func(r *Rule) { r.Tools = []string{"a["} })}, "not a valid glob"},
		{"bad arg glob", []Rule{with(func(r *Rule) { r.Args = map[string]string{"p": "[x"} })}, "args.p"},
		{"unknown client request", []Rule{with(func(r *Rule) { r.ClientRequests = []string{"telepathy"} })}, "client_requests"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.rules, servers)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// Client requests are decided by rules that name them, and only by those: a rule
// without client_requests never allows one, and a rule with them never decides a call.
func TestClientRequests(t *testing.T) {
	r, err := New([]Rule{
		{Name: "no-sampling-for-contractors", Effect: Deny, When: When{Groups: []string{"contractors"}},
			Server: "*", Tools: []string{"*"}, ClientRequests: []string{"sampling"}},
		{Name: "devs-call", Effect: Allow, When: When{Groups: []string{"developers", "contractors"}},
			Server: "tickets", Tools: []string{"*"}},
		{Name: "devs-elicit", Effect: Allow, When: When{Groups: []string{"developers", "contractors"}},
			Server: "tickets", Tools: []string{"ticket_close"}, ClientRequests: []string{"elicitation", "sampling"}},
	}, servers)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		p    Principal
		tool string
		kind string
		want string
	}{
		{"the call itself", alice, "ticket_close", "", "devs-call"},
		{"allowed elicitation", alice, "ticket_close", "elicitation", "devs-elicit"},
		{"kind not listed", alice, "ticket_close", "roots", DefaultDeny},
		{"tool not listed", alice, "ticket_list", "elicitation", DefaultDeny},
		{"deny rule for the kind", bob, "ticket_close", "sampling", "no-sampling-for-contractors"},
		{"deny rule for a kind does not deny the call", bob, "ticket_close", "", "devs-call"},
		{"nobody", eve, "ticket_close", "elicitation", DefaultDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := r.Decide(context.Background(), Request{Principal: c.p, Server: "tickets", Tool: c.tool, ClientRequest: c.kind})
			if err != nil || d.Rule != c.want {
				t.Errorf("rule = %q (err %v), want %q", d.Rule, err, c.want)
			}
		})
	}
	// A rule about client requests neither lists a tool nor hides one.
	if !r.Visible(bob, "tickets", "ticket_close") || r.Visible(eve, "tickets", "ticket_close") {
		t.Error("client request rules changed the listing")
	}
}
