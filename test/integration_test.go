// Package test holds the end-to-end tests: a real gateway, built from a YAML config,
// in front of an in-process fake IdP, fake Vault and fake upstreams over both
// transports. No Docker and no network beyond loopback.
package test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ubixsys/ubixgate/internal/audit"
	"github.com/ubixsys/ubixgate/internal/config"
	"github.com/ubixsys/ubixgate/internal/gateway"
	"github.com/ubixsys/ubixgate/internal/policy"
	"github.com/ubixsys/ubixgate/test/fakes"
)

const chainKey = "integration-test-chain-key-32-bytes!"

// The stdio upstream is this test binary, started again with this variable set.
const stdioEnv = "UBIXGATE_FAKE_STDIO"

func TestMain(m *testing.M) {
	if os.Getenv(stdioEnv) == "1" {
		if err := fakes.ServeStdio(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type env struct {
	url     string
	idp     *fakes.IdP
	vault   *fakes.Vault
	tickets *fakes.Tickets
	audit   string
	cfg     *config.Config
}

const policyYAML = `
policy:
  rules:
    - name: contractors-no-writes
      effect: deny
      when: { groups: [contractors] }
      server: "*"
      tools: ["*_create", "*_delete"]
    - name: devs-tickets-own-project
      effect: allow
      when: { groups: [developers] }
      server: tickets
      tools: ["*"]
      args: { project: "myorg/*" }
      audit_args: [project]
    - name: everyone-reads-stdio
      effect: allow
      when: { groups: [developers, contractors] }
      server: stdio
      tools: [status, env_has, ask]
    - name: personal-tickets
      effect: allow
      when: { groups: [personal] }
      server: mine
      tools: ["*"]
    - name: alice-confirms-closes
      effect: allow
      when: { users: [alice@example.com] }
      server: tickets
      tools: [ticket_close]
      client_requests: [elicitation]
`

func start(t *testing.T, ticketVersions []string) *env {
	t.Helper()
	e := &env{idp: fakes.NewIdP(), vault: fakes.NewVault(),
		tickets: &fakes.Tickets{Token: "svc-secret-1", Identity: "svc-tickets", Versions: ticketVersions,
			Users: map[string]string{"Bearer carol-own-token": "carol"}}}
	t.Cleanup(e.idp.Server.Close)
	t.Cleanup(e.vault.Server.Close)
	e.vault.Put("secret/data/mcp/tickets", map[string]any{"token": "svc-secret-1"})
	e.vault.Put("secret/data/mcp/stdio", map[string]any{"token": "stdio-secret-1"})
	e.vault.Put("secret/data/mcp/mine/carol@example.com", map[string]any{"token": "carol-own-token"})
	e.vault.Put("secret/data/mcp/shared@example.com", map[string]any{"token": "svc-secret-1"})
	up := httptest.NewServer(e.tickets.Handler())
	t.Cleanup(up.Close)

	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gw := httptest.NewUnstartedServer(nil)
	e.url = "http://" + gw.Listener.Addr().String() + "/mcp"
	e.audit = filepath.Join(dir, "audit.jsonl")
	exe, _ := os.Executable()
	cfgYAML := fmt.Sprintf(`
public_url: %s
identity:
  mode: jwt
  issuer: %s
  jwks_url: %s
  claims: { user: email }
vault:
  address: %s
  auth: { method: approle, role_id_file: %s, secret_id_file: %s }
upstreams:
  - name: tickets
    transport: http
    url: %s/mcp
    credential: { path: secret/data/mcp/tickets, field: token, format: "Bearer {value}" }
  - name: mine
    transport: http
    url: %s/mcp
    credential: { path: "secret/data/mcp/mine/{user}", catalog_path: secret/data/mcp/tickets, field: token, format: "Bearer {value}" }
  - name: stdio
    transport: stdio
    command: [%q]
    env: { %s: "1" }
    credential: { path: secret/data/mcp/stdio, field: token, env: STDIO_TOKEN }
audit: { sink: file, path: %s, chain_key_file: %s }
`, e.url, e.idp.Issuer, e.idp.JWKSURL(), e.vault.Server.URL, write("role", e.vault.RoleID),
		write("secret", e.vault.SecretID), up.URL, up.URL, exe, stdioEnv, e.audit, write("chain", chainKey)) + policyYAML
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rt, err := gateway.Build(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	rt.Start(ctx)
	gw.Config.Handler = rt.Handler
	gw.Start()
	t.Cleanup(gw.Close)

	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(strings.TrimSuffix(e.url, "/mcp") + "/readyz")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("gateway not ready: %s", b)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return e
}

func (e *env) token(user string, groups ...string) string {
	return e.idp.Mint(e.idp.Claims(user, e.url, groups, "test-client"))
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func (e *env) connect(t *testing.T, token, protocol string) *mcp.ClientSession {
	t.Helper()
	return e.connectWith(t, token, protocol, nil)
}

func (e *env) connectWith(t *testing.T, token, protocol string, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "integration-test", Version: "1"}, opts)
	s, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: e.url,
		HTTPClient: &http.Client{Transport: bearer{token}}, DisableStandaloneSSE: true},
		&mcp.ClientSessionOptions{ProtocolVersion: protocol})
	if err != nil {
		t.Fatalf("connect (%s): %v", protocol, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func toolNames(t *testing.T, s *mcp.ClientSession) []string {
	t.Helper()
	res, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

func call(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	var text []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text = append(text, tc.Text)
		}
	}
	return strings.Join(text, "\n"), res.IsError
}

func readAudit(t *testing.T, path string) []audit.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []audit.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad audit line %q: %v", sc.Text(), err)
		}
		recs = append(recs, r)
	}
	return recs
}

func TestGateway(t *testing.T) {
	for _, tc := range []struct{ client, upstream string }{
		{"2026-07-28", "2026-07-28"},
		{"2025-11-25", "2026-07-28"},
		{"2026-07-28", "2025-11-25"},
	} {
		t.Run("client "+tc.client+" tickets "+tc.upstream, func(t *testing.T) {
			e := start(t, []string{tc.upstream})
			aliceTok := e.token("alice", "developers")
			alice := e.connect(t, aliceTok, tc.client)
			bob := e.connect(t, e.token("bob", "contractors"), tc.client)
			if got := alice.InitializeResult().ProtocolVersion; got != tc.client {
				t.Fatalf("negotiated %s with the gateway, want %s", got, tc.client)
			}

			// 1. Each caller sees only the tools policy lets them call.
			wantAlice := []string{"stdio__ask", "stdio__env_has", "stdio__status", "tickets__ticket_close", "tickets__ticket_create", "tickets__ticket_delete", "tickets__ticket_list"}
			if got := toolNames(t, alice); !slices.Equal(got, wantAlice) {
				t.Errorf("alice sees %v, want %v", got, wantAlice)
			}
			if got := toolNames(t, bob); !slices.Equal(got, []string{"stdio__ask", "stdio__env_has", "stdio__status"}) {
				t.Errorf("bob sees %v", got)
			}

			// 2. An allowed HTTP call succeeds with the injected service credential, and
			// the caller's own token never reaches the upstream.
			text, isErr := call(t, alice, "tickets__ticket_create", map[string]any{"project": "myorg/web", "title": "fix login"})
			if isErr || !strings.Contains(text, "authenticated as svc-tickets") {
				t.Errorf("create: %q (error=%v)", text, isErr)
			}
			if e.tickets.SawHeaderValue(aliceTok) {
				t.Error("the client's token was forwarded to the upstream")
			}

			// 3. The stdio upstream got its credential in its environment at spawn.
			text, _ = call(t, alice, "stdio__env_has", map[string]any{"name": "STDIO_TOKEN", "value": "stdio-secret-1"})
			if !strings.Contains(text, "match=true") {
				t.Errorf("stdio credential: %q", text)
			}
			text, _ = call(t, alice, "stdio__env_has", map[string]any{"name": stdioEnv + "_NOT_SET", "value": ""})
			if !strings.Contains(text, "set=false") {
				t.Errorf("unexpected env: %q", text)
			}

			// 4. Denials name the deciding rule.
			text, isErr = call(t, bob, "tickets__ticket_delete", map[string]any{"project": "myorg/web", "id": 1})
			if !isErr || text != "denied by rule contractors-no-writes" {
				t.Errorf("bob delete: %q", text)
			}
			text, isErr = call(t, alice, "tickets__ticket_delete", map[string]any{"project": "other/repo", "id": 1})
			if !isErr || text != "denied by rule default-deny" {
				t.Errorf("alice delete other/repo: %q", text)
			}
			// An unknown tool is denied the way a hidden one would be.
			text, _ = call(t, bob, "tickets__no_such_tool", nil)
			if text != "denied by rule default-deny" {
				t.Errorf("unknown tool: %q", text)
			}

			// 5. One audit line per call, with the decision, rule and redacted args.
			recs := readAudit(t, e.audit)
			if len(recs) != 6 {
				t.Fatalf("%d audit records for 6 calls", len(recs))
			}
			want := []struct{ user, tool, decision, rule, status string }{
				{"alice@example.com", "tickets__ticket_create", "allow", "devs-tickets-own-project", "ok"},
				{"alice@example.com", "stdio__env_has", "allow", "everyone-reads-stdio", "ok"},
				{"alice@example.com", "stdio__env_has", "allow", "everyone-reads-stdio", "ok"},
				{"bob@example.com", "tickets__ticket_delete", "deny", "contractors-no-writes", "denied"},
				{"alice@example.com", "tickets__ticket_delete", "deny", "default-deny", "denied"},
				{"bob@example.com", "tickets__no_such_tool", "deny", "unknown-tool", "denied"},
			}
			ids := map[string]bool{}
			for i, w := range want {
				r := recs[i]
				if r.User != w.user || r.Tool != w.tool || r.Decision != w.decision || r.Rule != w.rule || r.Status != w.status {
					t.Errorf("record %d = %+v, want %+v", i, r, w)
				}
				if r.RequestID == "" || ids[r.RequestID] || r.Client != "test-client" {
					t.Errorf("record %d: request id %q, client %q", i, r.RequestID, r.Client)
				}
				ids[r.RequestID] = true
			}
			if a := recs[0].Args; a["project"] != "myorg/web" || a["title"] != audit.Redacted {
				t.Errorf("args not redacted by policy: %v", a)
			}
			if a := recs[1].Args; a["value"] != audit.Redacted {
				t.Errorf("argument values must be redacted unless the rule keeps them: %v", a)
			}
			// The gateway chains every record (audit.chain_key_file).
			f, _ := os.Open(e.audit)
			defer f.Close()
			if n, _, err := audit.Verify(f, []byte(chainKey)); err != nil || n != 6 {
				t.Errorf("audit chain: %d records, %v", n, err)
			}
		})
	}
}

func TestCredentialRotationAndVaultOutage(t *testing.T) {
	e := start(t, nil)
	alice := e.connect(t, e.token("alice", "developers"), "")
	args := map[string]any{"project": "myorg/web"}
	if text, isErr := call(t, alice, "tickets__ticket_list", args); isErr {
		t.Fatalf("list: %s", text)
	}

	// Rotate the service token in Vault and at the upstream. The gateway's cached copy
	// is now wrong: the upstream answers 401, the gateway drops the entry, reads Vault
	// again and retries once.
	e.vault.Put("secret/data/mcp/tickets", map[string]any{"token": "svc-secret-2"})
	e.tickets.SetToken("svc-secret-2")
	if text, isErr := call(t, alice, "tickets__ticket_list", args); isErr {
		t.Fatalf("after rotation: %s", text)
	}
	if e.tickets.Refused() == 0 {
		t.Error("expected the stale credential to be refused once")
	}

	// Vault down and the upstream rotating again: the call fails as an upstream error
	// with the reason recorded, not a hang or a crash.
	e.vault.SetDown(true)
	e.tickets.SetToken("svc-secret-3")
	text, isErr := call(t, alice, "tickets__ticket_list", args)
	if !isErr || !strings.Contains(text, "credential unavailable") {
		t.Errorf("vault down: %q", text)
	}
	recs := readAudit(t, e.audit)
	last := recs[len(recs)-1]
	if last.Status != audit.StatusUpstreamError || last.Reason != "credential_unavailable" {
		t.Errorf("last record = %+v", last)
	}
}

func TestAuthentication(t *testing.T) {
	e := start(t, nil)
	post := func(token string) (int, http.Header) {
		req, _ := http.NewRequest(http.MethodPost, e.url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	wrongAud := e.idp.Mint(e.idp.Claims("alice", "https://other.example.com/mcp", []string{"developers"}, ""))
	for name, tok := range map[string]string{"no token": "", "garbage": "abc", "wrong audience": wrongAud} {
		code, hdr := post(tok)
		if code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, code)
		}
		if h := hdr.Get("WWW-Authenticate"); !strings.Contains(h, `resource_metadata="`) ||
			!strings.Contains(h, "/.well-known/oauth-protected-resource/mcp") {
			t.Errorf("%s: WWW-Authenticate = %q", name, h)
		}
	}
	// No audit record for requests that never authenticated: there is no caller to name.
	if b, _ := os.ReadFile(e.audit); len(b) != 0 {
		t.Errorf("audit log should be empty, got %s", b)
	}
	resp, err := http.Get(strings.TrimSuffix(e.url, "/mcp") + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&meta)
	resp.Body.Close()
	if meta["resource"] != e.url {
		t.Errorf("metadata resource = %v, want %s", meta["resource"], e.url)
	}
}

// An upstream's request to the caller's client (here an elicitation) goes back to that
// caller only when a rule allows it, is audited as its own record, and the upstream's
// state can be continued only by the same user, with answers to the requests asked.
func TestClientRequests(t *testing.T) {
	e := start(t, nil)
	accept := &mcp.ClientOptions{ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{}}, nil
	}}
	manual := &mcp.ClientOptions{ElicitationHandler: accept.ElicitationHandler,
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}}
	aliceTok, carolTok := e.token("alice", "developers"), e.token("carol", "developers")
	args := map[string]any{"project": "myorg/web"}

	// 1. Allowed: the SDK client answers and retries; the upstream gets its own state back.
	alice := e.connectWith(t, aliceTok, "2026-07-28", accept)
	text, isErr := call(t, alice, "tickets__ticket_close", args)
	if isErr || text != "closed in myorg/web: answer accept, state state-for-myorg/web" {
		t.Fatalf("allowed elicitation: %q (error=%v)", text, isErr)
	}

	// 2. No rule allows carol's elicitation: the call fails naming the rule.
	carol := e.connectWith(t, carolTok, "2026-07-28", accept)
	if text, isErr := call(t, carol, "tickets__ticket_close", args); !isErr || text != "denied by rule default-deny" {
		t.Errorf("denied elicitation: %q", text)
	}

	// 3. A 2025-11-25 client cannot receive the request in this stateless gateway.
	old := e.connectWith(t, aliceTok, "2025-11-25", accept)
	if text, isErr := call(t, old, "tickets__ticket_close", args); !isErr || !strings.Contains(text, "requires MCP 2026-07-28") {
		t.Errorf("old client: %q", text)
	}

	// 4. The sealed state works only for its user, with answers to the requests asked.
	aliceM := e.connectWith(t, aliceTok, "2026-07-28", manual)
	res, err := aliceM.CallTool(context.Background(), &mcp.CallToolParams{Name: "tickets__ticket_close", Arguments: args})
	if err != nil || !res.NeedsInput() || res.RequestState == "" || strings.Contains(res.RequestState, "state-for") {
		t.Fatalf("first round: %+v, %v", res, err)
	}
	carolM := e.connectWith(t, carolTok, "2026-07-28", manual)
	yes := mcp.InputResponseMap{"confirm": &mcp.ElicitResult{Action: "accept"}}
	for name, tc := range map[string]struct {
		s     *mcp.ClientSession
		state string
		ans   mcp.InputResponseMap
	}{
		"another user":      {carolM, res.RequestState, yes},
		"tampered":          {aliceM, res.RequestState + "x", yes},
		"forged":            {aliceM, "e30.AAAA", yes},
		"answers, no state": {aliceM, "", yes},
		"unasked answer":    {aliceM, res.RequestState, mcp.InputResponseMap{"other": &mcp.ElicitResult{Action: "accept"}}},
	} {
		r, err := tc.s.CallTool(context.Background(), &mcp.CallToolParams{Name: "tickets__ticket_close", Arguments: args,
			RequestState: tc.state, InputResponses: tc.ans})
		if err != nil || !r.IsError || r.Content[0].(*mcp.TextContent).Text != "denied by rule invalid-request-state" {
			t.Errorf("%s: %+v, %v", name, r, err)
		}
	}

	// 5. A 2025-11-25 upstream shares one connection among callers, so the gateway
	// declares no client capabilities there and its requests are refused.
	if text, _ := call(t, alice, "stdio__ask", nil); text != "elicit error: client does not support elicitation" {
		t.Errorf("stdio elicitation: %q", text)
	}

	// 6. The audit log: each client request is its own record, after its call's.
	type row struct{ user, kind, decision, rule, status string }
	var got []row
	for _, r := range readAudit(t, e.audit)[:7] {
		got = append(got, row{strings.TrimSuffix(r.User, "@example.com"), r.ClientRequest, r.Decision, r.Rule, r.Status})
	}
	want := []row{
		{"alice", "elicitation", "allow", "alice-confirms-closes", "ok"},
		{"alice", "", "allow", "devs-tickets-own-project", "input_required"},
		{"alice", "", "allow", "devs-tickets-own-project", "ok"},
		{"carol", "elicitation", "deny", "default-deny", "denied"},
		{"carol", "", "deny", "default-deny", "denied"},
		{"alice", "elicitation", "allow", "alice-confirms-closes", "not_sent"},
		{"alice", "", "allow", "devs-tickets-own-project", "not_sent"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit:\n got %v\nwant %v", got, want)
	}
}

// When one request in a result is denied, none is sent, and the allowed ones are
// recorded as not sent rather than ok.
func TestClientRequestsMixed(t *testing.T) {
	e := start(t, nil)
	alice := e.connectWith(t, e.token("alice", "developers"), "2026-07-28", &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept"}, nil
		}})
	text, isErr := call(t, alice, "tickets__ticket_close", map[string]any{"project": "myorg/web", "title": "and summarize"})
	if !isErr || text != "denied by rule default-deny" {
		t.Fatalf("mixed: %q", text)
	}
	var got []string
	for _, r := range readAudit(t, e.audit) {
		got = append(got, fmt.Sprintf("%s %s %s %s %s", r.ClientRequest, r.Decision, r.Rule, r.Status, r.Reason))
	}
	want := []string{
		"elicitation allow alice-confirms-closes not_sent client_request_denied",
		"sampling deny default-deny denied ",
		" deny default-deny denied client_request_denied",
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit:\n got %q\nwant %q", got, want)
	}
}

// A per-user credential: each caller's calls carry their own token, a caller without
// one is refused, and the shared catalog credential is never used for a call.
func TestPerUserCredentials(t *testing.T) {
	e := start(t, nil)
	args := map[string]any{"project": "myorg/web"}
	carol := e.connect(t, e.token("carol", "personal"), "")
	if text, isErr := call(t, carol, "mine__ticket_list", args); isErr || !strings.HasPrefix(text, "authenticated as carol:") {
		t.Errorf("carol: %q", text)
	}
	// dave has no secret of his own; "../shared" would reach another secret if the
	// user name were put in the path unchecked.
	for _, user := range []string{"dave", "../shared"} {
		s := e.connect(t, e.token(user, "personal"), "")
		if text, isErr := call(t, s, "mine__ticket_list", args); !isErr || text != "upstream error: credential unavailable" {
			t.Errorf("%s: %q", user, text)
		}
	}
	if got := e.tickets.Calls(); !slices.Equal(got, []string{"carol"}) {
		t.Errorf("the upstream ran calls as %v, want only carol's", got)
	}
	var got []string
	for _, r := range readAudit(t, e.audit) {
		got = append(got, r.Status+"/"+r.Reason)
	}
	want := []string{"ok/", "denied/credential_unavailable", "denied/credential_unavailable"}
	if !slices.Equal(got, want) {
		t.Errorf("audit = %v, want %v", got, want)
	}
}

// policy explain gives the decision the live gateway made, for the same calls, because
// both run gateway.Decide over the same rules.
func TestExplainMatchesGateway(t *testing.T) {
	e := start(t, nil)
	alice := e.connect(t, e.token("alice", "developers"), "")
	bob := e.connect(t, e.token("bob", "contractors"), "")
	calls := []struct {
		s     *mcp.ClientSession
		p     policy.Principal
		tool  string
		args  map[string]any
		known bool
	}{
		{alice, policy.Principal{User: "alice@example.com", Groups: []string{"developers"}}, "tickets__ticket_create", map[string]any{"project": "myorg/web"}, true},
		{alice, policy.Principal{User: "alice@example.com", Groups: []string{"developers"}}, "tickets__ticket_delete", map[string]any{"project": "other/x"}, true},
		{bob, policy.Principal{User: "bob@example.com", Groups: []string{"contractors"}}, "tickets__ticket_delete", map[string]any{"project": "myorg/web"}, true},
		{bob, policy.Principal{User: "bob@example.com", Groups: []string{"contractors"}}, "tickets__no_such_tool", nil, false},
	}
	pol, err := gateway.Policy(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range calls {
		call(t, c.s, c.tool, c.args)
	}
	recs := readAudit(t, e.audit)
	for i, c := range calls {
		server, tool, _ := strings.Cut(c.tool, gateway.Sep)
		dec, _ := gateway.Decide(context.Background(), pol, policy.Request{Principal: c.p, Server: server, Tool: tool, Args: c.args}, c.known)
		if dec.Rule != recs[i].Rule || string(dec.Effect) != recs[i].Decision {
			t.Errorf("%s: explain says %s by %s, the gateway %s by %s", c.tool, dec.Effect, dec.Rule, recs[i].Decision, recs[i].Rule)
		}
	}
}
