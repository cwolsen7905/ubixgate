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
	"github.com/ubixsys/ubixgate/test/fakes"
)

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
      tools: [status, env_has]
`

func start(t *testing.T, ticketVersions []string) *env {
	t.Helper()
	e := &env{idp: fakes.NewIdP(), vault: fakes.NewVault(),
		tickets: &fakes.Tickets{Token: "svc-secret-1", Identity: "svc-tickets", Versions: ticketVersions}}
	t.Cleanup(e.idp.Server.Close)
	t.Cleanup(e.vault.Server.Close)
	e.vault.Put("secret/data/mcp/tickets", map[string]any{"token": "svc-secret-1"})
	e.vault.Put("secret/data/mcp/stdio", map[string]any{"token": "stdio-secret-1"})
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
  - name: stdio
    transport: stdio
    command: [%q]
    env: { %s: "1" }
    credential: { path: secret/data/mcp/stdio, field: token, env: STDIO_TOKEN }
audit: { sink: file, path: %s }
`, e.url, e.idp.Issuer, e.idp.JWKSURL(), e.vault.Server.URL, write("role", e.vault.RoleID),
		write("secret", e.vault.SecretID), up.URL, exe, stdioEnv, e.audit) + policyYAML
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
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
	c := mcp.NewClient(&mcp.Implementation{Name: "integration-test", Version: "1"}, nil)
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
			wantAlice := []string{"stdio__env_has", "stdio__status", "tickets__ticket_create", "tickets__ticket_delete", "tickets__ticket_list"}
			if got := toolNames(t, alice); !slices.Equal(got, wantAlice) {
				t.Errorf("alice sees %v, want %v", got, wantAlice)
			}
			if got := toolNames(t, bob); !slices.Equal(got, []string{"stdio__env_has", "stdio__status"}) {
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
