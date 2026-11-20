package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ubixsys/ubixgate/internal/policy"
)

func load(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseFull(t *testing.T) {
	c, err := Parse(load(t))
	if err != nil {
		t.Fatal(err)
	}
	tk := c.Upstream("tickets")
	if tk == nil || tk.Credential.Header != "Authorization" || tk.Credential.TTL != 30*time.Second || tk.Timeout != time.Minute {
		t.Errorf("tickets defaults: %+v %+v", tk, tk.Credential)
	}
	if c.Vault.Auth.Mount != "approle" {
		t.Errorf("mount default = %q", c.Vault.Auth.Mount)
	}
	if r := c.Policy.Rules[1]; r.Effect != policy.Allow || r.Args["project"] != "myorg/*" || r.When.Clients[0] != "claude-code" {
		t.Errorf("rule = %+v", r)
	}
	src := strings.Replace(string(load(t)), "path: secret/data/mcp/tickets", "path: m/{user}\n      catalog_path: m/shared", 1)
	if pc, err := Parse([]byte(src)); err != nil || !pc.Upstream("tickets").Credential.PerUser() {
		t.Errorf("per-user credential: %v", err)
	}
	if c.Identity.Claims.User != "email" {
		t.Errorf("claims = %+v", c.Identity.Claims)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"unknown key", "listen:", "lisen:", "field lisen not found"},
		{"no public url", "public_url: https://mcp.example.com/mcp", "public_url: ''", "public_url"},
		{"bad mode", "mode: jwt", "mode: magic", "identity.mode"},
		{"static off loopback", "mode: jwt", "mode: static\n  tokens: [{token: dev-token-0123456789, user: a}]\n  # ", "loopback"},
		{"vault missing", "vault:\n  address: http://ubixvault:8200\n  auth: { method: approle, role_id_file: /run/role_id, secret_id_file: /run/secret_id }", "", "vault is required"},
		{"bad upstream name", "name: tickets", "name: Tickets__x", "name must be"},
		{"double dash name is fine but underscores are not", "name: shepherd", "name: shep_herd", "name must be"},
		{"stdio without command", "command: [shepherd, mcp]", "command: []", "needs a command"},
		{"format without value", `format: "Bearer {value}"`, `format: "Bearer"`, "must contain {value}"},
		{"policy names unknown server", "server: tickets", "server: jira", "matches no configured upstream"},
		{"bad sink", "sink: file", "sink: kafka", "audit.sink"},
		{"hash without key", "sink: file,", "hash_args: true, sink: file,", "hash_key_file"},
		{"chain on stdout", "sink: file, path: /var/log/ubixgate/audit.jsonl", "sink: stdout, chain_key_file: /run/k", "needs the file sink"},
		{"per-user without catalog", "path: secret/data/mcp/tickets", "path: secret/data/mcp/tickets/{user}", "needs catalog_path"},
		{"per-user catalog with user", "path: secret/data/mcp/tickets", "path: x/{user}\n      catalog_path: y/{user}", "needs catalog_path"},
		{"catalog without per-user", "path: secret/data/mcp/tickets", "path: x\n      catalog_path: y", "only for a per-user"},
		{"per-user on stdio", "env: { SHEPHERD_HOME: /data/shepherd }", "env: { SHEPHERD_HOME: /data/shepherd }\n    credential: { path: \"x/{user}\", catalog_path: y, field: t, env: T }", "needs an http upstream"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := string(load(t))
			if !strings.Contains(src, c.from) {
				t.Fatalf("fixture lacks %q", c.from)
			}
			_, err := Parse([]byte(strings.Replace(src, c.from, c.to, 1)))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestStaticOnLoopback(t *testing.T) {
	src := strings.Replace(string(load(t)), `listen: ":8080"`, `listen: "127.0.0.1:8080"`, 1)
	src = strings.Replace(src, "mode: jwt", "mode: static\n  tokens: [{token: dev-token-0123456789, user: a}]\n  #", 1)
	src = strings.Replace(src, "  issuer: https://idp.example.com\n", "", 1)
	src = strings.Replace(src, "  jwks_url: https://idp.example.com/jwks\n", "", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
}

func TestReportsEveryProblem(t *testing.T) {
	_, err := Parse([]byte("public_url: x\nidentity: {mode: none}\n"))
	if err == nil {
		t.Fatal("want errors")
	}
	for _, want := range []string{"public_url", "identity.mode", "at least one upstream"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
}
