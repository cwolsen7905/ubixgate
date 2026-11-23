package test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubixsys/ubixgate/internal/config"
	"github.com/ubixsys/ubixgate/internal/gateway"
	"github.com/ubixsys/ubixgate/internal/secrets"
	"github.com/ubixsys/ubixgate/test/fakes"
)

// TestHashiCorpVault runs the gateway's Vault client and the gateway itself against a
// real HashiCorp Vault. It needs a server prepared by bin/ci/hashicorp-vault.sh and is
// skipped without HCVAULT_ADDR, so `go test` needs no Docker.
//
// Environment: HCVAULT_ADDR, HCVAULT_ROLE_ID_FILE, HCVAULT_SECRET_ID_FILE, HCVAULT_ROOT
// (a root token, used only to check what the server holds), HCVAULT_KV_TOKEN (the value
// stored at secret/mcp/tickets), HCVAULT_DB_PATH (a database creds path).
func TestHashiCorpVault(t *testing.T) {
	addr := os.Getenv("HCVAULT_ADDR")
	if addr == "" {
		t.Skip("HCVAULT_ADDR not set: no HashiCorp Vault to test against")
	}
	cfg := config.Vault{Address: addr, Auth: config.VaultAuth{Method: "approle", Mount: "approle",
		RoleIDFile: os.Getenv("HCVAULT_ROLE_ID_FILE"), SecretIDFile: os.Getenv("HCVAULT_SECRET_ID_FILE")}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := secrets.New(cfg, nil, log)
	if err := c.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(ctx); err != nil {
		t.Fatalf("approle login: %v", err)
	}

	t.Run("kv2 read", func(t *testing.T) {
		s, err := c.Read(ctx, "secret/data/mcp/tickets")
		if err != nil || s.Data["token"] != os.Getenv("HCVAULT_KV_TOKEN") || s.LeaseID != "" {
			t.Fatalf("secret=%+v err=%v", s, err)
		}
		if _, err := c.Read(ctx, "secret/data/mcp/nothing"); err == nil {
			t.Fatal("a missing secret read without error")
		}
		if _, err := c.Read(ctx, "secret/data/other/private"); err == nil {
			t.Fatal("a path outside the policy was readable")
		}
	})

	t.Run("token renewal", func(t *testing.T) {
		// The role's token TTL is a few seconds, so KeepAlive renews it (at half the TTL)
		// several times; reads must keep working well past the original TTL.
		kctx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { c.KeepAlive(kctx); close(done) }()
		time.Sleep(12 * time.Second)
		if _, err := c.Read(ctx, "secret/data/mcp/tickets"); err != nil {
			t.Fatalf("read after the token's original TTL: %v", err)
		}
		stop()
		<-done
	})

	t.Run("dynamic lease and revoke", func(t *testing.T) {
		s, err := c.Read(ctx, os.Getenv("HCVAULT_DB_PATH"))
		if err != nil {
			t.Fatal(err)
		}
		if s.LeaseID == "" || s.Lease <= 0 || s.Data["username"] == nil || s.Data["password"] == nil {
			t.Fatalf("a database credential must carry its lease in the envelope: %+v", s)
		}
		if !leaseExists(t, addr, s.LeaseID) {
			t.Fatalf("lease %s is not known to Vault", s.LeaseID)
		}
		if err := c.Revoke(ctx, s.LeaseID); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		// Revocation runs the database's revocation statement; a revoked lease is gone.
		deadline := time.Now().Add(10 * time.Second)
		for leaseExists(t, addr, s.LeaseID) {
			if time.Now().After(deadline) {
				t.Fatal("the lease still exists after revoke")
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	t.Run("gateway injects the kv2 credential", func(t *testing.T) {
		idp := fakes.NewIdP()
		defer idp.Server.Close()
		tk := &fakes.Tickets{Token: os.Getenv("HCVAULT_KV_TOKEN"), Identity: "svc-tickets"}
		up := httptest.NewServer(tk.Handler())
		defer up.Close()
		gw := httptest.NewUnstartedServer(nil)
		url := "http://" + gw.Listener.Addr().String() + "/mcp"
		dir := t.TempDir()
		auditPath := filepath.Join(dir, "audit.jsonl")
		y := `
public_url: ` + url + `
identity: { mode: jwt, issuer: ` + idp.Issuer + `, jwks_url: ` + idp.JWKSURL() + `, claims: { user: email } }
vault:
  address: ` + addr + `
  auth: { method: approle, role_id_file: ` + cfg.Auth.RoleIDFile + `, secret_id_file: ` + cfg.Auth.SecretIDFile + ` }
upstreams:
  - name: tickets
    transport: http
    url: ` + up.URL + `/mcp
    credential: { path: secret/data/mcp/tickets, field: token, format: "Bearer {value}" }
audit: { sink: file, path: ` + auditPath + ` }
policy:
  rules:
    - { name: devs, effect: allow, when: { groups: [developers] }, server: tickets, tools: ["*"] }
`
		parsed, err := config.Parse([]byte(y))
		if err != nil {
			t.Fatal(err)
		}
		rt, err := gateway.Build(ctx, parsed, log)
		if err != nil {
			t.Fatalf("gateway.Build against HashiCorp Vault: %v", err)
		}
		defer rt.Close()
		rt.Start(ctx)
		gw.Config.Handler = rt.Handler
		gw.Start()
		defer gw.Close()
		resp, err := http.Get(strings.TrimSuffix(url, "/mcp") + "/readyz")
		if err != nil {
			t.Fatalf("readyz: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("readyz: HTTP %d", resp.StatusCode)
		}
		e := &env{url: url, idp: idp}
		s := e.connect(t, e.token("alice@example.com", "developers"), "2025-11-25")
		defer s.Close()
		if out, isErr := call(t, s, "tickets__ticket_list", map[string]any{"project": "myorg/web"}); isErr || !strings.Contains(out, "authenticated as svc-tickets") {
			t.Fatalf("ticket_list: %q err=%v (the upstream did not see the Vault credential)", out, isErr)
		}
	})
}

// leaseExists asks Vault, with the root token, whether a lease is still known.
func leaseExists(t *testing.T, addr, id string) bool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, addr+"/v1/sys/leases/lookup", strings.NewReader(`{"lease_id":"`+id+`"}`))
	req.Header.Set("X-Vault-Token", os.Getenv("HCVAULT_ROOT"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
