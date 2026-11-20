package secrets

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ubixsys/ubixgate/internal/config"
	"github.com/ubixsys/ubixgate/test/fakes"
)

func login(t *testing.T, v *fakes.Vault) *Client {
	t.Helper()
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c := New(config.Vault{Address: v.Server.URL, Auth: config.VaultAuth{Method: "approle", Mount: "approle",
		RoleIDFile: write("role", v.RoleID), SecretIDFile: write("secret", v.SecretID)}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

var cred = &config.Credential{Path: "secret/data/mcp/tickets", Field: "token", Format: "Bearer {value}", TTL: time.Minute}

func TestLoginAndRead(t *testing.T) {
	v := fakes.NewVault()
	defer v.Server.Close()
	v.Put("secret/data/mcp/tickets", map[string]any{"token": "svc-123"})
	c := login(t, v)
	data, _, err := c.Read(context.Background(), "secret/data/mcp/tickets")
	if err != nil || data["token"] != "svc-123" {
		t.Fatalf("data=%v err=%v (KV v2 data.data must be unwrapped)", data, err)
	}
	if err := c.Healthy(context.Background()); err != nil {
		t.Error(err)
	}
}

func TestLoginRejected(t *testing.T) {
	v := fakes.NewVault()
	defer v.Server.Close()
	v.SecretID = "rotated"
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "r"), []byte("role-1"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "s"), []byte("secret-1"), 0o600)
	c := New(config.Vault{Address: v.Server.URL, Auth: config.VaultAuth{Method: "approle", Mount: "approle",
		RoleIDFile: filepath.Join(dir, "r"), SecretIDFile: filepath.Join(dir, "s")}}, nil, nil)
	if err := c.Login(context.Background()); err == nil {
		t.Fatal("login with a wrong secret ID succeeded")
	}
}

func TestCacheSingleFlightAndExpiry(t *testing.T) {
	v := fakes.NewVault()
	defer v.Server.Close()
	v.Put("secret/data/mcp/tickets", map[string]any{"token": "svc-123"})
	cache := NewCache(login(t, v))
	now := time.Now()
	cache.now = func() time.Time { return now }

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := cache.Get(context.Background(), cred)
			if err != nil || got != "Bearer svc-123" {
				t.Errorf("got %q err %v", got, err)
			}
		}()
	}
	wg.Wait()
	if n := v.Reads(); n != 1 {
		t.Errorf("%d Vault reads for a burst, want 1", n)
	}

	// Vault goes down: the cached value is served until it expires, never after.
	v.SetDown(true)
	if _, err := cache.Get(context.Background(), cred); err != nil {
		t.Errorf("cached value should be served while Vault is down: %v", err)
	}
	now = now.Add(61 * time.Second)
	if _, err := cache.Get(context.Background(), cred); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable once the cache expired", err)
	}

	// Back up, with a rotated value: picked up on the next read.
	v.SetDown(false)
	v.Put("secret/data/mcp/tickets", map[string]any{"token": "svc-456"})
	if got, _ := cache.Get(context.Background(), cred); got != "Bearer svc-456" {
		t.Errorf("got %q after rotation", got)
	}
}

func TestCacheInvalidateAndMissingField(t *testing.T) {
	v := fakes.NewVault()
	defer v.Server.Close()
	v.Put("secret/data/mcp/tickets", map[string]any{"token": "a"})
	cache := NewCache(login(t, v))
	_, _ = cache.Get(context.Background(), cred)
	cache.Invalidate(cred)
	_, _ = cache.Get(context.Background(), cred)
	if n := v.Reads(); n != 2 {
		t.Errorf("%d reads, want 2 after Invalidate", n)
	}
	bad := *cred
	bad.Field = "nope"
	if _, err := cache.Get(context.Background(), &bad); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v", err)
	}
}

type leaseReader struct{ lease time.Duration }

func (l leaseReader) Read(context.Context, string) (map[string]any, time.Duration, error) {
	return map[string]any{"token": "x"}, l.lease, nil
}

func TestLeaseCapsTTL(t *testing.T) {
	cache := NewCache(leaseReader{lease: 10 * time.Second})
	now := time.Now()
	cache.now = func() time.Time { return now }
	_, _ = cache.Get(context.Background(), cred)
	if got := cache.Expiry(cred).Sub(now); got != 10*time.Second {
		t.Errorf("expiry in %v, want the 10s lease, not the 60s TTL", got)
	}
}
