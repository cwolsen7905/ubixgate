package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	s, err := c.Read(context.Background(), "secret/data/mcp/tickets")
	if err != nil || s.Data["token"] != "svc-123" || s.LeaseID != "" {
		t.Fatalf("secret=%+v err=%v (KV v2 data.data must be unwrapped)", s, err)
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

// leaseReader issues a new lease per read and records revocations.
type leaseReader struct {
	lease   time.Duration
	field   string
	mu      sync.Mutex
	n       int
	revoked []string
}

func (l *leaseReader) Read(context.Context, string) (Secret, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
	f := l.field
	if f == "" {
		f = "token"
	}
	return Secret{Data: map[string]any{f: "x"}, Lease: l.lease, LeaseID: fmt.Sprintf("l%d", l.n)}, nil
}

func (l *leaseReader) Revoke(_ context.Context, id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.revoked = append(l.revoked, id)
	return nil
}

// revokedSoon waits briefly for revocations made after the cache's grace period.
func (l *leaseReader) revokedSoon(want ...string) []string {
	for i := 0; i < 100; i++ {
		l.mu.Lock()
		got := append([]string(nil), l.revoked...)
		l.mu.Unlock()
		if len(got) >= len(want) {
			slices.Sort(got)
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.revoked...)
}

func TestLeaseRevocation(t *testing.T) {
	r := &leaseReader{lease: time.Hour}
	cache := NewCache(r)
	cache.Grace = 0
	now := time.Now()
	cache.now = func() time.Time { return now }
	ctx := context.Background()

	_, _ = cache.Get(ctx, cred) // l1
	cache.Invalidate(cred)      // dropped: revoked
	if got := r.revokedSoon("l1"); !slices.Equal(got, []string{"l1"}) {
		t.Fatalf("after invalidate: %v", got)
	}
	_, _ = cache.Get(ctx, cred) // l2
	now = now.Add(2 * time.Minute)
	_, _ = cache.Get(ctx, cred) // l2 expired and replaced by l3: l2 revoked
	if got := r.revokedSoon("l1", "l2"); !slices.Equal(got, []string{"l1", "l2"}) {
		t.Fatalf("after expiry: %v", got)
	}

	// A stdio process holds l3: replacing it in the cache does not revoke it; the
	// process stopping does. Releasing the current value does not revoke it either.
	held := cache.Hold(cred)
	now = now.Add(2 * time.Minute)
	_, _ = cache.Get(ctx, cred) // l4
	time.Sleep(20 * time.Millisecond)
	if got := r.revokedSoon(); len(got) != 2 {
		t.Fatalf("a held lease was revoked: %v", got)
	}
	cache.Release(held)
	if got := r.revokedSoon("l1", "l2", "l3"); !slices.Equal(got, []string{"l1", "l2", "l3"}) {
		t.Fatalf("after release: %v", got)
	}
	cache.Release(cache.Hold(cred)) // l4 is still served: kept
	time.Sleep(20 * time.Millisecond)
	cache.Close() // shutdown: l4 revoked
	if got := r.revokedSoon("l1", "l2", "l3", "l4"); !slices.Equal(got, []string{"l1", "l2", "l3", "l4"}) {
		t.Fatalf("after close: %v", got)
	}
}

func TestUnusableLeaseRevoked(t *testing.T) {
	r := &leaseReader{lease: time.Hour, field: "other"}
	cache := NewCache(r)
	if _, err := cache.Get(context.Background(), cred); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if got := r.revokedSoon("l1"); !slices.Equal(got, []string{"l1"}) {
		t.Errorf("a lease issued without the field was not revoked: %v", got)
	}
}

// Both envelopes carry a lease: HashiCorp Vault's top level, and uBixVault's database
// engine, which puts lease_id and lease_duration inside data.
func TestReadLeaseShapes(t *testing.T) {
	v := fakes.NewVault()
	defer v.Server.Close()
	v.PutDynamic("database/creds/ubix", map[string]any{"password": "p1"}, 30, false)
	v.PutDynamic("hcv/creds/app", map[string]any{"password": "p2"}, 40, true)
	c := login(t, v)
	for path, want := range map[string]time.Duration{"database/creds/ubix": 30 * time.Second, "hcv/creds/app": 40 * time.Second} {
		s, err := c.Read(context.Background(), path)
		if err != nil || s.Lease != want || !strings.HasPrefix(s.LeaseID, "lease-") || s.Data["password"] == nil {
			t.Errorf("%s: %+v, %v", path, s, err)
		}
	}
	if err := c.Revoke(context.Background(), "lease-1"); err != nil || !slices.Equal(v.Revoked(), []string{"lease-1"}) {
		t.Errorf("revoke: %v %v", err, v.Revoked())
	}
	// The lease caps the cache against uBixVault too.
	cache := NewCache(c)
	now := time.Now()
	cache.now = func() time.Time { return now }
	if _, err := cache.Get(context.Background(), &config.Credential{Path: "database/creds/ubix", Field: "password", Format: "{value}", TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if got := cache.Expiry(&config.Credential{Path: "database/creds/ubix", Field: "password"}).Sub(now); got != 30*time.Second {
		t.Errorf("expiry in %v, want the 30s lease", got)
	}
}

func TestLeaseCapsTTL(t *testing.T) {
	cache := NewCache(&leaseReader{lease: 10 * time.Second})
	now := time.Now()
	cache.now = func() time.Time { return now }
	_, _ = cache.Get(context.Background(), cred)
	if got := cache.Expiry(cred).Sub(now); got != 10*time.Second {
		t.Errorf("expiry in %v, want the 10s lease, not the 60s TTL", got)
	}
}

// A value nobody asks for again is swept once it expires, and its lease revoked; a value
// still fresh, and one a process holds, keep theirs.
func TestSweep(t *testing.T) {
	r := &leaseReader{lease: time.Hour}
	cache := NewCache(r)
	cache.Grace = 0
	now := time.Now()
	cache.now = func() time.Time { return now }
	ctx := context.Background()
	gone := &config.Credential{Path: "secret/data/mcp/tickets/carol", Field: "token", TTL: time.Minute}
	held := &config.Credential{Path: "secret/data/mcp/stdio", Field: "token", TTL: time.Minute}
	fresh := &config.Credential{Path: "secret/data/mcp/tickets/dave", Field: "token", TTL: time.Hour}
	_, _ = cache.Get(ctx, gone)  // l1
	_, _ = cache.Get(ctx, held)  // l2
	_, _ = cache.Get(ctx, fresh) // l3
	lease := cache.Hold(held)

	cache.Sweep() // nothing has expired
	now = now.Add(2 * time.Minute)
	cache.Sweep()
	if got := r.revokedSoon("l1"); !slices.Equal(got, []string{"l1"}) {
		t.Fatalf("after sweep: %v, want [l1]", got)
	}
	if !cache.Expiry(gone).IsZero() || cache.Expiry(fresh).IsZero() {
		t.Error("the sweep should forget the expired value and keep the fresh one")
	}
	cache.Release(lease) // the process stops: its swept lease goes now
	if got := r.revokedSoon("l1", "l2"); !slices.Equal(got, []string{"l1", "l2"}) {
		t.Fatalf("after release: %v, want [l1 l2]", got)
	}
}

// Vault having nothing at a path is ErrNoSecret; Vault being down is not.
func TestNoSecret(t *testing.T) {
	v := fakes.NewVault()
	defer v.Server.Close()
	c := login(t, v)
	cache := NewCache(c)
	if _, err := cache.Get(context.Background(), cred); !errors.Is(err, ErrNoSecret) {
		t.Errorf("missing secret: %v, want ErrNoSecret", err)
	}
	v.Put("secret/data/mcp/tickets", map[string]any{"other": "x"})
	if _, err := cache.Get(context.Background(), cred); !errors.Is(err, ErrNoSecret) {
		t.Errorf("missing field: %v, want ErrNoSecret", err)
	}
	v.SetDown(true)
	cache.Invalidate(cred)
	_, err := cache.Get(context.Background(), cred)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNoSecret) {
		t.Errorf("vault down: %v, want ErrUnavailable and not ErrNoSecret", err)
	}
}

// HashiCorp Vault reports a node's role in the health status code: standby and
// performance-standby nodes answer 429 and 473 and still serve reads.
func TestHealthyStatusCodes(t *testing.T) {
	for _, tc := range []struct {
		code int
		ok   bool
	}{{200, true}, {429, true}, {472, true}, {473, true}, {501, false}, {503, false}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = w.Write([]byte(`{"initialized":true}`))
		}))
		c := New(config.Vault{Address: srv.URL}, nil, nil)
		if err := c.Healthy(context.Background()); (err == nil) != tc.ok {
			t.Errorf("health %d: err=%v, want ok=%v", tc.code, err, tc.ok)
		}
		srv.Close()
	}
}

// Responses shaped as HashiCorp Vault sends them: a KV v1 read carries a default
// lease_duration and an empty lease_id, a database read carries both in the envelope, and
// a revoke answers 204 with no body.
func TestHashiCorpResponseShapes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/kv1/tickets":
			_, _ = w.Write([]byte(`{"lease_id":"","renewable":false,"lease_duration":2764800,"data":{"token":"v1-tok"},"warnings":null}`))
		case "/v1/database/creds/app":
			_, _ = w.Write([]byte(`{"lease_id":"database/creds/app/abc","renewable":true,"lease_duration":300,"data":{"username":"u","password":"p"}}`))
		case "/v1/sys/leases/revoke":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	}))
	defer srv.Close()
	c := New(config.Vault{Address: srv.URL}, nil, nil)
	s, err := c.Read(context.Background(), "kv1/tickets")
	if err != nil || s.Data["token"] != "v1-tok" || s.LeaseID != "" {
		t.Fatalf("kv1: %+v %v", s, err)
	}
	s, err = c.Read(context.Background(), "database/creds/app")
	if err != nil || s.LeaseID != "database/creds/app/abc" || s.Lease != 300*time.Second || s.Data["password"] != "p" {
		t.Fatalf("database: %+v %v", s, err)
	}
	if err := c.Revoke(context.Background(), s.LeaseID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := c.Read(context.Background(), "kv/missing"); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("missing path: %v", err)
	}
}
