// Package secrets is a small client for the Vault HTTP API (tested against uBixVault and
// HashiCorp Vault): the gateway's own login and renewal, reading a secret, and a
// per-path cache so a burst of calls makes one read.
package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ubixsys/ubixgate/internal/config"
)

const k8sTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// Client talks to one Vault server with the gateway's own token.
type Client struct {
	addr string
	auth config.VaultAuth
	http *http.Client
	log  *slog.Logger

	mu      sync.Mutex
	token   string
	ttl     time.Duration // the token's TTL at login or last renewal; 0 means it does not expire
	renewed time.Time
}

// New returns a client. Call Login before reading.
func New(cfg config.Vault, httpc *http.Client, log *slog.Logger) *Client {
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{addr: strings.TrimRight(cfg.Address, "/"), auth: cfg.Auth, http: httpc, log: log}
}

// vaultResponse is the envelope every Vault endpoint uses.
type vaultResponse struct {
	Data          map[string]any `json:"data"`
	LeaseID       string         `json:"lease_id"`
	LeaseDuration int            `json:"lease_duration"`
	Auth          *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

func (c *Client) do(ctx context.Context, method, path, token string, body any) (*vaultResponse, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+"/v1/"+strings.TrimLeft(path, "/"), rd)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	var vr vaultResponse
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&vr)
	if resp.StatusCode >= 300 {
		// Vault's error strings name paths, never secret values, so they are safe to log.
		err := fmt.Errorf("vault %s %s: HTTP %d %s", method, path, resp.StatusCode, strings.Join(vr.Errors, "; "))
		if resp.StatusCode == http.StatusNotFound {
			err = fmt.Errorf("%w: %w", ErrNoSecret, err)
		}
		return nil, err
	}
	return &vr, nil
}

// Login obtains the gateway's token with the configured method.
func (c *Client) Login(ctx context.Context) error {
	var token string
	var ttl time.Duration
	switch c.auth.Method {
	case "token":
		t, err := readFile(c.auth.TokenFile)
		if err != nil {
			return err
		}
		vr, err := c.do(ctx, http.MethodGet, "auth/token/lookup-self", t, nil)
		if err != nil {
			return err
		}
		token = t
		if f, ok := vr.Data["ttl"].(float64); ok {
			ttl = time.Duration(f) * time.Second
		}
	case "approle", "kubernetes":
		body := map[string]string{}
		if c.auth.Method == "approle" {
			roleID, err := readFile(c.auth.RoleIDFile)
			if err != nil {
				return err
			}
			secretID, err := readFile(c.auth.SecretIDFile)
			if err != nil {
				return err
			}
			body["role_id"], body["secret_id"] = roleID, secretID
		} else {
			f := c.auth.JWTFile
			if f == "" {
				f = k8sTokenFile
			}
			jwt, err := readFile(f)
			if err != nil {
				return err
			}
			body["role"], body["jwt"] = c.auth.Role, jwt
		}
		vr, err := c.do(ctx, http.MethodPost, "auth/"+c.auth.Mount+"/login", "", body)
		if err != nil {
			return err
		}
		if vr.Auth == nil || vr.Auth.ClientToken == "" {
			return errors.New("vault login: no client token in the response")
		}
		token, ttl = vr.Auth.ClientToken, time.Duration(vr.Auth.LeaseDuration)*time.Second
	default:
		return fmt.Errorf("vault: unknown auth method %q", c.auth.Method)
	}
	c.mu.Lock()
	c.token, c.ttl, c.renewed = token, ttl, time.Now()
	c.mu.Unlock()
	return nil
}

func (c *Client) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// Secret is what a read returns: the data, and for a dynamic secret its lease.
type Secret struct {
	Data    map[string]any
	Lease   time.Duration
	LeaseID string
}

// Read returns a secret's data and lease. KV v2's nested data.data is unwrapped. The
// lease is read from the envelope, as HashiCorp Vault sends it, or from inside data, as
// uBixVault's database engine does.
func (c *Client) Read(ctx context.Context, path string) (Secret, error) {
	vr, err := c.do(ctx, http.MethodGet, path, c.currentToken(), nil)
	if err != nil {
		return Secret{}, err
	}
	s := Secret{Data: vr.Data, Lease: time.Duration(vr.LeaseDuration) * time.Second, LeaseID: vr.LeaseID}
	if inner, ok := s.Data["data"].(map[string]any); ok {
		if _, hasMeta := s.Data["metadata"]; hasMeta {
			s.Data = inner
		}
	}
	if id, ok := s.Data["lease_id"].(string); ok && s.LeaseID == "" {
		s.LeaseID = id
	}
	if d, ok := s.Data["lease_duration"].(float64); ok && s.Lease == 0 {
		s.Lease = time.Duration(d) * time.Second
	}
	return s, nil
}

// Revoke ends a dynamic secret's lease, so the credential stops working at once.
func (c *Client) Revoke(ctx context.Context, leaseID string) error {
	_, err := c.do(ctx, http.MethodPut, "sys/leases/revoke", c.currentToken(), map[string]string{"lease_id": leaseID})
	return err
}

// Healthy reports whether Vault answers its health endpoint as initialised and unsealed.
// HashiCorp Vault uses the status code for the node's role: 200 is the active node, and
// 429, 472 and 473 are standby, disaster-recovery and performance-standby nodes. All of
// them can serve reads, so all count as healthy. 501 (not initialised) and 503 (sealed)
// do not.
func (c *Client) Healthy(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault GET sys/health: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusTooManyRequests, 472, 473:
		return nil
	}
	return fmt.Errorf("vault GET sys/health: HTTP %d", resp.StatusCode)
}

// KeepAlive renews the gateway's token at half its TTL, and logs in again when renewal
// fails. It returns when ctx is done.
func (c *Client) KeepAlive(ctx context.Context) {
	for {
		c.mu.Lock()
		ttl, renewed := c.ttl, c.renewed
		c.mu.Unlock()
		wait := time.Minute
		if ttl > 0 {
			wait = time.Until(renewed.Add(ttl / 2))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(max(wait, time.Second)):
		}
		if ttl == 0 {
			continue
		}
		vr, err := c.do(ctx, http.MethodPost, "auth/token/renew-self", c.currentToken(), map[string]any{})
		if err == nil && vr.Auth != nil {
			c.mu.Lock()
			c.ttl, c.renewed = time.Duration(vr.Auth.LeaseDuration)*time.Second, time.Now()
			c.mu.Unlock()
			continue
		}
		c.log.Warn("vault token renewal failed; logging in again", "err", err)
		if err := c.Login(ctx); err != nil {
			c.log.Error("vault login failed", "err", err)
			c.mu.Lock()
			c.renewed = time.Now().Add(-c.ttl/2 + 10*time.Second) // retry in 10s
			c.mu.Unlock()
		}
	}
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("vault auth: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// ErrUnavailable means a credential could not be obtained and no unexpired cached copy
// exists. The audit reason for it is "credential_unavailable".
var ErrUnavailable = errors.New("credential_unavailable")

// ErrNoSecret means Vault answered and has no usable secret at the path: nothing there,
// or no value in the configured field. It is an ErrUnavailable. Vault being down,
// sealed or refusing the gateway's token is not an ErrNoSecret.
var ErrNoSecret = fmt.Errorf("%w: no secret", ErrUnavailable)

// Reader is what the cache needs from a Client.
type Reader interface {
	Read(ctx context.Context, path string) (Secret, error)
	Revoke(ctx context.Context, leaseID string) error
}

// Cache holds one value per credential for min(ttl, lease). Concurrent misses for the
// same credential share one Vault read. Values are never served past their expiry.
//
// A dynamic secret's lease is revoked once the cache drops it (expired and read again,
// invalidated, or the cache closed), after Grace, so calls already sent with it can
// finish. A credential a stdio process holds in its environment is revoked by its
// upstream when the process stops instead (Hold, Release).
type Cache struct {
	r     Reader
	now   func() time.Time
	Grace time.Duration
	Log   *slog.Logger

	mu      sync.Mutex
	entries map[string]*entry
	held    map[string]int // lease ID to the number of processes holding it
}

type entry struct {
	ready   chan struct{} // closed when the read finishes
	value   string
	err     error
	expires time.Time
	leaseID string
}

// NewCache returns an empty cache over r.
func NewCache(r Reader) *Cache {
	return &Cache{r: r, now: time.Now, Grace: time.Minute, Log: slog.New(slog.DiscardHandler),
		entries: map[string]*entry{}, held: map[string]int{}}
}

// lease is an entry's lease ID once its read has finished. Called with c.mu held.
func lease(e *entry) string {
	select {
	case <-e.ready:
		return e.leaseID
	default:
		return ""
	}
}

// dropped revokes a replaced entry's lease after Grace, unless a process holds it.
// Called with c.mu held.
func (c *Cache) dropped(e *entry) {
	if e == nil || e.leaseID == "" || c.held[e.leaseID] > 0 {
		return
	}
	id := e.leaseID
	e.leaseID = ""
	time.AfterFunc(c.Grace, func() { c.revoke(id) })
}

func (c *Cache) revoke(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.r.Revoke(ctx, id); err != nil {
		c.Log.Warn("could not revoke an unused lease; it expires on its own", "err", err)
	}
}

// Hold marks the current lease of cr as in use by a process, and returns it ("" for a
// secret without a lease). Release it when the process stops.
func (c *Cache) Hold(cr *config.Credential) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[cr.Path+"#"+cr.Field]
	if e == nil || lease(e) == "" {
		return ""
	}
	c.held[e.leaseID]++
	return e.leaseID
}

// Release ends a Hold. The last release of a lease the cache no longer serves revokes it.
func (c *Cache) Release(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held[id]--; c.held[id] > 0 {
		return
	}
	delete(c.held, id)
	for _, e := range c.entries {
		if lease(e) == id {
			return // still the current value: revoked when the cache drops it
		}
	}
	go c.revoke(id)
}

// Close revokes every lease the cache still holds that no process holds, at once.
func (c *Cache) Close() {
	c.mu.Lock()
	var ids []string
	for k, e := range c.entries {
		if id := lease(e); id != "" && c.held[id] == 0 {
			ids = append(ids, id)
		}
		delete(c.entries, k)
	}
	c.mu.Unlock()
	for _, id := range ids {
		c.revoke(id)
	}
}

// Sweep forgets values that have expired or failed, revoking their leases after Grace
// like any dropped value. Without it, a value nobody asks for again (a per-user secret
// whose user has stopped calling) would keep its lease until shutdown, and its entry
// for good.
func (c *Cache) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, e := range c.entries {
		select {
		case <-e.ready:
			if e.err != nil || !now.Before(e.expires) {
				c.dropped(e)
				delete(c.entries, k)
			}
		default: // a read is in flight
		}
	}
}

// Get returns the credential's value, formatted, reading Vault on a miss.
func (c *Cache) Get(ctx context.Context, cr *config.Credential) (string, error) {
	key := cr.Path + "#" + cr.Field
	c.mu.Lock()
	e := c.entries[key]
	if e != nil {
		select {
		case <-e.ready:
			if e.err != nil || !c.now().Before(e.expires) {
				c.dropped(e)
				e = nil // failed or expired: read again
			}
		default: // a read is in flight; wait for it below
		}
	}
	if e == nil {
		e = &entry{ready: make(chan struct{})}
		c.entries[key] = e
		c.mu.Unlock()
		e.value, e.expires, e.leaseID, e.err = c.read(ctx, cr)
		close(e.ready)
	} else {
		c.mu.Unlock()
	}
	select {
	case <-e.ready:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if e.err != nil {
		return "", e.err
	}
	return strings.ReplaceAll(cr.Format, "{value}", e.value), nil
}

func (c *Cache) read(ctx context.Context, cr *config.Credential) (string, time.Time, string, error) {
	s, err := c.r.Read(ctx, cr.Path)
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	v, ok := s.Data[cr.Field].(string)
	if !ok || v == "" {
		if s.LeaseID != "" {
			go c.revoke(s.LeaseID) // issued but unusable
		}
		return "", time.Time{}, "", fmt.Errorf("%w: field %q missing at %s", ErrNoSecret, cr.Field, cr.Path)
	}
	ttl := cr.TTL
	if s.Lease > 0 && s.Lease < ttl {
		ttl = s.Lease
	}
	return v, c.now().Add(ttl), s.LeaseID, nil
}

// Invalidate drops a cached credential, for example after an upstream answered 401.
func (c *Cache) Invalidate(cr *config.Credential) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cr.Path + "#" + cr.Field
	if e := c.entries[key]; e != nil {
		select {
		case <-e.ready:
			c.dropped(e)
		default:
		}
	}
	delete(c.entries, key)
}

// Expiry reports when the cached value for cr expires, or the zero time if none.
func (c *Cache) Expiry(cr *config.Credential) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[cr.Path+"#"+cr.Field]; e != nil {
		select {
		case <-e.ready:
			return e.expires
		default:
		}
	}
	return time.Time{}
}
