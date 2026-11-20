// Package secrets is a small client for the Vault HTTP API (tested against uBixVault;
// HashiCorp Vault serves the same API but is not yet tested): the gateway's own login and renewal, reading a secret, and a
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
		return nil, fmt.Errorf("vault %s %s: HTTP %d %s", method, path, resp.StatusCode, strings.Join(vr.Errors, "; "))
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

// Read returns a secret's data and lease. KV v2's nested data.data is unwrapped.
func (c *Client) Read(ctx context.Context, path string) (map[string]any, time.Duration, error) {
	vr, err := c.do(ctx, http.MethodGet, path, c.currentToken(), nil)
	if err != nil {
		return nil, 0, err
	}
	data := vr.Data
	if inner, ok := data["data"].(map[string]any); ok {
		if _, hasMeta := data["metadata"]; hasMeta {
			data = inner
		}
	}
	return data, time.Duration(vr.LeaseDuration) * time.Second, nil
}

// Healthy reports whether Vault answers its health endpoint as initialised and unsealed.
func (c *Client) Healthy(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "sys/health", "", nil)
	return err
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

// Reader is what the cache needs from a Client.
type Reader interface {
	Read(ctx context.Context, path string) (map[string]any, time.Duration, error)
}

// Cache holds one value per credential for min(ttl, lease). Concurrent misses for the
// same credential share one Vault read. Values are never served past their expiry.
type Cache struct {
	r   Reader
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	ready   chan struct{} // closed when the read finishes
	value   string
	err     error
	expires time.Time
}

// NewCache returns an empty cache over r.
func NewCache(r Reader) *Cache {
	return &Cache{r: r, now: time.Now, entries: map[string]*entry{}}
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
				e = nil // failed or expired: read again
			}
		default: // a read is in flight; wait for it below
		}
	}
	if e == nil {
		e = &entry{ready: make(chan struct{})}
		c.entries[key] = e
		c.mu.Unlock()
		e.value, e.expires, e.err = c.read(ctx, cr)
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

func (c *Cache) read(ctx context.Context, cr *config.Credential) (string, time.Time, error) {
	data, lease, err := c.r.Read(ctx, cr.Path)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	v, ok := data[cr.Field].(string)
	if !ok || v == "" {
		return "", time.Time{}, fmt.Errorf("%w: field %q missing at %s", ErrUnavailable, cr.Field, cr.Path)
	}
	ttl := cr.TTL
	if lease > 0 && lease < ttl {
		ttl = lease
	}
	return v, c.now().Add(ttl), nil
}

// Invalidate drops a cached credential, for example after an upstream answered 401.
func (c *Cache) Invalidate(cr *config.Credential) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, cr.Path+"#"+cr.Field)
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
