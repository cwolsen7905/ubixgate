// Package config loads and validates the gateway's single YAML file. Unknown keys are
// errors, and Load reports every problem it finds, not only the first.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/ubixsys/ubixgate/internal/identity"
	"github.com/ubixsys/ubixgate/internal/policy"
)

// Config is the whole file.
type Config struct {
	Listen    string     `yaml:"listen"`
	PublicURL string     `yaml:"public_url"`
	Identity  Identity   `yaml:"identity"`
	Vault     *Vault     `yaml:"vault"`
	Upstreams []Upstream `yaml:"upstreams"`
	Limits    Limits     `yaml:"limits"`
	Audit     Audit      `yaml:"audit"`
	Policy    Policy     `yaml:"policy"`
	Tracing   *Tracing   `yaml:"tracing"` // off when absent
	// RequestStateKeyFile holds the key that seals upstream request state to its caller.
	// Replicas behind one URL need the same key; without one each process makes its own.
	RequestStateKeyFile string `yaml:"request_state_key_file"`
}

// Identity says how callers are authenticated.
type Identity struct {
	Mode    string                 `yaml:"mode"` // jwt or static
	Issuer  string                 `yaml:"issuer"`
	JWKSURL string                 `yaml:"jwks_url"`
	Claims  identity.Claims        `yaml:"claims"`
	Tokens  []identity.StaticToken `yaml:"tokens"` // static mode only
}

// Vault says how the gateway logs in to a Vault-API server.
type Vault struct {
	Address string    `yaml:"address"`
	Auth    VaultAuth `yaml:"auth"`
}

// VaultAuth is the gateway's own Vault login.
type VaultAuth struct {
	Method       string `yaml:"method"` // token, approle or kubernetes
	Mount        string `yaml:"mount"`  // auth mount path; defaults to the method name
	TokenFile    string `yaml:"token_file"`
	RoleIDFile   string `yaml:"role_id_file"`
	SecretIDFile string `yaml:"secret_id_file"`
	Role         string `yaml:"role"`     // kubernetes
	JWTFile      string `yaml:"jwt_file"` // kubernetes; defaults to the service account token
}

// Upstream is one MCP server behind the gateway.
type Upstream struct {
	Name       string            `yaml:"name"`
	Transport  string            `yaml:"transport"` // http or stdio
	URL        string            `yaml:"url"`
	Command    []string          `yaml:"command"`
	Env        map[string]string `yaml:"env"`
	Timeout    time.Duration     `yaml:"timeout"` // per call; default 60s
	Credential *Credential       `yaml:"credential"`
}

// Credential is where an upstream's secret lives in Vault and how it is attached.
type Credential struct {
	Path   string        `yaml:"path"`   // e.g. secret/data/mcp/tickets
	Field  string        `yaml:"field"`  // key inside the secret's data
	Header string        `yaml:"header"` // http: header to set, default Authorization
	Format string        `yaml:"format"` // e.g. "Bearer {value}"; default "{value}"
	Env    string        `yaml:"env"`    // stdio: environment variable to set
	TTL    time.Duration `yaml:"ttl"`    // cache lifetime, capped by the lease; default 60s
	// CatalogPath is read when Path names a per-user secret ("{user}"): it is used to
	// connect and list tools, never for a call.
	CatalogPath string `yaml:"catalog_path"`
}

// PerUser reports whether each caller's calls use their own secret.
func (c *Credential) PerUser() bool { return strings.Contains(c.Path, "{user}") }

// Limits holds the per-user call limit.
type Limits struct {
	PerUserPerMinute int `yaml:"per_user_per_minute"` // 0 means no limit
}

// Audit says where audit records go.
type Audit struct {
	Sink        string `yaml:"sink"` // file or stdout
	Path        string `yaml:"path"`
	HashArgs    bool   `yaml:"hash_args"`
	HashKeyFile string `yaml:"hash_key_file"`
	// ChainKeyFile turns on the HMAC chain over the file's records (audit verify).
	ChainKeyFile string `yaml:"chain_key_file"`
}

// Tracing exports OpenTelemetry spans over OTLP/HTTP.
type Tracing struct {
	Endpoint    string  `yaml:"endpoint"`     // e.g. http://collector:4318
	ServiceName string  `yaml:"service_name"` // default ubixgate
	SampleRatio float64 `yaml:"sample_ratio"` // of new traces, in (0, 1]; default 1
}

// Policy is the rule list.
type Policy struct {
	Rules []policy.Rule `yaml:"rules"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,22}[a-z0-9])?$`)

// Load reads, parses and validates the file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and validates a config document.
func Parse(b []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Audit.Sink == "" {
		c.Audit.Sink = "stdout"
	}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Timeout == 0 {
			u.Timeout = 60 * time.Second
		}
		if cr := u.Credential; cr != nil {
			if cr.Format == "" {
				cr.Format = "{value}"
			}
			if cr.TTL == 0 {
				cr.TTL = 60 * time.Second
			}
			if u.Transport == "http" && cr.Header == "" {
				cr.Header = "Authorization"
			}
		}
	}
	if t := c.Tracing; t != nil {
		if t.ServiceName == "" {
			t.ServiceName = "ubixgate"
		}
		if t.SampleRatio == 0 {
			t.SampleRatio = 1
		}
	}
	if c.Vault != nil && c.Vault.Auth.Mount == "" {
		c.Vault.Auth.Mount = c.Vault.Auth.Method
	}
}

func (c *Config) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("config: "+format, a...)) }

	if u, err := url.Parse(c.PublicURL); c.PublicURL == "" || err != nil || u.Host == "" ||
		(u.Scheme != "https" && u.Scheme != "http") {
		bad("public_url must be an absolute http(s) URL; it is the audience tokens must carry")
	}

	switch c.Identity.Mode {
	case "jwt":
		if c.Identity.Issuer == "" || c.Identity.JWKSURL == "" {
			bad("identity: jwt mode needs issuer and jwks_url")
		}
		if len(c.Identity.Tokens) > 0 {
			bad("identity: tokens are only for static mode")
		}
	case "static":
		if !loopback(c.Listen) {
			bad("identity: static mode is for local development and needs a loopback listen address (127.0.0.1 or [::1]), not %q", c.Listen)
		}
		if _, err := identity.NewStatic(c.Identity.Tokens); err != nil || len(c.Identity.Tokens) == 0 {
			bad("identity: static mode needs tokens, each with a user and at least 16 characters")
		}
	default:
		bad("identity.mode must be jwt or static, not %q", c.Identity.Mode)
	}

	names := map[string]bool{}
	var servers []string
	needVault := false
	for i, u := range c.Upstreams {
		where := fmt.Sprintf("upstreams[%d] (%s)", i, u.Name)
		if !nameRE.MatchString(u.Name) {
			bad("%s: name must be 1 to 24 lowercase letters, digits or single dashes; it prefixes every tool name", where)
		}
		if names[u.Name] {
			bad("%s: duplicate name", where)
		}
		names[u.Name] = true
		servers = append(servers, u.Name)
		switch u.Transport {
		case "http":
			if pu, err := url.Parse(u.URL); err != nil || pu.Host == "" {
				bad("%s: http transport needs an absolute url", where)
			}
			if len(u.Command) > 0 || len(u.Env) > 0 {
				bad("%s: command and env are for stdio upstreams", where)
			}
		case "stdio":
			if len(u.Command) == 0 {
				bad("%s: stdio transport needs a command", where)
			}
			if u.URL != "" {
				bad("%s: url is for http upstreams", where)
			}
		default:
			bad("%s: transport must be http or stdio", where)
		}
		if cr := u.Credential; cr != nil {
			needVault = true
			if cr.Path == "" || cr.Field == "" {
				bad("%s: credential needs path and field", where)
			}
			if !strings.Contains(cr.Format, "{value}") {
				bad("%s: credential format must contain {value}", where)
			}
			if u.Transport == "stdio" && cr.Env == "" {
				bad("%s: a stdio credential is passed as an environment variable; set credential.env", where)
			}
			if u.Transport == "http" && cr.Env != "" {
				bad("%s: credential.env is for stdio upstreams; use header", where)
			}
			switch {
			case cr.PerUser() && u.Transport != "http":
				bad("%s: a per-user credential needs an http upstream; one stdio process serves every caller", where)
			case cr.PerUser() && (cr.CatalogPath == "" || strings.Contains(cr.CatalogPath, "{user}")):
				bad("%s: a per-user credential needs catalog_path, without {user}, to list tools", where)
			case !cr.PerUser() && cr.CatalogPath != "":
				bad("%s: catalog_path is only for a per-user credential path", where)
			}
		}
	}
	if len(c.Upstreams) == 0 {
		bad("at least one upstream is required")
	}

	if needVault && c.Vault == nil {
		bad("vault is required because an upstream has a credential")
	}
	if v := c.Vault; v != nil {
		if pu, err := url.Parse(v.Address); err != nil || pu.Host == "" {
			bad("vault.address must be an absolute URL")
		}
		switch v.Auth.Method {
		case "token":
			if v.Auth.TokenFile == "" {
				bad("vault.auth: token method needs token_file")
			}
		case "approle":
			if v.Auth.RoleIDFile == "" || v.Auth.SecretIDFile == "" {
				bad("vault.auth: approle method needs role_id_file and secret_id_file")
			}
		case "kubernetes":
			if v.Auth.Role == "" {
				bad("vault.auth: kubernetes method needs role")
			}
		default:
			bad("vault.auth.method must be token, approle or kubernetes")
		}
	}

	if c.Limits.PerUserPerMinute < 0 {
		bad("limits.per_user_per_minute must not be negative")
	}
	switch c.Audit.Sink {
	case "stdout":
	case "file":
		if c.Audit.Path == "" {
			bad("audit: file sink needs path")
		}
	default:
		bad("audit.sink must be file or stdout")
	}
	if t := c.Tracing; t != nil {
		if u, err := url.Parse(t.Endpoint); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			bad("tracing: endpoint must be an absolute http(s) URL, such as http://collector:4318")
		}
		if t.SampleRatio < 0 || t.SampleRatio > 1 {
			bad("tracing: sample_ratio must be in (0, 1]")
		}
	}
	if c.Audit.ChainKeyFile != "" && c.Audit.Sink != "file" {
		bad("audit: chain_key_file needs the file sink, so a restart can continue the chain")
	}
	if c.Audit.HashArgs && c.Audit.HashKeyFile == "" {
		bad("audit: hash_args needs hash_key_file")
	}

	if _, err := policy.New(c.Policy.Rules, servers); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Upstream returns the named upstream, or nil.
func (c *Config) Upstream(name string) *Upstream {
	for i := range c.Upstreams {
		if c.Upstreams[i].Name == name {
			return &c.Upstreams[i]
		}
	}
	return nil
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
