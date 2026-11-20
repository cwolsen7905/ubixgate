// Package upstream connects to the MCP servers behind the gateway, over Streamable HTTP
// or stdio, keeps their tool catalogs, and forwards calls with the upstream's own
// credential attached. The caller's token is never sent: each upstream request is built
// fresh by this package.
package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ubixsys/ubixgate/internal/config"
	"github.com/ubixsys/ubixgate/internal/secrets"
	"github.com/ubixsys/ubixgate/internal/version"
)

// Upstream is one connected MCP server.
type Upstream struct {
	cfg      config.Upstream
	creds    *secrets.Cache
	log      *slog.Logger
	onChange func() // called after the tool list changes

	mu       sync.Mutex
	session  *mcp.ClientSession
	tools    []*mcp.Tool
	inflight int
	credExp  time.Time // stdio: when the credential the process was started with expires
}

// New returns an unconnected upstream. onChange is called whenever its catalog changes.
func New(cfg config.Upstream, creds *secrets.Cache, log *slog.Logger, onChange func()) *Upstream {
	return &Upstream{cfg: cfg, creds: creds, log: log.With("upstream", cfg.Name), onChange: onChange}
}

// Name is the upstream's configured name, the prefix of its tools.
func (u *Upstream) Name() string { return u.cfg.Name }

// Tools returns the last fetched catalog.
func (u *Upstream) Tools() []*mcp.Tool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.tools
}

// Ready reports whether the upstream is connected and has listed its tools.
func (u *Upstream) Ready() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.session != nil && u.tools != nil
}

// Refresh connects if needed and fetches the tool list.
func (u *Upstream) Refresh(ctx context.Context) error {
	s, err := u.ensure(ctx)
	if err != nil {
		return err
	}
	var tools []*mcp.Tool
	for t, err := range s.Tools(ctx, nil) {
		if err != nil {
			u.drop(s)
			return fmt.Errorf("list tools: %w", err)
		}
		tools = append(tools, t)
	}
	slices.SortFunc(tools, func(a, b *mcp.Tool) int { return strings.Compare(a.Name, b.Name) })
	u.mu.Lock()
	changed := !sameTools(u.tools, tools)
	u.tools = tools
	u.mu.Unlock()
	if changed && u.onChange != nil {
		u.onChange()
	}
	return nil
}

// Call forwards one tool call; params.Name is the upstream's own tool name. Errors
// returned are transport, credential or protocol failures; a tool that ran and failed
// comes back as a result with IsError set. A result that asks for client input is
// returned as is (NeedsInput), for the gateway to decide on.
func (u *Upstream) Call(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	ctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout)
	defer cancel()
	if cr := u.cfg.Credential; cr != nil && u.cfg.Transport == "http" {
		// Fetch now so a Vault failure is reported as such, not as a transport error.
		if _, err := u.creds.Get(ctx, cr); err != nil {
			return nil, err
		}
	}
	s, err := u.ensure(ctx)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	u.inflight++
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.inflight--
		u.mu.Unlock()
	}()
	res, err := s.CallTool(ctx, params)
	if errors.Is(err, mcp.ErrConnectionClosed) {
		// The process exited or the connection broke. Not retried, since a tool call may
		// not be idempotent; the next call reconnects.
		u.drop(s)
	}
	return res, err
}

// ensure returns a live session, connecting or restarting as needed.
func (u *Upstream) ensure(ctx context.Context) (*mcp.ClientSession, error) {
	u.mu.Lock()
	s := u.session
	// A stdio process holds its credential in its environment, so a rotated credential
	// needs a restart. Do it only when no call is in flight.
	if s != nil && u.cfg.Transport == "stdio" && u.cfg.Credential != nil &&
		time.Now().After(u.credExp) && u.inflight == 0 {
		u.log.Info("restarting stdio upstream: its credential expired")
		u.session = nil
		u.mu.Unlock()
		_ = s.Close()
		u.mu.Lock()
		s = nil
	}
	u.mu.Unlock()
	if s != nil {
		return s, nil
	}

	t, credExp, err := u.transport(ctx)
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "ubixgate", Version: version.Version}, &mcp.ClientOptions{
		// The gateway itself answers no sampling, elicitation or roots requests, so an
		// upstream on an older revision, which would send them over this shared
		// connection, is told the client cannot. Newer upstreams see the calling client's
		// own capabilities per call and return their requests in the result instead.
		Capabilities:   &mcp.ClientCapabilities{},
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := u.Refresh(ctx); err != nil {
					u.log.Warn("refresh after tools/list_changed failed", "err", err)
				}
			}()
		},
	})
	s, err = client.Connect(ctx, t, nil)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.session != nil { // another caller connected first
		go func() { _ = s.Close() }()
		return u.session, nil
	}
	u.session, u.credExp = s, credExp
	u.log.Info("connected", "protocol", protocolOf(s))
	return s, nil
}

func (u *Upstream) transport(ctx context.Context) (mcp.Transport, time.Time, error) {
	switch u.cfg.Transport {
	case "http":
		hc := &http.Client{Transport: &credTransport{base: http.DefaultTransport, creds: u.creds, cred: u.cfg.Credential}}
		return &mcp.StreamableClientTransport{Endpoint: u.cfg.URL, HTTPClient: hc, DisableStandaloneSSE: true}, time.Time{}, nil
	case "stdio":
		cmd := exec.Command(u.cfg.Command[0], u.cfg.Command[1:]...)
		// The child gets PATH and HOME, its configured env and its credential, never the
		// gateway's own environment.
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		for k, v := range u.cfg.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		var exp time.Time
		if cr := u.cfg.Credential; cr != nil {
			v, err := u.creds.Get(ctx, cr)
			if err != nil {
				return nil, exp, err
			}
			cmd.Env = append(cmd.Env, cr.Env+"="+v)
			exp = u.creds.Expiry(cr)
		}
		cmd.Stderr = &logWriter{log: u.log}
		return &mcp.CommandTransport{Command: cmd}, exp, nil
	}
	return nil, time.Time{}, fmt.Errorf("unknown transport %q", u.cfg.Transport)
}

// drop forgets a broken session so the next use reconnects.
func (u *Upstream) drop(s *mcp.ClientSession) {
	u.mu.Lock()
	if u.session == s {
		u.session = nil
	}
	u.mu.Unlock()
	_ = s.Close()
}

// Close disconnects.
func (u *Upstream) Close() error {
	u.mu.Lock()
	s := u.session
	u.session = nil
	u.mu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}

// credTransport attaches the upstream's credential to every HTTP request. On a 401 it
// drops the cached credential and retries once with a fresh one, which is safe because
// a rejected request was not executed.
type credTransport struct {
	base  http.RoundTripper
	creds *secrets.Cache
	cred  *config.Credential
}

func (t *credTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.cred == nil {
		return t.base.RoundTrip(req)
	}
	send := func() (*http.Response, error) {
		v, err := t.creds.Get(req.Context(), t.cred)
		if err != nil {
			return nil, err
		}
		r := req.Clone(req.Context())
		if req.GetBody != nil {
			if r.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		r.Header.Set(t.cred.Header, v)
		return t.base.RoundTrip(r)
	}
	resp, err := send()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || (req.Body != nil && req.GetBody == nil) {
		return resp, err
	}
	_ = resp.Body.Close()
	t.creds.Invalidate(t.cred)
	return send()
}

// logWriter sends a stdio upstream's stderr to the gateway's log, line by line.
type logWriter struct{ log *slog.Logger }

func (w *logWriter) Write(p []byte) (int, error) {
	w.log.Debug("stderr", "line", string(trimNL(p)))
	return len(p), nil
}

func trimNL(p []byte) []byte {
	for len(p) > 0 && (p[len(p)-1] == '\n' || p[len(p)-1] == '\r') {
		p = p[:len(p)-1]
	}
	return p
}

func protocolOf(s *mcp.ClientSession) string {
	if r := s.InitializeResult(); r != nil {
		return r.ProtocolVersion
	}
	return ""
}

func sameTools(a, b []*mcp.Tool) bool {
	if len(a) != len(b) || (a == nil) != (b == nil) {
		return false
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
