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
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/ubixsys/ubixgate/internal/config"
	"github.com/ubixsys/ubixgate/internal/ops"
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
	lease    string    // stdio: the dynamic secret lease the process holds, released when it stops
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

// Call forwards one tool call made for user; params.Name is the upstream's own tool name. Errors
// returned are transport, credential or protocol failures; a tool that ran and failed
// comes back as a result with IsError set. A result that asks for client input is
// returned as is (NeedsInput), for the gateway to decide on.
func (u *Upstream) Call(ctx context.Context, user string, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	ctx, cancel := context.WithTimeout(context.WithValue(ctx, callerKey{}, user), u.cfg.Timeout)
	defer cancel()
	if cr := u.cfg.Credential; cr != nil && u.cfg.Transport == "http" {
		// Fetch now so a Vault failure is reported as such, not as a transport error.
		cctx, span := ops.Tracer().Start(ctx, "credential")
		cr, err := credFor(cctx, cr)
		if err == nil {
			_, err = u.creds.Get(cctx, cr)
		}
		if err != nil {
			span.SetStatus(codes.Error, "credential_unavailable")
		}
		span.End()
		if err != nil {
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
	ctx, span := ops.Tracer().Start(ctx, "upstream", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("ubixgate.server", u.cfg.Name)))
	defer span.End()
	res, err := s.CallTool(ctx, params)
	if err != nil {
		span.SetStatus(codes.Error, "upstream error")
	}
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
		held := u.lease
		u.session, u.lease = nil, ""
		u.mu.Unlock()
		_ = s.Close()
		u.creds.Release(held)
		u.mu.Lock()
		s = nil
	}
	u.mu.Unlock()
	if s != nil {
		return s, nil
	}

	t, credExp, lease, err := u.transport(ctx)
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
		u.creds.Release(lease)
		return nil, fmt.Errorf("connect: %w", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.session != nil { // another caller connected first
		go func() { _ = s.Close(); u.creds.Release(lease) }()
		return u.session, nil
	}
	u.session, u.credExp, u.lease = s, credExp, lease
	u.log.Info("connected", "protocol", protocolOf(s))
	return s, nil
}

func (u *Upstream) transport(ctx context.Context) (mcp.Transport, time.Time, string, error) {
	switch u.cfg.Transport {
	case "http":
		hc := &http.Client{Transport: &credTransport{base: http.DefaultTransport, creds: u.creds, cred: u.cfg.Credential}}
		return &mcp.StreamableClientTransport{Endpoint: u.cfg.URL, HTTPClient: hc, DisableStandaloneSSE: true}, time.Time{}, "", nil
	case "stdio":
		cmd := exec.Command(u.cfg.Command[0], u.cfg.Command[1:]...)
		// The child gets PATH and HOME, its configured env and its credential, never the
		// gateway's own environment.
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		for k, v := range u.cfg.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		var exp time.Time
		var lease string
		if cr := u.cfg.Credential; cr != nil {
			v, err := u.creds.Get(ctx, cr)
			if err != nil {
				return nil, exp, "", err
			}
			cmd.Env = append(cmd.Env, cr.Env+"="+v)
			exp, lease = u.creds.Expiry(cr), u.creds.Hold(cr)
		}
		cmd.Stderr = &logWriter{log: u.log}
		return &mcp.CommandTransport{Command: cmd}, exp, lease, nil
	}
	return nil, time.Time{}, "", fmt.Errorf("unknown transport %q", u.cfg.Transport)
}

// drop forgets a broken session so the next use reconnects.
func (u *Upstream) drop(s *mcp.ClientSession) {
	u.mu.Lock()
	held := ""
	if u.session == s {
		u.session, held, u.lease = nil, u.lease, ""
	}
	u.mu.Unlock()
	_ = s.Close()
	u.creds.Release(held)
}

// Close disconnects.
func (u *Upstream) Close() error {
	u.mu.Lock()
	s, held := u.session, u.lease
	u.session, u.lease = nil, ""
	u.mu.Unlock()
	if s != nil {
		err := s.Close()
		u.creds.Release(held)
		return err
	}
	return nil
}

// PerUser reports whether calls use the caller's own credential.
func (u *Upstream) PerUser() bool { return u.cfg.Credential != nil && u.cfg.Credential.PerUser() }

// callerKey marks a context as a tool call made for a user. Call always sets it, and the
// HTTP requests of that call carry the context.
type callerKey struct{}

var userRE = regexp.MustCompile(`^[A-Za-z0-9@._+-]+$`)

// credFor picks the credential for a request: a per-user one for a call, resolved for
// its user, and the catalog one only for requests that are not calls. A user name that
// cannot safely form a path is refused, never mapped to another secret.
func credFor(ctx context.Context, cr *config.Credential) (*config.Credential, error) {
	if !cr.PerUser() {
		return cr, nil
	}
	c := *cr
	user, isCall := ctx.Value(callerKey{}).(string)
	switch {
	case !isCall:
		c.Path = cr.CatalogPath
	case !userRE.MatchString(user) || user == "." || user == "..":
		return nil, fmt.Errorf("%w: user %q cannot name a credential path", secrets.ErrUnavailable, user)
	default:
		c.Path = strings.ReplaceAll(cr.Path, "{user}", user)
	}
	return &c, nil
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
	// Pass the trace on: W3C trace context only, never the caller's token.
	req = req.Clone(req.Context())
	otel.GetTextMapPropagator().Inject(req.Context(), propagation.HeaderCarrier(req.Header))
	if t.cred == nil {
		return t.base.RoundTrip(req)
	}
	cred, err := credFor(req.Context(), t.cred)
	if err != nil {
		return nil, err
	}
	send := func() (*http.Response, error) {
		v, err := t.creds.Get(req.Context(), cred)
		if err != nil {
			return nil, err
		}
		r := req.Clone(req.Context())
		if req.GetBody != nil {
			if r.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		r.Header.Set(cred.Header, v)
		return t.base.RoundTrip(r)
	}
	resp, err := send()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || (req.Body != nil && req.GetBody == nil) {
		return resp, err
	}
	_ = resp.Body.Close()
	t.creds.Invalidate(cred)
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
