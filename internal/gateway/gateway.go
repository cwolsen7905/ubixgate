// Package gateway is the MCP server that clients connect to. It merges the upstreams'
// catalogs under "server__tool" names, filters tools/list per caller, and runs every
// tools/call through the same steps: authenticate (in HTTP middleware), identify, route,
// authorize, inject and forward, audit. Every exit from a call writes one audit record.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/ubixsys/ubixgate/internal/audit"
	"github.com/ubixsys/ubixgate/internal/identity"
	"github.com/ubixsys/ubixgate/internal/ops"
	"github.com/ubixsys/ubixgate/internal/policy"
	"github.com/ubixsys/ubixgate/internal/secrets"
	"github.com/ubixsys/ubixgate/internal/upstream"
	"github.com/ubixsys/ubixgate/internal/version"
)

// Sep joins an upstream's name and its tool's name.
const Sep = "__"

// RuleLimit is the rule name a call refused by the per-user limit shows.
const RuleLimit = "per-user-limit"

// Options configure a Gateway.
type Options struct {
	PublicURL   string // the MCP endpoint's canonical URL; also the token audience
	Issuers     []string
	Auth        identity.Authenticator
	Policy      policy.Decider
	Upstreams   []*upstream.Upstream
	Audit       *audit.Sink
	Redactor    audit.Redactor
	PerUserRate int    // calls per minute per user; 0 means no limit
	StateKey    []byte // seals upstream request state to the caller; see clientreq.go
	Metrics     *ops.Metrics
	Log         *slog.Logger
}

// Gateway serves the merged catalog.
type Gateway struct {
	opts   Options
	server *mcp.Server
	policy atomic.Pointer[policy.Decider]
	limit  *limiter

	mu     sync.Mutex
	routes map[string]route // namespaced name to upstream and its own tool name
}

type route struct {
	up   *upstream.Upstream
	tool string
}

// New builds a gateway. Call Sync (or let the upstreams' change callbacks call it) to
// publish their catalogs.
func New(opts Options) *Gateway {
	g := &Gateway{opts: opts, routes: map[string]route{}, limit: newLimiter(opts.PerUserRate)}
	g.policy.Store(&opts.Policy)
	g.server = mcp.NewServer(&mcp.Implementation{Name: "ubixgate", Version: version.Version}, &mcp.ServerOptions{
		Logger: opts.Log,
		// The tool list differs per caller, so clients and proxies must not share it.
		SetCacheable: func(_ context.Context, _ mcp.Request, c *mcp.Cacheable) {
			c.CacheScope, c.TTLMs = "private", 60_000
		},
	})
	g.server.AddReceivingMiddleware(g.middleware)
	return g
}

// SetPolicy swaps the policy atomically, for a config reload.
func (g *Gateway) SetPolicy(d policy.Decider) { g.policy.Store(&d) }

func (g *Gateway) decider() policy.Decider { return *g.policy.Load() }

// Sync republishes the merged catalog from the upstreams' current tool lists.
func (g *Gateway) Sync() {
	g.mu.Lock()
	defer g.mu.Unlock()
	next := map[string]route{}
	var add []*mcp.Tool
	for _, up := range g.opts.Upstreams {
		for _, t := range up.Tools() {
			name := up.Name() + Sep + t.Name
			if !validSchema(t.InputSchema) {
				g.opts.Log.Warn("skipping tool without an object input schema", "tool", name)
				continue
			}
			nt := *t
			nt.Name = name
			next[name] = route{up: up, tool: t.Name}
			add = append(add, &nt)
		}
	}
	var gone []string
	for name := range g.routes {
		if _, ok := next[name]; !ok {
			gone = append(gone, name)
		}
	}
	g.server.RemoveTools(gone...)
	for _, t := range add {
		// Calls never reach this handler: the middleware answers tools/call itself.
		g.server.AddTool(t, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return nil, errors.New("unreachable")
		})
	}
	g.routes = next
}

func validSchema(s any) bool {
	b, err := json.Marshal(s)
	if err != nil {
		return false
	}
	var m map[string]any
	return json.Unmarshal(b, &m) == nil && m["type"] == "object"
}

// Handler serves the MCP endpoint at the public URL's path, behind bearer
// authentication, plus the protected resource metadata that a 401 points to.
func (g *Gateway) Handler(mux *http.ServeMux) {
	path := endpointPath(g.opts.PublicURL)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return g.server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, Logger: g.opts.Log})
	verify := func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		ctx, span := ops.Tracer().Start(ctx, "auth")
		defer span.End()
		p, err := g.opts.Auth.Authenticate(ctx, token)
		if err != nil {
			span.SetStatus(codes.Error, "authentication failed")
			g.opts.Metrics.AuthFailures.Inc()
			g.opts.Log.Info("authentication failed", "reason", err)
			return nil, auth.ErrInvalidToken // the client is told only that the token is invalid
		}
		return &auth.TokenInfo{UserID: p.User, Extra: map[string]any{"principal": p}}, nil
	}
	metaPath := identity.MetadataPath + strings.TrimSuffix(path, "/")
	requireAuth := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: origin(g.opts.PublicURL) + metaPath,
		// Expiry is already checked by the authenticator; static tokens have none.
		AllowMissingExpiration: true,
	})
	mux.Handle(path, traced(requireAuth(mcpHandler)))
	meta := identity.ResourceMetadata(g.opts.PublicURL, g.opts.Issuers)
	mux.Handle("GET "+metaPath, meta)
	mux.Handle("GET "+identity.MetadataPath, meta)
}

// traced starts a span per MCP request, continuing the caller's W3C trace context.
func traced(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := ops.Tracer().Start(ctx, "mcp "+r.Method, trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (g *Gateway) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case "tools/list":
			res, err := next(ctx, method, req)
			if lr, ok := res.(*mcp.ListToolsResult); ok && err == nil {
				p := principalOf(req)
				kept := lr.Tools[:0]
				for _, t := range lr.Tools {
					if r, ok := g.lookup(t.Name); ok && g.decider().Visible(p, r.up.Name(), r.tool) {
						kept = append(kept, t)
					}
				}
				lr.Tools = kept
			}
			return res, err
		case "tools/call":
			if cr, ok := req.(*mcp.CallToolRequest); ok {
				return g.call(ctx, cr), nil
			}
		}
		return next(ctx, method, req)
	}
}

func (g *Gateway) lookup(name string) (route, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.routes[name]
	return r, ok
}

// call runs one tools/call and always writes exactly one audit record.
func (g *Gateway) call(ctx context.Context, req *mcp.CallToolRequest) *mcp.CallToolResult {
	start := time.Now()
	ctx, span := ops.Tracer().Start(ctx, "tools/call")
	defer span.End()
	p := principalOf(req)
	rec := audit.Record{Time: start.UTC(), RequestID: newID(), User: p.User, Groups: p.Groups,
		Client: p.Client, ClientDeclared: declaredClient(req), Tool: req.Params.Name}
	var args map[string]any
	_ = json.Unmarshal(req.Params.Arguments, &args) // non-object arguments match no arg constraint

	finish := func(res *mcp.CallToolResult) *mcp.CallToolResult {
		rec.LatencyMS = time.Since(start).Milliseconds()
		g.write(rec)
		g.opts.Metrics.Calls.WithLabelValues(rec.Server, rec.Decision, rec.Status).Inc()
		g.opts.Metrics.CallDuration.WithLabelValues(rec.Server).Observe(time.Since(start).Seconds())
		if res.Meta == nil {
			res.Meta = mcp.Meta{}
		}
		res.Meta["ubixgate/request_id"] = rec.RequestID
		// Names and outcomes only: no argument values, credentials or caller identity.
		span.SetAttributes(attribute.String("mcp.tool.name", rec.Tool), attribute.String("ubixgate.server", rec.Server),
			attribute.String("ubixgate.request_id", rec.RequestID), attribute.String("ubixgate.decision", rec.Decision),
			attribute.String("ubixgate.rule", rec.Rule), attribute.String("ubixgate.status", rec.Status))
		if rec.Status != audit.StatusOK && rec.Status != audit.StatusInputRequired {
			span.SetStatus(codes.Error, rec.Status)
		}
		return res
	}
	deny := func(rule, shown string) *mcp.CallToolResult {
		rec.Decision, rec.Rule, rec.Status = string(policy.Deny), rule, audit.StatusDenied
		rec.Args = g.opts.Redactor.Redact(args, nil)
		return finish(errorResult("denied by rule " + shown))
	}

	server, tool, _ := strings.Cut(req.Params.Name, Sep)
	rec.Server = server
	pr := policy.Request{Principal: p, Server: server, Tool: tool, Args: args}
	r, known := g.lookup(req.Params.Name)
	_, pspan := ops.Tracer().Start(ctx, "policy")
	dec, shown := Decide(ctx, g.decider(), pr, known)
	pspan.SetAttributes(attribute.String("ubixgate.decision", string(dec.Effect)), attribute.String("ubixgate.rule", dec.Rule))
	pspan.End()
	if !dec.Allowed() {
		if !known {
			rec.Server = "" // keep made-up names out of metric labels
		}
		return deny(dec.Rule, shown)
	}
	if !g.limit.allow(p.User) {
		return deny(RuleLimit, RuleLimit)
	}

	params := &mcp.CallToolParams{Name: r.tool, Meta: clientCaps(req.Params.Meta)}
	if len(req.Params.Arguments) > 0 {
		params.Arguments = req.Params.Arguments
	}
	if req.Params.RequestState != "" || len(req.Params.InputResponses) > 0 {
		// A retry carrying answers: the state must be one this gateway sealed for this
		// user and tool, and the answers must be to the requests it passed on.
		up, ok := g.open(req.Params.RequestState, p.User, req.Params.Name, argsHash(req.Params.Arguments), req.Params.InputResponses)
		if !ok {
			return deny(RuleRequestState, RuleRequestState)
		}
		params.RequestState, params.InputResponses = up, req.Params.InputResponses
	}

	rec.Decision, rec.Rule = string(policy.Allow), dec.Rule
	rec.Args = g.opts.Redactor.Redact(args, dec.AuditArgs)
	res, err := r.up.Call(ctx, p.User, params)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		rec.Status, rec.Reason = audit.StatusTimeout, "upstream did not answer in time"
		return finish(errorResult("upstream timed out"))
	case errors.Is(err, secrets.ErrUnavailable):
		rec.Status, rec.Reason = audit.StatusUpstreamError, "credential_unavailable"
		if r.up.PerUser() && errors.Is(err, secrets.ErrNoSecret) {
			// Vault answered: this caller has no credential of their own, a refusal. Vault
			// being unreachable stays an upstream error, so an outage is not logged as one.
			rec.Status = audit.StatusDenied
		}
		g.opts.Log.Warn("credential unavailable", "server", server, "err", err, "request_id", rec.RequestID)
		return finish(errorResult("upstream error: credential unavailable"))
	case err != nil:
		rec.Status, rec.Reason = audit.StatusUpstreamError, err.Error()
		return finish(errorResult("upstream error"))
	case res.NeedsInput():
		rec.LatencyMS = time.Since(start).Milliseconds() // for the request records
		out, denied := g.needsInput(ctx, rec, pr, argsHash(req.Params.Arguments), res, canAnswer(req))
		switch {
		case denied != "":
			rec.Decision, rec.Rule, rec.Status = string(policy.Deny), denied, audit.StatusDenied
			rec.Reason = "client_request_denied"
		case out != res:
			rec.Status, rec.Reason = audit.StatusNotSent, "client_protocol"
		default:
			rec.Status = audit.StatusInputRequired
		}
		return finish(out)
	case res.IsError:
		rec.Status = audit.StatusToolError
	default:
		rec.Status = audit.StatusOK
	}
	return finish(res)
}

// Decide is the policy step of every call, and of `ubixgate policy explain`. known says
// whether the tool exists. It returns the decision, whose rule the audit record shows,
// and the rule the caller is shown. For an unknown tool that is the rule that would
// deny the name if it existed, so probing for hidden tools learns nothing the caller's
// catalog does not already show.
func Decide(ctx context.Context, d policy.Decider, pr policy.Request, known bool) (policy.Decision, string) {
	dec, err := d.Decide(ctx, pr)
	if err != nil {
		dec = policy.Decision{Effect: policy.Deny, Rule: policy.DefaultDeny}
	}
	if !known {
		shown := policy.UnknownTool
		if !dec.Allowed() {
			shown = dec.Rule
		}
		return policy.Decision{Effect: policy.Deny, Rule: policy.UnknownTool}, shown
	}
	return dec, dec.Rule
}

func (g *Gateway) write(rec audit.Record) {
	if err := g.opts.Audit.Write(rec); err != nil {
		g.opts.Log.Error("audit write failed", "err", err, "request_id", rec.RequestID)
	}
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

func principalOf(req mcp.Request) policy.Principal {
	if ex := req.GetExtra(); ex != nil && ex.TokenInfo != nil {
		if p, ok := ex.TokenInfo.Extra["principal"].(policy.Principal); ok {
			return p
		}
	}
	return policy.Principal{}
}

// declaredClient is what the client says it is: recorded, never trusted.
func declaredClient(req *mcp.CallToolRequest) string {
	if ci, ok := req.Params.Meta[mcp.MetaKeyClientInfo].(map[string]any); ok {
		if n, _ := ci["name"].(string); n != "" {
			return n
		}
	}
	if ex := req.GetExtra(); ex != nil && ex.Header != nil {
		return ex.Header.Get("User-Agent")
	}
	return ""
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func endpointPath(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return "/mcp"
	}
	return u.Path
}

func origin(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// limiter is a per-user token bucket, in memory, so it is per replica.
type limiter struct {
	perMin float64
	mu     sync.Mutex
	users  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMin int) *limiter {
	return &limiter{perMin: float64(perMin), users: map[string]*bucket{}}
}

func (l *limiter) allow(user string) bool {
	if l.perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.users[user]
	if b == nil {
		b = &bucket{tokens: l.perMin, last: now}
		l.users[user] = b
	}
	b.tokens = min(l.perMin, b.tokens+now.Sub(b.last).Minutes()*l.perMin)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
