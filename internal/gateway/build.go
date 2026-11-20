package gateway

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ubixsys/ubixgate/internal/audit"
	"github.com/ubixsys/ubixgate/internal/config"
	"github.com/ubixsys/ubixgate/internal/identity"
	"github.com/ubixsys/ubixgate/internal/ops"
	"github.com/ubixsys/ubixgate/internal/policy"
	"github.com/ubixsys/ubixgate/internal/secrets"
	"github.com/ubixsys/ubixgate/internal/upstream"
)

// Runtime is a gateway assembled from a config, with its background work.
type Runtime struct {
	Gateway *Gateway
	Handler http.Handler
	cfg     *config.Config
	vault   *secrets.Client
	ups     []*upstream.Upstream
	sink    *audit.Sink
	metrics *ops.Metrics
	log     *slog.Logger
}

// RefreshEvery is how often upstream catalogs are re-listed, in case an upstream does not
// send tools/list_changed.
var RefreshEvery = 5 * time.Minute

// Build assembles a gateway from cfg. It logs in to Vault but does not wait for the
// upstreams; Start connects them in the background, and /readyz reports when all are up.
func Build(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Runtime, error) {
	rt := &Runtime{cfg: cfg, metrics: ops.NewMetrics(), log: log}

	var authn identity.Authenticator
	var issuers []string
	switch cfg.Identity.Mode {
	case "jwt":
		j, err := identity.NewJWT(identity.JWTConfig{Issuer: cfg.Identity.Issuer, JWKSURL: cfg.Identity.JWKSURL,
			Audience: cfg.PublicURL, Claims: cfg.Identity.Claims})
		if err != nil {
			return nil, err
		}
		authn, issuers = j, []string{cfg.Identity.Issuer}
	case "static":
		s, err := identity.NewStatic(cfg.Identity.Tokens)
		if err != nil {
			return nil, err
		}
		log.Warn("static token mode: for local development only")
		authn = s
	}

	var creds *secrets.Cache
	if cfg.Vault != nil {
		rt.vault = secrets.New(*cfg.Vault, nil, log)
		if err := rt.vault.Login(ctx); err != nil {
			return nil, fmt.Errorf("vault login: %w", err)
		}
		creds = secrets.NewCache(rt.vault)
	}

	pol, err := policy.New(cfg.Policy.Rules, serverNames(cfg))
	if err != nil {
		return nil, err
	}

	switch cfg.Audit.Sink {
	case "file":
		if rt.sink, err = audit.OpenFile(cfg.Audit.Path); err != nil {
			return nil, err
		}
	default:
		rt.sink = audit.NewSink(os.Stdout)
	}
	var red audit.Redactor
	if cfg.Audit.HashArgs {
		key, err := os.ReadFile(cfg.Audit.HashKeyFile)
		if err != nil {
			return nil, fmt.Errorf("audit hash key: %w", err)
		}
		red.HashKey = []byte(strings.TrimSpace(string(key)))
	}

	// Without a key file the key is per process, so a retry must reach the same replica.
	stateKey := make([]byte, 32)
	_, _ = rand.Read(stateKey)
	if cfg.RequestStateKeyFile != "" {
		key, err := os.ReadFile(cfg.RequestStateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("request state key: %w", err)
		}
		stateKey = []byte(strings.TrimSpace(string(key)))
	}

	var g *Gateway
	for _, uc := range cfg.Upstreams {
		rt.ups = append(rt.ups, upstream.New(uc, creds, log, func() {
			if g != nil {
				g.Sync()
			}
		}))
	}
	g = New(Options{PublicURL: cfg.PublicURL, Issuers: issuers, Auth: authn, Policy: pol, Upstreams: rt.ups,
		Audit: rt.sink, Redactor: red, StateKey: stateKey, PerUserRate: cfg.Limits.PerUserPerMinute, Metrics: rt.metrics, Log: log})
	rt.Gateway = g

	mux := http.NewServeMux()
	g.Handler(mux)
	checks := map[string]ops.Check{"upstreams": rt.upstreamsReady}
	if rt.vault != nil {
		checks["vault"] = rt.vault.Healthy
	}
	ops.Mount(mux, rt.metrics, checks)
	rt.Handler = mux
	return rt, nil
}

// Start connects the upstreams and keeps catalogs and the Vault token fresh until ctx
// is done.
func (rt *Runtime) Start(ctx context.Context) {
	if rt.vault != nil {
		go rt.vault.KeepAlive(ctx)
	}
	for _, up := range rt.ups {
		go func() {
			backoff := time.Second
			for {
				err := up.Refresh(ctx)
				rt.metrics.UpstreamUp.WithLabelValues(up.Name()).Set(boolf(err == nil))
				wait := RefreshEvery
				if err != nil {
					rt.log.Warn("upstream not available", "upstream", up.Name(), "err", err, "retry_in", backoff)
					wait, backoff = backoff, min(backoff*2, time.Minute)
				} else {
					backoff = time.Second
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}()
	}
}

// Reload applies a new config. Only the policy can change without a restart; any other
// difference is reported and the old values stay.
func (rt *Runtime) Reload(cfg *config.Config) error {
	pol, err := policy.New(cfg.Policy.Rules, serverNames(rt.cfg))
	if err != nil {
		return err
	}
	rt.Gateway.SetPolicy(pol)
	old, next := *rt.cfg, *cfg
	old.Policy, next.Policy = config.Policy{}, config.Policy{}
	if fmt.Sprint(old) != fmt.Sprint(next) {
		rt.log.Warn("config changes outside policy need a restart; only the policy was reloaded")
	}
	rt.cfg.Policy = cfg.Policy
	return nil
}

// Close disconnects upstreams and closes the audit log.
func (rt *Runtime) Close() error {
	var errs []error
	for _, up := range rt.ups {
		errs = append(errs, up.Close())
	}
	errs = append(errs, rt.sink.Close())
	return errors.Join(errs...)
}

func (rt *Runtime) upstreamsReady(context.Context) error {
	var down []string
	for _, up := range rt.ups {
		if !up.Ready() {
			down = append(down, up.Name())
		}
	}
	if len(down) > 0 {
		return fmt.Errorf("not connected: %s", strings.Join(down, ", "))
	}
	return nil
}

func serverNames(cfg *config.Config) []string {
	var s []string
	for _, u := range cfg.Upstreams {
		s = append(s, u.Name)
	}
	return s
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
