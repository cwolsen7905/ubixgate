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

// Policy builds the decider the gateway runs for cfg.
func Policy(cfg *config.Config) (*policy.Rules, error) {
	return policy.New(cfg.Policy.Rules, serverNames(cfg))
}

// loadStateKey reads the request state key, or makes one for this process when path is
// empty, in which case a retry must reach the same replica.
func loadStateKey(path string) ([]byte, error) {
	if path == "" {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		return key, err
	}
	return ReadKey(path)
}

// ReadKey reads an HMAC key file. A key shorter than 32 bytes after trimming is refused:
// an empty one would let anyone forge what it protects.
func ReadKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	key := []byte(strings.TrimSpace(string(b)))
	if len(key) < 32 {
		return nil, fmt.Errorf("key file %s holds %d bytes, need at least 32", path, len(key))
	}
	return key, nil
}

// Runtime is a gateway assembled from a config, with its background work.
type Runtime struct {
	Gateway *Gateway
	Handler http.Handler
	cfg     *config.Config
	vault   *secrets.Client
	creds   *secrets.Cache
	ups     []*upstream.Upstream
	sink    *audit.Sink
	metrics *ops.Metrics
	log     *slog.Logger

	stopTracing func(context.Context) error
}

// RefreshEvery is how often upstream catalogs are re-listed, in case an upstream does not
// send tools/list_changed.
var RefreshEvery = 5 * time.Minute

// SweepEvery is how often expired credentials are dropped from the cache and their
// leases revoked.
var SweepEvery = time.Minute

// Build assembles a gateway from cfg. It logs in to Vault but does not wait for the
// upstreams; Start connects them in the background, and /readyz reports when all are up.
func Build(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Runtime, error) {
	rt := &Runtime{cfg: cfg, metrics: ops.NewMetrics(), log: log}
	if t := cfg.Tracing; t != nil {
		stop, err := ops.Tracing(ctx, t.Endpoint, t.ServiceName, t.SampleRatio)
		if err != nil {
			return nil, err
		}
		rt.stopTracing = stop
	}

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
		creds.Log = log
		for _, u := range cfg.Upstreams { // let calls sent with a replaced credential finish
			creds.Grace = max(creds.Grace, u.Timeout)
		}
		rt.creds = creds
	}

	pol, err := Policy(cfg)
	if err != nil {
		return nil, err
	}

	switch cfg.Audit.Sink {
	case "file":
		var chainKey []byte
		if cfg.Audit.ChainKeyFile != "" {
			if chainKey, err = ReadKey(cfg.Audit.ChainKeyFile); err != nil {
				return nil, fmt.Errorf("audit chain: %w", err)
			}
		}
		if rt.sink, err = audit.OpenFile(cfg.Audit.Path, chainKey); err != nil {
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

	stateKey, err := loadStateKey(cfg.RequestStateKeyFile)
	if err != nil {
		return nil, err
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
		go func() { // revoke the leases of values nobody asks for again
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(SweepEvery):
					rt.creds.Sweep()
				}
			}
		}()
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
	if rt.creds != nil {
		rt.creds.Close() // revoke the leases nothing uses any more
	}
	errs = append(errs, rt.sink.Close())
	if rt.stopTracing != nil { // flush the last spans
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		errs = append(errs, rt.stopTracing(ctx))
	}
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
