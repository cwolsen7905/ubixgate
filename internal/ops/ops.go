// Package ops serves the operational endpoints (/healthz, /readyz, /metrics) and sets
// up structured logging.
package ops

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics are the gateway's Prometheus series. Names and labels are a public interface.
type Metrics struct {
	Registry     *prometheus.Registry
	Calls        *prometheus.CounterVec   // server, decision, status
	CallDuration *prometheus.HistogramVec // server
	AuthFailures prometheus.Counter
	UpstreamUp   *prometheus.GaugeVec // upstream
}

// NewMetrics registers the series on a fresh registry, with Go and process collectors.
func NewMetrics() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Calls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ubixgate_tool_calls_total", Help: "Tool calls by upstream, policy decision and result status.",
		}, []string{"server", "decision", "status"}),
		CallDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "ubixgate_tool_call_duration_seconds", Help: "Tool call latency through the gateway, by upstream.",
			Buckets: prometheus.DefBuckets,
		}, []string{"server"}),
		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ubixgate_auth_failures_total", Help: "Requests refused because the bearer token was missing or invalid.",
		}),
		UpstreamUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ubixgate_upstream_up", Help: "1 if the upstream is connected and has listed its tools.",
		}, []string{"upstream"}),
	}
	m.Registry.MustRegister(m.Calls, m.CallDuration, m.AuthFailures, m.UpstreamUp,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Check is one readiness condition; nil means ready.
type Check func(ctx context.Context) error

// Mount adds /healthz, /readyz and /metrics to mux. /healthz says the process is up;
// /readyz runs every check and answers 503 naming the ones that fail.
func Mount(mux *http.ServeMux, m *Metrics, checks map[string]Check) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var failed []string
		for name, check := range checks {
			if err := check(ctx); err != nil {
				failed = append(failed, name+": "+err.Error())
			}
		}
		if len(failed) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, strings.Join(failed, "\n"))
			return
		}
		_, _ = fmt.Fprintln(w, "ready")
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
}

// Logger returns a JSON slog logger on stderr at the given level (debug, info, warn, error).
func Logger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
