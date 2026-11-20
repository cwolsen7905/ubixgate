package ops

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/ubixsys/ubixgate/internal/version"
)

// Tracer is what the gateway records spans with. Until Tracing is set up it is a no-op,
// so tracing costs nothing when it is off.
func Tracer() trace.Tracer { return otel.Tracer("github.com/ubixsys/ubixgate") }

// Tracing exports spans over OTLP/HTTP to endpoint: a collector's base URL such as
// http://collector:4318, which gets /v1/traces, or a full traces URL. It samples ratio
// of new traces and follows the caller's sampling decision when a request carries W3C
// trace context. It returns a function that flushes and stops the exporter.
//
// Spans carry names, decisions, rules, statuses and the audit request ID, never argument
// values, credentials or the caller's identity: the audit log is the place for who.
func Tracing(ctx context.Context, endpoint, service string, ratio float64) (func(context.Context) error, error) {
	// The exporter posts to the URL's own path; a collector's base URL gets the OTLP one.
	if u, err := url.Parse(endpoint); err == nil && strings.Trim(u.Path, "/") == "" {
		endpoint = strings.TrimSuffix(endpoint, "/") + "/v1/traces"
	}
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
	if err != nil {
		return nil, fmt.Errorf("tracing: %w", err)
	}
	res := resource.NewSchemaless(attribute.String("service.name", service),
		attribute.String("service.version", version.Version))
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return tp.Shutdown, nil
}
