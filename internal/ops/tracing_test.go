package ops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestTracing(t *testing.T) {
	// Off until set up: spans are not recorded.
	if _, s := Tracer().Start(context.Background(), "x"); s.IsRecording() {
		t.Fatal("tracing is on before it was set up")
	}
	var posts atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/traces" {
			posts.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	stop, err := Tracing(context.Background(), collector.URL, "ubixgate-test", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, s := Tracer().Start(context.Background(), "tools/call")
	if !s.IsRecording() {
		t.Error("a new trace is not sampled at ratio 1")
	}
	s.End()
	if err := stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if posts.Load() == 0 {
		t.Error("no spans reached the collector's /v1/traces")
	}
}
