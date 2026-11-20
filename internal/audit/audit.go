// Package audit writes one JSON line per tool call. Argument keys are always kept;
// argument values are dropped unless the deciding rule names them, or replaced by an
// HMAC so equal values can be correlated without being readable.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"
)

// Result statuses.
const (
	StatusOK            = "ok"
	StatusDenied        = "denied"
	StatusToolError     = "tool_error"     // the upstream ran the tool and reported an error
	StatusUpstreamError = "upstream_error" // the call did not complete: transport, credential or protocol failure
	StatusTimeout       = "timeout"
	// StatusInputRequired: the upstream asked the caller's client for input, and the
	// call continues when the client retries with the answers.
	StatusInputRequired = "input_required"
	// StatusNotSent: a client request the policy allowed but this client cannot receive.
	StatusNotSent = "not_sent"
)

// Record is one audit line. Field names are a public interface (docs/VERSIONING.md).
type Record struct {
	Time           time.Time      `json:"time"`
	RequestID      string         `json:"request_id"`
	User           string         `json:"user"`
	Groups         []string       `json:"groups,omitempty"`
	Client         string         `json:"client,omitempty"`
	ClientDeclared string         `json:"client_declared,omitempty"`
	Server         string         `json:"server,omitempty"`
	Tool           string         `json:"tool"`
	ClientRequest  string         `json:"client_request,omitempty"` // sampling, elicitation or roots; empty for the call itself
	Decision       string         `json:"decision"`
	Rule           string         `json:"rule"`
	Status         string         `json:"status"`
	Reason         string         `json:"reason,omitempty"`
	LatencyMS      int64          `json:"latency_ms"`
	Args           map[string]any `json:"args,omitempty"`
}

// Redacted is the placeholder for an argument value that is not logged.
const Redacted = "[redacted]"

// Redactor applies the argument logging rules.
type Redactor struct {
	HashKey []byte // when set, unlogged values become an HMAC instead of Redacted
}

// Redact returns args with every value not named in keep replaced.
func (r Redactor) Redact(args map[string]any, keep []string) map[string]any {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		switch {
		case slices.Contains(keep, k):
			out[k] = v
		case len(r.HashKey) > 0:
			b, _ := json.Marshal(v)
			m := hmac.New(sha256.New, r.HashKey)
			m.Write(b)
			out[k] = "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))[:32]
		default:
			out[k] = Redacted
		}
	}
	return out
}

// Sink writes records as JSON lines. It is safe for concurrent use.
type Sink struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
}

// NewSink writes to w.
func NewSink(w io.Writer) *Sink { return &Sink{w: w} }

// OpenFile appends to the file at path, creating it with mode 0600. The log is
// append-only by open mode, not tamper-evident: ship it off the host if that matters.
func OpenFile(path string) (*Sink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return &Sink{w: f, c: f}, nil
}

// Write appends one record.
func (s *Sink) Write(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(b)
	return err
}

// Close closes the underlying file, if any.
func (s *Sink) Close() error {
	if s.c != nil {
		return s.c.Close()
	}
	return nil
}
