// Package audit writes one JSON line per tool call. Argument keys are always kept;
// argument values are dropped unless the deciding rule names them, or replaced by an
// HMAC so equal values can be correlated without being readable.
package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
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
	// Chain is set by a chained sink, always as the last field: the HMAC of the previous
	// record's chain and this line without it. See Verify.
	Chain string `json:"chain,omitempty"`
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
	mu   sync.Mutex
	w    io.Writer
	c    io.Closer
	key  []byte // chain key; nil for an unchained log
	prev string // the last record's chain
	torn bool   // the last write failed partway, leaving a line with no newline
}

// NewSink writes to w.
func NewSink(w io.Writer) *Sink { return &Sink{w: w} }

// OpenFile appends to the file at path, creating it with mode 0600. With a chain key,
// every record carries an HMAC chained over the one before, continuing from the file's
// last record, so editing, removing or inserting a line is detectable (Verify).
// Removing lines from the end is not: compare the last chain with a copy kept elsewhere.
func OpenFile(path string, chainKey []byte) (*Sink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	s := &Sink{w: f, c: f, key: chainKey}
	if s.key != nil {
		if s.prev, err = lastChain(f); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: %s: %w", path, err)
		}
	}
	return s, nil
}

// Write appends one record.
func (s *Sink) Write(r Record) error {
	r.Chain = ""
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := ""
	if s.key != nil {
		next = link(s.key, s.prev, b)
		b = append(b[:len(b)-1], `,"chain":"`+next+`"}`...)
	}
	line := append(b, '\n')
	if s.torn { // end the fragment first, so this record starts its own line
		line = append([]byte{'\n'}, line...)
	}
	if n, err := s.w.Write(line); err != nil {
		// The chain stays at the last complete record. A partial line left in the file
		// is what audit verify will name.
		s.torn = s.torn && n == 0 || n > 0 && n < len(line)
		return err
	}
	s.torn = false
	if s.key != nil {
		s.prev = next
	}
	return nil
}

func link(key []byte, prev string, line []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(prev + "\n"))
	m.Write(line)
	return hex.EncodeToString(m.Sum(nil))
}

var chainSuffix = regexp.MustCompile(`,"chain":"([0-9a-f]{64})"}$`)

// split returns a chained line without its chain field, and the chain.
func split(line []byte) ([]byte, string, bool) {
	m := chainSuffix.FindSubmatchIndex(line)
	if m == nil {
		return nil, "", false
	}
	body := append(append([]byte{}, line[:m[0]]...), '}')
	return body, string(line[m[2]:m[3]]), true
}

// lastChain reads the chain of the file's last chained line, so the chain continues
// after a restart. An empty file starts a chain. A line torn by a crash or a failed
// write is left in place for audit verify to name, and the file is ended with a newline
// so the next record starts on its own line. A file with no chained line in its last
// megabyte is refused rather than silently started over.
func lastChain(f *os.File) (string, error) {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return "", err
	}
	n := min(st.Size(), 1<<20)
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, st.Size()-n); err != nil && err != io.EOF {
		return "", err
	}
	if buf[len(buf)-1] != '\n' {
		if _, err := f.Write([]byte("\n")); err != nil {
			return "", err
		}
	}
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if _, c, ok := split(lines[i]); ok {
			return c, nil
		}
	}
	return "", errors.New("chain_key_file is set but the file holds no chained record; start a new file")
}

// BrokenError names the first line where a chained log stops verifying.
type BrokenError struct {
	Line int
	Why  string
}

func (e *BrokenError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Why) }

// Verify checks a chained log from its first line, starting from the chain value from
// (empty for a log that begins a chain, or the last chain of the file before it). It returns the number of records and
// the last chain, or a *BrokenError for the first line that is not chained, does not
// parse, or does not follow from the line before (edited, removed or inserted).
func Verify(r io.Reader, key []byte, from string) (int, string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	prev, n := from, 0
	for sc.Scan() {
		n++
		body, c, ok := split(sc.Bytes())
		switch {
		case !ok:
			return n - 1, prev, &BrokenError{n, "no chain field"}
		case !json.Valid(body):
			return n - 1, prev, &BrokenError{n, "not a JSON record"}
		case !hmac.Equal([]byte(c), []byte(link(key, prev, body))):
			return n - 1, prev, &BrokenError{n, "chain does not follow: this line or one before it was edited, removed or inserted"}
		}
		prev = c
	}
	return n, prev, sc.Err()
}

// Close closes the underlying file, if any.
func (s *Sink) Close() error {
	if s.c != nil {
		return s.c.Close()
	}
	return nil
}
