package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRedact(t *testing.T) {
	args := map[string]any{"project": "myorg/web", "title": "secret plan", "n": 3.0}
	got := (Redactor{}).Redact(args, []string{"project"})
	if got["project"] != "myorg/web" || got["title"] != Redacted || got["n"] != Redacted {
		t.Errorf("got %v", got)
	}
	h := Redactor{HashKey: []byte("k")}
	a, b := h.Redact(args, nil), h.Redact(map[string]any{"title": "secret plan"}, nil)
	if a["title"] != b["title"] || !strings.HasPrefix(a["title"].(string), "hmac-sha256:") {
		t.Errorf("equal values must hash equally: %v %v", a["title"], b["title"])
	}
	if strings.Contains(a["title"].(string), "secret") {
		t.Error("hash leaks the value")
	}
	if (Redactor{}).Redact(nil, nil) != nil {
		t.Error("no args, no map")
	}
}

func TestSinkOneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.Write(Record{User: "alice", Tool: "t", Status: StatusOK}) }()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 50 {
		t.Fatalf("%d lines, want 50", len(lines))
	}
	for _, l := range lines {
		var r Record
		if err := json.Unmarshal([]byte(l), &r); err != nil || r.User != "alice" {
			t.Fatalf("bad line %q: %v", l, err)
		}
	}
}

func TestOpenFileAppendsWithPrivateMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 2; i++ {
		s, err := OpenFile(p)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Write(Record{Tool: "t"})
		_ = s.Close()
	}
	b, _ := os.ReadFile(p)
	if strings.Count(string(b), "\n") != 2 {
		t.Errorf("file = %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
}
