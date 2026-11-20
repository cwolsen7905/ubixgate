package audit

import (
	"bytes"
	"encoding/json"
	"errors"
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
		s, err := OpenFile(p, nil)
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

func TestChain(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	write := func(users ...string) {
		t.Helper()
		s, err := OpenFile(p, key)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range users {
			if err := s.Write(Record{User: u, Tool: "t__x", Args: map[string]any{"k": Redacted}}); err != nil {
				t.Fatal(err)
			}
		}
		_ = s.Close()
	}
	write("a", "b", "c")
	write("d", "e") // a restart continues the chain from the file's last line
	orig, _ := os.ReadFile(p)
	n, last, err := Verify(bytes.NewReader(orig), key)
	if err != nil || n != 5 {
		t.Fatalf("intact log: %d records, %v", n, err)
	}
	lines := strings.SplitAfter(strings.TrimSuffix(string(orig), "\n"), "\n")
	var rec Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil || rec.Chain == "" || rec.User != "a" {
		t.Errorf("a chained line must still parse as a record: %+v, %v", rec, err)
	}

	cases := map[string]struct {
		log  string
		line int
	}{
		"edited":        {strings.Replace(string(orig), `"user":"c"`, `"user":"x"`, 1), 3},
		"removed":       {lines[0] + lines[1] + lines[3] + lines[4], 3},
		"inserted":      {lines[0] + lines[1] + lines[1] + lines[2] + lines[3] + lines[4], 3},
		"swapped":       {lines[0] + lines[2] + lines[1] + lines[3] + lines[4], 2},
		"chain dropped": {lines[0] + `{"user":"z"}` + "\n" + lines[1], 2},
	}
	for name, c := range cases {
		_, _, err := Verify(strings.NewReader(c.log), key)
		var be *BrokenError
		if !errors.As(err, &be) || be.Line != c.line {
			t.Errorf("%s: err = %v, want line %d", name, err, c.line)
		}
	}
	if _, _, err := Verify(bytes.NewReader(orig), []byte("another key of thirty-two bytes!")); err == nil {
		t.Error("verified with the wrong key")
	}

	// The documented limit: cutting lines off the end leaves a valid chain. Only a copy
	// of the last chain kept elsewhere shows it.
	n, cut, err := Verify(strings.NewReader(lines[0]+lines[1]+lines[2]), key)
	if err != nil || n != 3 || cut == last {
		t.Errorf("truncated log: %d records, %v; its last chain must differ from the full log's", n, err)
	}

	// A chain is never started silently on top of unchained records.
	plain := filepath.Join(t.TempDir(), "plain.jsonl")
	_ = os.WriteFile(plain, []byte(`{"user":"a"}`+"\n"), 0o600)
	if _, err := OpenFile(plain, key); err == nil {
		t.Error("opened an unchained log with a chain key")
	}
}
