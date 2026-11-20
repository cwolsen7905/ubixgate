package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestLimiter(t *testing.T) {
	l := newLimiter(3)
	for i := 0; i < 3; i++ {
		if !l.allow("alice") {
			t.Fatalf("call %d refused within the limit", i+1)
		}
	}
	if l.allow("alice") {
		t.Error("fourth call in the same minute allowed")
	}
	if !l.allow("bob") {
		t.Error("the limit is per user")
	}
	if !newLimiter(0).allow("x") {
		t.Error("0 means no limit")
	}
}

func TestEndpointPath(t *testing.T) {
	for in, want := range map[string]string{
		"https://mcp.example.com/mcp":   "/mcp",
		"https://mcp.example.com":       "/mcp",
		"https://example.com/tools/mcp": "/tools/mcp",
		"http://127.0.0.1:8080/":        "/mcp",
	} {
		if got := endpointPath(in); got != want {
			t.Errorf("endpointPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSealedState(t *testing.T) {
	g := &Gateway{opts: Options{StateKey: []byte("0123456789abcdef0123456789abcdef")}}
	args := argsHash(json.RawMessage(`{"project": "myorg/web", "n": 9007199254740993}`))
	st := sealedState{User: "alice", Tool: "t__x", Args: args, IDs: []string{"q"}, Upstream: "up-state",
		Expires: time.Now().Add(time.Minute).Unix()}
	good := g.seal(st)
	yes := mcp.InputResponseMap{"q": &mcp.ElicitResult{Action: "accept"}}
	if up, ok := g.open(good, "alice", "t__x", argsHash(json.RawMessage(`{"project":"myorg/web","n":9007199254740993}`)), yes); !ok || up != "up-state" {
		t.Fatalf("valid state refused (%q, %v); spacing must not matter", up, ok)
	}
	expired := st
	expired.Expires = time.Now().Add(-time.Second).Unix()
	other := &Gateway{opts: Options{StateKey: []byte("another key, also 32 bytes long!")}}
	for name, c := range map[string]struct {
		g                       *Gateway
		state, user, tool, args string
		ans                     mcp.InputResponseMap
	}{
		"expired":    {g, g.seal(expired), "alice", "t__x", args, yes},
		"other tool": {g, good, "alice", "t__y", args, yes},
		"other user": {g, good, "bob", "t__x", args, yes},
		"other args": {g, good, "alice", "t__x", argsHash(json.RawMessage(`{"project":"evil/x","n":9007199254740993}`)), yes},
		// 2^53+1 and 2^53 are the same float64, so a hash of parsed arguments would pass.
		"large integer":  {g, good, "alice", "t__x", argsHash(json.RawMessage(`{"project":"myorg/web","n":9007199254740992}`)), yes},
		"not an object":  {g, g.seal(sealedState{User: "alice", Tool: "t__x", Args: argsHash(json.RawMessage(`[1]`)), Expires: st.Expires}), "alice", "t__x", argsHash(json.RawMessage(`[2]`)), nil},
		"other key":      {other, good, "alice", "t__x", args, yes},
		"unasked answer": {g, good, "alice", "t__x", args, mcp.InputResponseMap{"z": &mcp.ElicitResult{}}},
		"garbage":        {g, "not-a-state", "alice", "t__x", args, yes},
	} {
		if _, ok := c.g.open(c.state, c.user, c.tool, c.args, c.ans); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadStateKey(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct {
		content string
		ok      bool
	}{"empty": {"  \n", false}, "short": {"0123456789", false}, "long enough": {strings.Repeat("k", 32) + "\n", true}} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadStateKey(p); (err == nil) != c.ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if k, err := loadStateKey(""); err != nil || len(k) != 32 {
		t.Errorf("generated key: %d bytes, %v", len(k), err)
	}
}
