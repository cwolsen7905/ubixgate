package gateway

import "testing"

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
