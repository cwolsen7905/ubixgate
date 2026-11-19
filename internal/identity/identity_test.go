package identity

import (
	"context"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubixsys/ubixgate/test/fakes"
)

const aud = "https://mcp.example.com"

func newJWT(t *testing.T, idp *fakes.IdP) *JWT {
	t.Helper()
	j, err := NewJWT(JWTConfig{Issuer: idp.Issuer, JWKSURL: idp.JWKSURL(), Audience: aud,
		Claims: Claims{User: "email"}})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestJWT(t *testing.T) {
	idp := fakes.NewIdP()
	defer idp.Server.Close()
	j := newJWT(t, idp)

	base := func() map[string]any { return idp.Claims("alice", aud, []string{"developers"}, "claude-code") }
	with := func(k string, v any) map[string]any { c := base(); c[k] = v; return c }
	without := func(k string) map[string]any { c := base(); delete(c, k); return c }
	hour := time.Hour

	cases := []struct {
		name  string
		token string
		want  string // "" means accepted; otherwise a fragment of the error
	}{
		{"valid RS256", idp.Mint(base()), ""},
		{"valid ES256", idp.MintAlg("ES256", base()), ""},
		{"audience in an array", idp.Mint(with("aud", []string{"other", aud})), ""},
		{"expired within skew is accepted", idp.Mint(with("exp", time.Now().Add(-30*time.Second).Unix())), ""},

		{"bad signature", tamper(idp.Mint(base())), "signature does not verify"},
		{"claims swapped under a valid signature", swapClaims(idp.Mint(base()), idp.Mint(with("email", "root@example.com"))), "signature does not verify"},
		{"wrong audience", idp.Mint(with("aud", "https://other.example.com")), "audience"},
		{"audience array without us", idp.Mint(with("aud", []string{"a", "b"})), "audience"},
		{"no audience", idp.Mint(without("aud")), "audience"},
		{"expired", idp.Mint(with("exp", time.Now().Add(-hour).Unix())), "expired"},
		{"no exp", idp.Mint(without("exp")), "exp is required"},
		{"not yet valid", idp.Mint(with("nbf", time.Now().Add(hour).Unix())), "not valid before"},
		{"wrong issuer", idp.Mint(with("iss", "https://evil.example.com")), "issuer"},
		{"alg none", idp.MintHeader(map[string]any{"alg": "none", "kid": "RS256-1"}, base()), `"none" is not allowed`},
		{"alg None", idp.MintHeader(map[string]any{"alg": "None"}, base()), "not allowed"},
		{"HS256 keyed with the public key", idp.MintHeader(map[string]any{"alg": "HS256", "kid": "RS256-1"}, base()), `"HS256" is not allowed`},
		{"RS256 header pointing at the EC key", idp.MintHeader(map[string]any{"alg": "RS256", "kid": "ES256-1"}, base()), "key"},
		{"unknown kid", idp.MintHeader(map[string]any{"alg": "RS256", "kid": "nope"}, base()), `no key with id "nope"`},
		{"crit header", idp.MintHeader(map[string]any{"alg": "RS256", "kid": "RS256-1", "crit": []string{"x"}}, base()), "critical"},
		{"missing user claim", idp.Mint(without("email")), `claim "email"`},
		{"not a JWT", "abc.def", "compact"},
		{"garbage header", "!!!.e30.sig", "bad header"},
		{"empty", "", "compact"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := j.Authenticate(context.Background(), c.token)
			if c.want == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				if p.User != "alice@example.com" || !slices.Equal(p.Groups, []string{"developers"}) || p.Client != "claude-code" {
					t.Errorf("principal = %+v", p)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, want an error mentioning %q", c.want)
			}
			if !errors.Is(err, ErrUnauthenticated) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want ErrUnauthenticated mentioning %q", err, c.want)
			}
		})
	}
}

func TestJWKSRotation(t *testing.T) {
	idp := fakes.NewIdP()
	defer idp.Server.Close()
	j := newJWT(t, idp)
	ctx := context.Background()
	claims := idp.Claims("alice", aud, nil, "")

	old := idp.Mint(claims)
	if _, err := j.Authenticate(ctx, old); err != nil {
		t.Fatal(err)
	}
	if n := idp.Fetches(); n != 1 {
		t.Fatalf("JWKS fetched %d times, want 1", n)
	}

	idp.Rotate()
	fresh := idp.Mint(claims)

	// Within minRefresh an unknown kid does not refetch: bogus kids cannot flood the IdP.
	if _, err := j.Authenticate(ctx, fresh); err == nil {
		t.Fatal("new key accepted before a refetch was allowed")
	}
	if n := idp.Fetches(); n != 1 {
		t.Fatalf("JWKS fetched %d times within minRefresh, want 1", n)
	}

	// Once minRefresh has passed, the unknown kid triggers one refetch and the new key works.
	j.keys.minRefresh = 0
	if _, err := j.Authenticate(ctx, fresh); err != nil {
		t.Fatalf("token signed with the rotated key: %v", err)
	}
	if n := idp.Fetches(); n != 2 {
		t.Fatalf("JWKS fetched %d times, want 2", n)
	}
	// The retired key is no longer published, so its tokens are refused.
	if _, err := j.Authenticate(ctx, old); err == nil {
		t.Fatal("token signed with a retired key was accepted")
	}
}

func TestJWKSUnreachableKeepsCache(t *testing.T) {
	idp := fakes.NewIdP()
	j := newJWT(t, idp)
	tok := idp.Mint(idp.Claims("alice", aud, nil, ""))
	if _, err := j.Authenticate(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	idp.Server.Close()
	j.keys.minRefresh, j.keys.maxAge = 0, 0 // force a refetch attempt, which fails
	if _, err := j.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("a cached key should survive a failed refetch: %v", err)
	}
}

func TestJWTClaimShapes(t *testing.T) {
	idp := fakes.NewIdP()
	defer idp.Server.Close()
	j, _ := NewJWT(JWTConfig{Issuer: idp.Issuer, JWKSURL: idp.JWKSURL(), Audience: aud})
	c := idp.Claims("bob", aud, nil, "")
	c["groups"] = "a b"
	delete(c, "azp")
	c["client_id"] = "cursor"
	p, err := j.Authenticate(context.Background(), idp.Mint(c))
	if err != nil {
		t.Fatal(err)
	}
	if p.User != "bob" || !slices.Equal(p.Groups, []string{"a", "b"}) || p.Client != "cursor" {
		t.Errorf("principal = %+v (default user claim is sub, groups may be a string, client falls back to client_id)", p)
	}
}

func TestNewJWTRequiresFields(t *testing.T) {
	if _, err := NewJWT(JWTConfig{Issuer: "x", JWKSURL: "y"}); err == nil {
		t.Error("audience must be required")
	}
}

func TestStatic(t *testing.T) {
	s, err := NewStatic([]StaticToken{{Token: "dev-token-alice-0001", User: "alice", Groups: []string{"developers"}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(context.Background(), "dev-token-alice-0001")
	if err != nil || p.User != "alice" {
		t.Fatalf("p=%+v err=%v", p, err)
	}
	if _, err := s.Authenticate(context.Background(), "dev-token-alice-0002"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("err = %v", err)
	}
	if _, err := NewStatic([]StaticToken{{Token: "short", User: "a"}}); err == nil {
		t.Error("short static tokens must be refused")
	}
}

func TestBearerAndChallenge(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "bearer abc")
	if got := BearerToken(r); got != "abc" {
		t.Errorf("BearerToken = %q", got)
	}
	r.Header.Set("Authorization", "Basic abc")
	if got := BearerToken(r); got != "" {
		t.Errorf("BearerToken = %q for Basic", got)
	}
	if got := Challenge(aud + "/"); got != `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"` {
		t.Errorf("Challenge = %s", got)
	}
	w := httptest.NewRecorder()
	ResourceMetadata(aud, []string{"https://idp"}).ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `"resource":"https://mcp.example.com"`) {
		t.Errorf("metadata = %s", w.Body.String())
	}
}

// tamper flips one character of the signature.
func tamper(tok string) string {
	b := []byte(tok)
	i := len(b) - 5
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// swapClaims puts b's payload under a's header and signature.
func swapClaims(a, b string) string {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	return pa[0] + "." + pb[1] + "." + pa[2]
}
