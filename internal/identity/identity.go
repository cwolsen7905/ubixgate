// Package identity authenticates callers. In JWT mode it validates an OIDC access
// token against the issuer's JWKS and maps its claims to a policy.Principal; in static
// mode, meant for local development only, it looks the bearer token up in a fixed table.
package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ubixsys/ubixgate/internal/policy"
)

// ErrUnauthenticated wraps every authentication failure. Callers answer 401 with a
// generic message and log the wrapped reason.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator turns a request's bearer token into a principal.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (policy.Principal, error)
}

// BearerToken extracts the token from an Authorization header, or "".
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// Claims names the token claims that identify the caller.
type Claims struct {
	User   string `yaml:"user"`   // default "sub"
	Groups string `yaml:"groups"` // default "groups"
	Client string `yaml:"client"` // default "azp"; falls back to "client_id"
}

// JWTConfig configures JWT validation.
type JWTConfig struct {
	Issuer   string
	JWKSURL  string
	Audience string // the gateway's canonical URL; tokens for anything else are refused
	Claims   Claims
	Skew     time.Duration // allowed clock skew for exp and nbf; default 60s
	Client   *http.Client
}

// JWT validates RS256 and ES256 tokens. No other algorithm is accepted: not "none", and
// not HS*, so a public key can never be used as an HMAC secret.
type JWT struct {
	cfg  JWTConfig
	keys *keySet
	now  func() time.Time
}

// NewJWT returns a validator. Keys are fetched on first use.
func NewJWT(cfg JWTConfig) (*JWT, error) {
	if cfg.Issuer == "" || cfg.JWKSURL == "" || cfg.Audience == "" {
		return nil, errors.New("identity: issuer, jwks_url and audience are required")
	}
	if cfg.Claims.User == "" {
		cfg.Claims.User = "sub"
	}
	if cfg.Claims.Groups == "" {
		cfg.Claims.Groups = "groups"
	}
	if cfg.Claims.Client == "" {
		cfg.Claims.Client = "azp"
	}
	if cfg.Skew == 0 {
		cfg.Skew = 60 * time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	return &JWT{cfg: cfg, keys: newKeySet(cfg.JWKSURL, cfg.Client), now: time.Now}, nil
}

func unauth(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnauthenticated, fmt.Sprintf(format, a...))
}

// Authenticate validates token and returns the principal it names.
func (j *JWT) Authenticate(ctx context.Context, token string) (policy.Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return policy.Principal{}, unauth("token is not a JWS compact serialization")
	}
	var hdr struct {
		Alg  string `json:"alg"`
		Kid  string `json:"kid"`
		Crit []any  `json:"crit"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return policy.Principal{}, unauth("bad header: %v", err)
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return policy.Principal{}, unauth("algorithm %q is not allowed", hdr.Alg)
	}
	if hdr.Crit != nil {
		return policy.Principal{}, unauth("critical header extensions are not supported")
	}
	k, err := j.keys.get(ctx, hdr.Kid)
	if err != nil {
		return policy.Principal{}, unauth("%v", err)
	}
	if k.alg != "" && k.alg != hdr.Alg {
		return policy.Principal{}, unauth("key %q is for %s, token says %s", hdr.Kid, k.alg, hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return policy.Principal{}, unauth("bad signature encoding")
	}
	if !verify(hdr.Alg, k.key, parts[0]+"."+parts[1], sig) {
		return policy.Principal{}, unauth("signature does not verify")
	}

	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return policy.Principal{}, unauth("bad claims: %v", err)
	}
	if iss, _ := claims["iss"].(string); iss != j.cfg.Issuer {
		return policy.Principal{}, unauth("issuer %q is not %q", iss, j.cfg.Issuer)
	}
	if !audienceHas(claims["aud"], j.cfg.Audience) {
		return policy.Principal{}, unauth("token audience does not include %q", j.cfg.Audience)
	}
	now := j.now()
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return policy.Principal{}, unauth("exp is required")
	}
	if now.After(exp.Add(j.cfg.Skew)) {
		return policy.Principal{}, unauth("token expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && now.Add(j.cfg.Skew).Before(nbf) {
		return policy.Principal{}, unauth("token not valid before %s", nbf.UTC().Format(time.RFC3339))
	}

	p := policy.Principal{Groups: stringList(claims[j.cfg.Claims.Groups])}
	p.User, _ = claims[j.cfg.Claims.User].(string)
	if p.User == "" {
		return policy.Principal{}, unauth("claim %q (the user) is missing", j.cfg.Claims.User)
	}
	p.Client, _ = claims[j.cfg.Claims.Client].(string)
	if p.Client == "" {
		p.Client, _ = claims["client_id"].(string)
	}
	return p, nil
}

func verify(alg string, key crypto.PublicKey, input string, sig []byte) bool {
	sum := sha256.Sum256([]byte(input))
	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub, sum[:], r, s)
	}
	return false
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func audienceHas(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, _ := v.(string); s == want {
				return true
			}
		}
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// stringList accepts a JSON array of strings or a single space-separated string.
func stringList(v any) []string {
	switch x := v.(type) {
	case string:
		return strings.Fields(x)
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// StaticToken is one entry of the static token table.
type StaticToken struct {
	Token  string   `yaml:"token"`
	User   string   `yaml:"user"`
	Groups []string `yaml:"groups"`
	Client string   `yaml:"client"`
}

// Static authenticates against a fixed token table. It is for local development: the
// config loader refuses it on a non-loopback listen address.
type Static struct{ tokens []StaticToken }

// NewStatic returns a static authenticator. Every token must be at least 16 characters.
func NewStatic(tokens []StaticToken) (*Static, error) {
	for i, t := range tokens {
		if len(t.Token) < 16 || t.User == "" {
			return nil, fmt.Errorf("identity: static token %d needs a user and a token of at least 16 characters", i+1)
		}
	}
	return &Static{tokens: tokens}, nil
}

// Authenticate compares token with every entry in constant time.
func (s *Static) Authenticate(_ context.Context, token string) (policy.Principal, error) {
	var found *StaticToken
	for i := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.tokens[i].Token)) == 1 {
			found = &s.tokens[i]
		}
	}
	if found == nil {
		return policy.Principal{}, unauth("unknown static token")
	}
	return policy.Principal{User: found.User, Groups: found.Groups, Client: found.Client}, nil
}

// ResourceMetadata serves RFC 9728 protected resource metadata, so a client that gets a
// 401 can discover which authorization server issues tokens for this gateway.
func ResourceMetadata(resource string, issuers []string) http.Handler {
	body, _ := json.Marshal(map[string]any{
		"resource":                 resource,
		"authorization_servers":    issuers,
		"bearer_methods_supported": []string{"header"},
	})
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

// MetadataPath is where ResourceMetadata is mounted.
const MetadataPath = "/.well-known/oauth-protected-resource"

// Challenge is the WWW-Authenticate value for a 401 from the gateway at publicURL.
func Challenge(publicURL string) string {
	return fmt.Sprintf(`Bearer resource_metadata="%s%s"`, strings.TrimRight(publicURL, "/"), MetadataPath)
}
