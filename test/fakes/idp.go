// Package fakes holds in-process stand-ins for the services the gateway talks to: an
// identity provider, a Vault server and MCP upstreams. Tests and the demo use them; the
// gateway itself never imports this package.
package fakes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// IdP is a fake identity provider: it serves a JWKS and mints signed JWTs. It holds an
// RSA key and an EC P-256 key, and Rotate replaces both with new key IDs.
type IdP struct {
	Issuer string
	Server *httptest.Server

	mu      sync.Mutex
	gen     int
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	fetches int
}

// NewIdP starts a fake IdP on a loopback port. Close it with Server.Close.
func NewIdP() *IdP {
	idp := &IdP{}
	idp.Rotate()
	idp.Server = httptest.NewServer(idp)
	idp.Issuer = idp.Server.URL
	return idp
}

// NewIdPHandler returns an IdP that is not started, for callers that serve it themselves
// (the demo). Set Issuer before minting.
func NewIdPHandler(issuer string) *IdP {
	idp := &IdP{Issuer: issuer}
	idp.Rotate()
	return idp
}

// JWKSURL is where the key set is served.
func (idp *IdP) JWKSURL() string { return idp.Issuer + "/jwks" }

// Rotate generates new keys with new key IDs. The old keys stop being published.
func (idp *IdP) Rotate() {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.gen++
	idp.rsaKey, idp.ecKey = rk, ek
}

func (idp *IdP) kid(alg string) string { return fmt.Sprintf("%s-%d", alg, idp.gen) }

// ServeHTTP serves /jwks.
func (idp *IdP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/jwks" {
		http.NotFound(w, r)
		return
	}
	idp.mu.Lock()
	idp.fetches++
	b64 := base64.RawURLEncoding.EncodeToString
	keys := []map[string]any{
		{"kty": "RSA", "kid": idp.kid("RS256"), "alg": "RS256", "use": "sig",
			"n": b64(idp.rsaKey.N.Bytes()), "e": b64(big.NewInt(int64(idp.rsaKey.E)).Bytes())},
		{"kty": "EC", "kid": idp.kid("ES256"), "alg": "ES256", "use": "sig", "crv": "P-256",
			"x": b64(ecPoint(idp.ecKey)[1:33]), "y": b64(ecPoint(idp.ecKey)[33:])},
	}
	idp.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

// Claims returns a standard claim set for user, valid for an hour.
func (idp *IdP) Claims(user, audience string, groups []string, client string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": idp.Issuer, "sub": user, "email": user + "@example.com", "aud": audience,
		"groups": groups, "azp": client, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
}

// Mint signs claims with the current RSA key (RS256).
func (idp *IdP) Mint(claims map[string]any) string { return idp.MintAlg("RS256", claims) }

// MintAlg signs claims with the named algorithm: RS256 or ES256 with the IdP's keys.
func (idp *IdP) MintAlg(alg string, claims map[string]any) string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.mint(map[string]any{"alg": alg, "typ": "JWT", "kid": idp.kid(alg)}, claims)
}

// MintHeader signs claims under an arbitrary header. The signing key follows
// header["alg"]: RS256, ES256, "none" (empty signature), or HS256 keyed with the RSA
// public modulus, which is the classic algorithm-confusion attack.
func (idp *IdP) MintHeader(header, claims map[string]any) string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.mint(header, claims)
}

func (idp *IdP) mint(header, claims map[string]any) string {
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	switch header["alg"] {
	case "RS256":
		s, err := rsa.SignPKCS1v15(rand.Reader, idp.rsaKey, crypto.SHA256, sum[:])
		if err != nil {
			panic(err)
		}
		sig = s
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, idp.ecKey, sum[:])
		if err != nil {
			panic(err)
		}
		sig = append(pad32(r.Bytes()), pad32(s.Bytes())...)
	case "HS256":
		m := hmac.New(sha256.New, idp.rsaKey.N.Bytes())
		m.Write([]byte(input))
		sig = m.Sum(nil)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// Fetches reports how many times the JWKS has been served.
func (idp *IdP) Fetches() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.fetches
}

// ecPoint is the uncompressed SEC 1 encoding of k's public key: 0x04 || X || Y.
func ecPoint(k *ecdsa.PrivateKey) []byte {
	b, err := k.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}
