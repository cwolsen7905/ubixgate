package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// keySet fetches and caches a JWKS. An unknown key ID triggers a refetch, at most once
// per minRefresh, so a key rotation at the IdP is picked up without a restart and a
// stream of bogus key IDs cannot turn the gateway into a JWKS flooder.
type keySet struct {
	url        string
	client     *http.Client
	maxAge     time.Duration
	minRefresh time.Duration

	mu      sync.Mutex
	keys    map[string]jwk
	fetched time.Time
}

type jwk struct {
	alg string // the JWK's own alg, if it declared one
	key crypto.PublicKey
}

func newKeySet(url string, client *http.Client) *keySet {
	return &keySet{url: url, client: client, maxAge: time.Hour, minRefresh: 30 * time.Second}
}

// get returns the key for kid. An empty kid is accepted only when the set holds exactly
// one key.
func (ks *keySet) get(ctx context.Context, kid string) (jwk, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if k, ok := ks.lookup(kid); ok && time.Since(ks.fetched) < ks.maxAge {
		return k, nil
	}
	if time.Since(ks.fetched) >= ks.minRefresh {
		if err := ks.fetch(ctx); err != nil {
			// Keep serving cached keys if the IdP is briefly unreachable.
			if k, ok := ks.lookup(kid); ok {
				return k, nil
			}
			return jwk{}, err
		}
	}
	if k, ok := ks.lookup(kid); ok {
		return k, nil
	}
	return jwk{}, fmt.Errorf("no key with id %q in the JWKS", kid)
}

func (ks *keySet) lookup(kid string) (jwk, bool) {
	if kid == "" && len(ks.keys) == 1 {
		for _, k := range ks.keys {
			return k, true
		}
	}
	k, ok := ks.keys[kid]
	return k, ok
}

// fetch replaces the cached keys. Called with ks.mu held.
func (ks *keySet) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ks.url, nil)
	if err != nil {
		return err
	}
	resp, err := ks.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	keys := map[string]jwk{}
	for _, raw := range doc.Keys {
		kid, k, err := parseJWK(raw)
		if err != nil {
			continue // skip keys we do not use (enc keys, other curves) rather than fail the set
		}
		keys[kid] = k
	}
	if len(keys) == 0 {
		return errors.New("JWKS holds no usable RS256 or ES256 signing keys")
	}
	ks.keys, ks.fetched = keys, time.Now()
	return nil
}

func parseJWK(raw json.RawMessage) (string, jwk, error) {
	var k struct {
		Kty, Kid, Alg, Use, Crv, N, E, X, Y string
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", jwk{}, err
	}
	if k.Use != "" && k.Use != "sig" {
		return "", jwk{}, errors.New("not a signing key")
	}
	num := func(s string) (*big.Int, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) == 0 {
			return nil, errors.New("bad key number")
		}
		return new(big.Int).SetBytes(b), nil
	}
	switch k.Kty {
	case "RSA":
		n, err := num(k.N)
		if err != nil {
			return "", jwk{}, err
		}
		e, err := num(k.E)
		if err != nil || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 {
			return "", jwk{}, errors.New("bad RSA exponent")
		}
		if n.BitLen() < 2048 {
			return "", jwk{}, errors.New("RSA key shorter than 2048 bits")
		}
		return k.Kid, jwk{alg: k.Alg, key: &rsa.PublicKey{N: n, E: int(e.Int64())}}, nil
	case "EC":
		if k.Crv != "P-256" {
			return "", jwk{}, errors.New("only P-256 is supported")
		}
		x, errx := base64.RawURLEncoding.DecodeString(k.X)
		y, erry := base64.RawURLEncoding.DecodeString(k.Y)
		if errx != nil || erry != nil || len(x) != 32 || len(y) != 32 {
			return "", jwk{}, errors.New("bad EC coordinates")
		}
		// Rejects points that are not on the curve.
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return "", jwk{}, fmt.Errorf("bad EC key: %w", err)
		}
		return k.Kid, jwk{alg: k.Alg, key: pub}, nil
	}
	return "", jwk{}, fmt.Errorf("unsupported key type %q", k.Kty)
}
