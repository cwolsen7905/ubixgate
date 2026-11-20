package fakes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	pathpkg "path"
	"strings"
	"sync"
)

// Vault is a fake Vault-API server: AppRole login, token lookup and renewal, KV v2 reads
// and the health endpoint. Only the issued token may read.
type Vault struct {
	Server   *httptest.Server
	RoleID   string
	SecretID string
	Token    string

	mu      sync.Mutex
	secrets map[string]map[string]any // KV v2 path ("secret/data/x") to data
	reads   int
	down    bool
}

// NewVault starts a fake Vault with one AppRole.
func NewVault() *Vault {
	v := &Vault{RoleID: "role-1", SecretID: "secret-1", Token: "hvs.fake-gateway-token", secrets: map[string]map[string]any{}}
	v.Server = httptest.NewServer(v)
	return v
}

// Put stores a KV v2 secret at path (for example "secret/data/mcp/tickets").
func (v *Vault) Put(path string, data map[string]any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.secrets[path] = data
}

// Reads reports how many secret reads were served.
func (v *Vault) Reads() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.reads
}

// SetDown makes every request fail with 503 until called with false.
func (v *Vault) SetDown(down bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.down = down
}

func (v *Vault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	reply := func(code int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}
	fail := func(code int, msg string) { reply(code, map[string]any{"errors": []string{msg}}) }
	if v.down {
		fail(http.StatusServiceUnavailable, "sealed")
		return
	}
	// Resolve dot segments, as servers and proxies in front of Vault may.
	path := strings.TrimPrefix(pathpkg.Clean(r.URL.Path), "/v1/")
	switch {
	case path == "sys/health":
		reply(200, map[string]any{"initialized": true, "sealed": false})
	case path == "auth/approle/login" && r.Method == http.MethodPost:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != v.RoleID || body["secret_id"] != v.SecretID {
			fail(http.StatusBadRequest, "invalid role or secret ID")
			return
		}
		reply(200, map[string]any{"auth": map[string]any{"client_token": v.Token, "lease_duration": 3600}})
	case r.Header.Get("X-Vault-Token") != v.Token:
		fail(http.StatusForbidden, "permission denied")
	case path == "auth/token/lookup-self":
		reply(200, map[string]any{"data": map[string]any{"ttl": 3600}})
	case path == "auth/token/renew-self":
		reply(200, map[string]any{"auth": map[string]any{"client_token": v.Token, "lease_duration": 3600}})
	default:
		data, ok := v.secrets[path]
		if !ok {
			fail(http.StatusNotFound, "no secret at "+path)
			return
		}
		v.reads++
		reply(200, map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}}})
	}
}
