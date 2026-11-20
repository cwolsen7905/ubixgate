package fakes

import (
	"encoding/json"
	"fmt"
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
	dynamic map[string]dynamicSecret  // path to a secret issued with a new lease per read
	revoked []string
	leases  int
	reads   int
	down    bool
}

type dynamicSecret struct {
	data     map[string]any
	ttl      int
	topLevel bool // HashiCorp Vault's envelope; otherwise inside data, as uBixVault sends it
}

// PutDynamic serves a dynamic secret at path: each read issues a new lease ("lease-N")
// of ttl seconds. With topLevel the lease is in the envelope, as HashiCorp Vault sends
// it; otherwise inside data, as uBixVault's database engine does.
func (v *Vault) PutDynamic(path string, data map[string]any, ttl int, topLevel bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dynamic[path] = dynamicSecret{data: data, ttl: ttl, topLevel: topLevel}
}

// Revoked reports the lease IDs revoked so far, in order.
func (v *Vault) Revoked() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.revoked...)
}

// NewVault starts a fake Vault with one AppRole.
func NewVault() *Vault {
	v := &Vault{RoleID: "role-1", SecretID: "secret-1", Token: "hvs.fake-gateway-token", secrets: map[string]map[string]any{},
		dynamic: map[string]dynamicSecret{}}
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
	case path == "sys/leases/revoke" && r.Method == http.MethodPut:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		v.revoked = append(v.revoked, body["lease_id"])
		w.WriteHeader(http.StatusNoContent)
	case v.dynamic[path].data != nil:
		d := v.dynamic[path]
		v.leases++
		v.reads++
		id := fmt.Sprintf("lease-%d", v.leases)
		data := map[string]any{}
		for k, val := range d.data {
			data[k] = val
		}
		if d.topLevel {
			reply(200, map[string]any{"lease_id": id, "lease_duration": d.ttl, "data": data})
			return
		}
		data["lease_id"], data["lease_duration"] = id, d.ttl
		reply(200, map[string]any{"data": data})
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
