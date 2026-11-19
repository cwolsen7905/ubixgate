// Command tickets is the demo's fake ticket tracker: an MCP server over Streamable HTTP
// that refuses every request without the service token. The token is read from a file
// written by the demo's Vault init step; the gateway gets the same value from Vault.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ubixsys/ubixgate/test/fakes"
)

func main() {
	path := env("TICKETS_TOKEN_FILE", "/shared/tickets-token")
	addr := env("TICKETS_LISTEN", ":9000")
	var token string
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
		b, err := os.ReadFile(path)
		if token = strings.TrimSpace(string(b)); err == nil && token != "" {
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("tickets: no token in %s", path)
		}
	}
	tk := &fakes.Tickets{Token: token, Identity: "svc-tickets"}
	http.Handle("/mcp", tk.Handler())
	log.Printf("tickets: listening on %s, requiring the service token from %s", addr, path)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
