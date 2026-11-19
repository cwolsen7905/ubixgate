// Command demo-idp is a toy identity provider for the demo. It serves a JWKS and hands
// out signed JWTs for two fixed users, so the gateway's real JWT path runs with no
// accounts or keys. Never use it for anything else: it gives a token to anyone who asks.
//
//	GET /jwks              the public keys
//	GET /token?user=alice  a one-hour RS256 token for alice (developers) or bob (contractors)
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ubixsys/ubixgate/test/fakes"
)

var users = map[string][]string{
	"alice": {"developers"},
	"bob":   {"contractors"},
}

func main() {
	issuer := env("DEMO_IDP_ISSUER", "http://localhost:9100")
	audience := env("DEMO_IDP_AUDIENCE", "http://localhost:8080/mcp")
	addr := env("DEMO_IDP_LISTEN", ":9100")
	idp := fakes.NewIdPHandler(issuer)

	http.Handle("/jwks", idp)
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		groups, ok := users[user]
		if !ok {
			http.Error(w, "unknown user; try alice or bob", http.StatusNotFound)
			return
		}
		client := r.URL.Query().Get("client")
		if client == "" {
			client = "demo-cli"
		}
		fmt.Fprintln(w, idp.Mint(idp.Claims(user, audience, groups, client)))
	})
	log.Printf("demo-idp: issuer %s, audience %s, listening on %s", issuer, audience, addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
