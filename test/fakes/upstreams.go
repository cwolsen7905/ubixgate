package fakes

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TicketArgs are the arguments every tickets tool takes.
type TicketArgs struct {
	Project string `json:"project" jsonschema:"repository the ticket belongs to, like myorg/web"`
	Title   string `json:"title,omitempty" jsonschema:"ticket title"`
	ID      int    `json:"id,omitempty" jsonschema:"ticket number"`
}

// Tickets is a fake ticket tracker served over Streamable HTTP. It refuses any request
// whose Authorization header is not "Bearer <Token>", the credential the gateway
// injects from Vault. It records the headers it saw, so tests can prove the caller's
// own token never arrived.
type Tickets struct {
	Token    string
	Identity string // what the tool replies it is authenticated as
	Versions []string

	mu      sync.Mutex
	seen    []http.Header
	refused int
}

// Handler returns the HTTP handler for the MCP endpoint.
func (tk *Tickets) Handler() http.Handler {
	s := mcp.NewServer(&mcp.Implementation{Name: "tickets", Version: "0.0.1"},
		&mcp.ServerOptions{SupportedProtocolVersions: tk.Versions})
	reply := func(verb string) mcp.ToolHandlerFor[TicketArgs, any] {
		return func(_ context.Context, _ *mcp.CallToolRequest, in TicketArgs) (*mcp.CallToolResult, any, error) {
			text := fmt.Sprintf("authenticated as %s: %s in %s", tk.Identity, verb, in.Project)
			if in.Project == "" {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "project is required"}}}, nil, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
		}
	}
	mcp.AddTool(s, &mcp.Tool{Name: "ticket_create", Description: "Open a ticket."}, reply("created ticket"))
	mcp.AddTool(s, &mcp.Tool{Name: "ticket_list", Description: "List open tickets."}, reply("listed tickets"))
	mcp.AddTool(s, &mcp.Tool{Name: "ticket_delete", Description: "Delete a ticket."}, reply("deleted ticket"))
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tk.mu.Lock()
		tk.seen = append(tk.seen, r.Header.Clone())
		ok := r.Header.Get("Authorization") == "Bearer "+tk.Token
		if !ok {
			tk.refused++
		}
		tk.mu.Unlock()
		if !ok {
			http.Error(w, "missing or wrong service token", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// SetToken changes the token the server accepts, as a rotation would.
func (tk *Tickets) SetToken(t string) {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	tk.Token = t
}

// SawHeaderValue reports whether any request carried a header containing s.
func (tk *Tickets) SawHeaderValue(s string) bool {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	for _, h := range tk.seen {
		for _, vs := range h {
			for _, v := range vs {
				if strings.Contains(v, s) {
					return true
				}
			}
		}
	}
	return false
}

// Refused reports how many requests were refused for a bad token.
func (tk *Tickets) Refused() int {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	return tk.refused
}

// EnvTool is the name of the stdio fake's tool that reports an environment variable.
const EnvTool = "env_has"

// ServeStdio runs a fake MCP server on stdin and stdout that speaks only 2025-11-25,
// like many stdio servers today. Its tools: "status" (read only), "lane_delete", and
// env_has, which says whether the named environment variable equals a value without
// echoing it.
func ServeStdio(ctx context.Context) error {
	s := mcp.NewServer(&mcp.Implementation{Name: "stdio-fake", Version: "0.0.1"},
		&mcp.ServerOptions{SupportedProtocolVersions: []string{"2025-11-25"}})
	type envArgs struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: EnvTool, Description: "Check an environment variable."},
		func(_ context.Context, _ *mcp.CallToolRequest, in envArgs) (*mcp.CallToolResult, any, error) {
			got, set := os.LookupEnv(in.Name)
			text := fmt.Sprintf("%s set=%v match=%v", in.Name, set, set && got == in.Value)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
		})
	type none struct{}
	mcp.AddTool(s, &mcp.Tool{Name: "status", Description: "Report status."},
		func(context.Context, *mcp.CallToolRequest, none) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "all quiet"}}}, nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "lane_delete", Description: "Delete a lane."},
		func(context.Context, *mcp.CallToolRequest, none) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deleted"}}}, nil, nil
		})
	return s.Run(ctx, &mcp.StdioTransport{})
}
