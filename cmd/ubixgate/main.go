// Command ubixgate is an MCP gateway: one authenticated Streamable HTTP endpoint in front
// of many upstream MCP servers, with per-call policy, credential injection and audit.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/ubixsys/ubixgate/internal/version"
)

const usage = `usage: ubixgate <command>

commands:
  version   print the version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "ubixgate %s\n", version.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "ubixgate: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
