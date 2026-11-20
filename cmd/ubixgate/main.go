// Command ubixgate is an MCP gateway: one authenticated Streamable HTTP endpoint in front
// of many upstream MCP servers, with per-call policy, credential injection and audit.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ubixsys/ubixgate/internal/audit"
	"github.com/ubixsys/ubixgate/internal/config"
	"github.com/ubixsys/ubixgate/internal/gateway"
	"github.com/ubixsys/ubixgate/internal/ops"
	"github.com/ubixsys/ubixgate/internal/policy"
	"github.com/ubixsys/ubixgate/internal/version"
)

const usage = `usage: ubixgate <command> [flags]

commands:
  serve -config FILE   run the gateway (SIGHUP reloads the policy)
  check FILE           validate a config file and exit
  policy explain -tool SERVER__TOOL -user U [-groups G1,G2] [-client C]
                 [-arg KEY=VALUE]... [-client-request KIND] [-config FILE]
                       print the decision and the rule that made it, offline
  audit verify [-config FILE] [-key KEYFILE] [-from CHAIN] [AUDIT_FILE]
                       check a chained audit log; name the first broken line
  version              print the version
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
	case "check":
		if len(args) != 2 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		if _, err := config.Load(args[1]); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "%s: ok\n", args[1])
		return 0
	case "policy":
		if len(args) < 2 || args[1] != "explain" {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return explain(args[2:], stdout, stderr)
	case "audit":
		if len(args) < 2 || args[1] != "verify" {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return verifyAudit(args[2:], stdout, stderr)
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("config", "ubixgate.yaml", "config file")
		level := fs.String("log-level", "info", "debug, info, warn or error")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := serve(*path, *level); err != nil {
			fmt.Fprintln(stderr, "ubixgate:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "ubixgate: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// explain answers "why was I denied" without a live call, with the gateway's own
// decision step. Exit status: 0 allowed, 1 denied or a bad config, 2 usage.
func explain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "ubixgate.yaml", "config file")
	user := fs.String("user", "", "user, as the identity claim gives it")
	groups := fs.String("groups", "", "comma-separated groups")
	client := fs.String("client", "", "client, as the signed claim gives it")
	name := fs.String("tool", "", "full tool name, server__tool")
	kind := fs.String("client-request", "", "decide an upstream request to the client instead: elicitation, sampling or roots")
	callArgs := map[string]any{}
	fs.Func("arg", "a top-level string argument, KEY=VALUE (repeatable)", func(s string) error {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return errors.New("want KEY=VALUE")
		}
		callArgs[k] = v
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *user == "" || *name == "" || fs.NArg() > 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	pol, err := gateway.Policy(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	p := policy.Principal{User: *user, Client: *client}
	if *groups != "" {
		p.Groups = strings.Split(*groups, ",")
	}
	server, tool, _ := strings.Cut(*name, gateway.Sep)
	known := tool != "" && cfg.Upstream(server) != nil
	dec, shown := gateway.Decide(context.Background(), pol, policy.Request{Principal: p, Server: server, Tool: tool,
		Args: callArgs, ClientRequest: *kind}, known)

	fmt.Fprintf(stdout, "decision: %s\nrule:     %s\n", dec.Effect, dec.Rule)
	if shown != dec.Rule {
		fmt.Fprintf(stdout, "shown:    denied by rule %s (what the caller sees)\n", shown)
	}
	if *kind == "" {
		fmt.Fprintf(stdout, "listed:   %v\n", known && pol.Visible(p, server, tool))
	}
	if len(dec.AuditArgs) > 0 {
		fmt.Fprintf(stdout, "logged:   %s\n", strings.Join(dec.AuditArgs, ", "))
	}
	fmt.Fprintln(stdout, "Offline: a tool on a configured upstream is assumed to exist; the per-user limit, credentials and the upstream are not checked.")
	if !dec.Allowed() {
		return 1
	}
	return 0
}

// verifyAudit checks a chained audit log. The key and file come from the config unless
// given. Exit status: 0 intact, 1 broken or unreadable, 2 usage.
func verifyAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "ubixgate.yaml", "config file, for audit.path and audit.chain_key_file")
	keyFile := fs.String("key", "", "chain key file; overrides the config's")
	from := fs.String("from", "", "the last chain of the file before this one, for a log that was rotated by copying")
	if err := fs.Parse(args); err != nil || fs.NArg() > 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	logFile := fs.Arg(0)
	if *keyFile == "" || logFile == "" {
		cfg, err := config.Load(*path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if *keyFile == "" {
			*keyFile = cfg.Audit.ChainKeyFile
		}
		if logFile == "" {
			logFile = cfg.Audit.Path
		}
	}
	if *keyFile == "" {
		fmt.Fprintln(stderr, "ubixgate: no chain key: set audit.chain_key_file or pass -key")
		return 1
	}
	key, err := gateway.ReadKey(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "ubixgate:", err)
		return 1
	}
	f, err := os.Open(logFile)
	if err != nil {
		fmt.Fprintln(stderr, "ubixgate:", err)
		return 1
	}
	defer f.Close()
	n, last, err := audit.Verify(f, key, *from)
	if err != nil {
		fmt.Fprintf(stdout, "%s: %v\n", logFile, err)
		switch {
		case n == 1:
			fmt.Fprintln(stdout, "Line 1 verifies.")
		case n > 1:
			fmt.Fprintf(stdout, "Lines 1 to %d verify.\n", n)
		}
		return 1
	}
	fmt.Fprintf(stdout, "%s: ok, %d records\nlast chain: %s\n", logFile, n, last)
	fmt.Fprintln(stdout, "Lines removed from the end cannot be detected here: compare the last chain with a copy kept elsewhere.")
	return 0
}

func serve(path, level string) error {
	log := ops.Logger(level)
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rt, err := gateway.Build(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer rt.Close()
	rt.Start(ctx)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			next, err := config.Load(path)
			if err == nil {
				err = rt.Reload(next)
			}
			if err != nil {
				log.Error("reload failed; keeping the current policy", "err", err)
				continue
			}
			log.Info("policy reloaded")
		}
	}()

	srv := &http.Server{Addr: cfg.Listen, Handler: rt.Handler, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("ubixgate listening", "addr", cfg.Listen, "endpoint", cfg.PublicURL, "version", version.Version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
