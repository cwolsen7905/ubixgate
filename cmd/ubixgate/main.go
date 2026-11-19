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
	"syscall"
	"time"

	"github.com/ubixsys/ubixgate/internal/config"
	"github.com/ubixsys/ubixgate/internal/gateway"
	"github.com/ubixsys/ubixgate/internal/ops"
	"github.com/ubixsys/ubixgate/internal/version"
)

const usage = `usage: ubixgate <command> [flags]

commands:
  serve -config FILE   run the gateway (SIGHUP reloads the policy)
  check FILE           validate a config file and exit
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
