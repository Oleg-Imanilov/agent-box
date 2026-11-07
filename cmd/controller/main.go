// Command controller is the policy, audit and API service. It runs in a
// container on the control network (never on the agent network) and never has
// access to the Docker socket.
//
// Configuration (environment variables):
//
//	AGENTBOX_DB                 SQLite path (default /data/agentbox.db)
//	AGENTBOX_LISTEN             listen address (default 127.0.0.1:8080)
//	AGENTBOX_ADMIN_TOKEN        admin bearer token (>= 32 chars), or
//	AGENTBOX_ADMIN_TOKEN_FILE   path to a file containing it
//	AGENTBOX_ALLOWED_HOSTS      comma-separated Host/Origin names (default localhost,127.0.0.1,::1)
//	AGENTBOX_ALLOW_CACHE_TTL    how long gateways may cache allow decisions (default 5s, 0 disables)
//
// "controller healthcheck" probes /healthz on the configured address, for use
// as a container HEALTHCHECK.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/audit"
	"github.com/Oleg-Imanilov/agent-box/internal/controller"
	"github.com/Oleg-Imanilov/agent-box/internal/policy"
	"github.com/Oleg-Imanilov/agent-box/internal/store"
	"github.com/Oleg-Imanilov/agent-box/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println(version.String("agentbox-controller"))
			return
		case "healthcheck":
			os.Exit(healthcheck())
		default:
			fmt.Fprintf(os.Stderr, "unknown argument %q\n", os.Args[1])
			os.Exit(2)
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("controller exited", "err", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func listenAddr() string { return env("AGENTBOX_LISTEN", "127.0.0.1:8080") }

func healthcheck() int {
	host, port, err := net.SplitHostPort(listenAddr())
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/healthz", nil)
	if err != nil {
		return 1
	}
	req.Host = "localhost"
	resp, err := c.Do(req)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func adminToken() (string, error) {
	if f := os.Getenv("AGENTBOX_ADMIN_TOKEN_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read admin token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv("AGENTBOX_ADMIN_TOKEN"), nil
}

func run(log *slog.Logger) error {
	tok, err := adminToken()
	if err != nil {
		return err
	}
	if len(tok) < controller.MinAdminTokenLen {
		return fmt.Errorf("admin token missing or shorter than %d characters (set AGENTBOX_ADMIN_TOKEN or AGENTBOX_ADMIN_TOKEN_FILE)", controller.MinAdminTokenLen)
	}
	var hosts []string
	for _, h := range strings.Split(os.Getenv("AGENTBOX_ALLOWED_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	cacheTTL := 5 * time.Second
	if v := os.Getenv("AGENTBOX_ALLOW_CACHE_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return fmt.Errorf("AGENTBOX_ALLOW_CACHE_TTL: invalid duration %q", v)
		}
		cacheTTL = d
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, env("AGENTBOX_DB", "/data/agentbox.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	al := audit.NewLogger(st, audit.Options{OnError: func(err error) { log.Error("audit write failed", "err", err) }})
	srv, err := controller.New(controller.Config{
		AdminToken: tok, AllowedHosts: hosts, AllowCacheTTL: cacheTTL, Version: version.Version, Logger: log,
	}, st, policy.NewEngine(), al)
	if err != nil {
		return err
	}
	if err := srv.LoadState(ctx); err != nil {
		return fmt.Errorf("load state: %w", err)
	}

	go audit.RunRetention(ctx, st, time.Hour, srv.RetentionDays, func(err error) { log.Error("audit retention failed", "err", err) })

	httpSrv := &http.Server{
		Addr:              listenAddr(),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("controller listening", "addr", httpSrv.Addr, "version", version.Version)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return al.Close(shutdownCtx)
}
