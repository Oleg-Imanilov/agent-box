// Command netgw is the AgentBox network gateway. It is the only container
// (besides the MCP gateway) attached to both the isolated agent network and an
// egress network.
//
// Configuration (environment variables):
//
//	AGENTBOX_CONTROLLER_URL       controller base URL (required)
//	AGENTBOX_GATEWAY_TOKEN        per-session token, or
//	AGENTBOX_GATEWAY_TOKEN_FILE   path to a file containing it
//	AGENTBOX_NETGW_LISTEN         listen address (default :3128)
//	AGENTBOX_NETGW_PROVIDERS_FILE JSON array of LLM providers served at /llm/<name>/
//	AGENTBOX_NETGW_APPROVALS      "true" to hold default-denied requests for human approval
//	AGENTBOX_NETGW_MAX_CONNS      concurrent connection limit (default 512)
//	AGENTBOX_NETGW_IDLE_TIMEOUT   idle tunnel timeout (default 5m)
//
// "netgw healthcheck" probes /healthz for use as a container HEALTHCHECK.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/netgw"
	"github.com/Oleg-Imanilov/agent-box/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println(version.String("agentbox-netgw"))
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
		log.Error("netgw exited", "err", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func listenAddr() string { return env("AGENTBOX_NETGW_LISTEN", ":3128") }

func healthcheck() int {
	_, port, err := net.SplitHostPort(listenAddr())
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func secret(name string) (string, error) {
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(name), nil
}

func loadProviders(path string) ([]netgw.Provider, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read providers file: %w", err)
	}
	var ps []netgw.Provider
	if err := json.Unmarshal(b, &ps); err != nil {
		return nil, fmt.Errorf("parse providers file: %w", err)
	}
	return ps, nil
}

func run(log *slog.Logger) error {
	token, err := secret("AGENTBOX_GATEWAY_TOKEN")
	if err != nil {
		return err
	}
	client, err := gwclient.New(os.Getenv("AGENTBOX_CONTROLLER_URL"), token, gwclient.Options{})
	if err != nil {
		return err
	}
	providers, err := loadProviders(os.Getenv("AGENTBOX_NETGW_PROVIDERS_FILE"))
	if err != nil {
		return err
	}
	cfg := netgw.Config{
		Controller: client,
		Approvals:  os.Getenv("AGENTBOX_NETGW_APPROVALS") == "true",
		Providers:  providers,
		Logger:     log,
	}
	if v := os.Getenv("AGENTBOX_NETGW_MAX_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("AGENTBOX_NETGW_MAX_CONNS: invalid value %q", v)
		}
		cfg.MaxConns = n
	}
	if v := os.Getenv("AGENTBOX_NETGW_IDLE_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return fmt.Errorf("AGENTBOX_NETGW_IDLE_TIMEOUT: invalid duration %q", v)
		}
		cfg.IdleTimeout = d
	}
	gw, err := netgw.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    listenAddr(),
		Handler: gw.Handler(),
		// No Read/WriteTimeout: tunnels and streamed completions are long-lived;
		// idle tunnels are closed by the gateway itself.
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("netgw listening", "addr", srv.Addr, "providers", len(providers), "approvals", cfg.Approvals, "version", version.Version)
		errCh <- srv.ListenAndServe()
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
	_ = srv.Shutdown(shutdownCtx)
	gw.Wait()
	return nil
}
