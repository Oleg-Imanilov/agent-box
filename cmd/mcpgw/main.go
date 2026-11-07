// Command mcpgw is the AgentBox MCP gateway. Agents are configured with
// http://<this host>:<port>/mcp/<server> and never see real MCP servers.
//
// Configuration (environment variables):
//
//	AGENTBOX_CONTROLLER_URL       controller base URL (required)
//	AGENTBOX_GATEWAY_TOKEN        per-session token, or
//	AGENTBOX_GATEWAY_TOKEN_FILE   path to a file containing it
//	AGENTBOX_MCPGW_SERVERS_FILE   JSON array of upstream servers (required):
//	                              [{"name":"github","url":"http://bridge-github:9000/mcp",
//	                                "bearer_file":"/run/secrets/github-bridge"}]
//	AGENTBOX_MCPGW_LISTEN         listen address (default :8081)
//	AGENTBOX_MCPGW_ALLOWED_HOSTS  comma-separated Host names to accept (default: any)
//	AGENTBOX_MCPGW_APPROVALS      "true" to hold default-denied tool calls for human approval
//
// "mcpgw healthcheck" probes /healthz for use as a container HEALTHCHECK.
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
	"strings"
	"syscall"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
	"github.com/Oleg-Imanilov/agent-box/internal/mcpgw"
	"github.com/Oleg-Imanilov/agent-box/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println(version.String("agentbox-mcpgw"))
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
		log.Error("mcpgw exited", "err", err)
		os.Exit(1)
	}
}

func listenAddr() string {
	if v := os.Getenv("AGENTBOX_MCPGW_LISTEN"); v != "" {
		return v
	}
	return ":8081"
}

func healthcheck() int {
	_, port, err := net.SplitHostPort(listenAddr())
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", port)+"/healthz", nil)
	if err != nil {
		return 1
	}
	if hosts := os.Getenv("AGENTBOX_MCPGW_ALLOWED_HOSTS"); hosts != "" {
		req.Host = strings.TrimSpace(strings.Split(hosts, ",")[0])
	}
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

func token() (string, error) {
	if f := os.Getenv("AGENTBOX_GATEWAY_TOKEN_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read AGENTBOX_GATEWAY_TOKEN_FILE: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv("AGENTBOX_GATEWAY_TOKEN"), nil
}

func run(log *slog.Logger) error {
	tok, err := token()
	if err != nil {
		return err
	}
	client, err := gwclient.New(os.Getenv("AGENTBOX_CONTROLLER_URL"), tok, gwclient.Options{})
	if err != nil {
		return err
	}
	path := os.Getenv("AGENTBOX_MCPGW_SERVERS_FILE")
	if path == "" {
		return errors.New("AGENTBOX_MCPGW_SERVERS_FILE is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read servers file: %w", err)
	}
	var servers []mcpgw.Server
	if err := json.Unmarshal(b, &servers); err != nil {
		return fmt.Errorf("parse servers file: %w", err)
	}
	cfg := mcpgw.Config{
		Controller: client,
		Servers:    servers,
		Approvals:  os.Getenv("AGENTBOX_MCPGW_APPROVALS") == "true",
		Logger:     log,
	}
	for _, h := range strings.Split(os.Getenv("AGENTBOX_MCPGW_ALLOWED_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.AllowedHosts = append(cfg.AllowedHosts, h)
		}
	}
	gw, err := mcpgw.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{
		Addr:    listenAddr(),
		Handler: gw.Handler(),
		// No Read/WriteTimeout: SSE streams are long-lived. Individual
		// upstream calls are bounded by the gateway's transport timeouts.
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("mcpgw listening", "addr", srv.Addr, "servers", len(servers), "approvals", cfg.Approvals, "version", version.Version)
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
