// Command mcpbridge runs a stdio MCP server and exposes it as an authenticated
// Streamable HTTP endpoint (POST/GET/DELETE /mcp) for the MCP gateway.
//
//	mcpbridge -- npx -y @modelcontextprotocol/server-filesystem /workspace
//
// Configuration (environment variables):
//
//	AGENTBOX_BRIDGE_TOKEN / _FILE      bearer token clients must present (>= 32 chars)
//	AGENTBOX_BRIDGE_LISTEN             listen address (default :9000)
//	AGENTBOX_BRIDGE_ALLOWED_HOSTS      comma-separated Host names to accept (default: any)
//	AGENTBOX_BRIDGE_REQUEST_TIMEOUT    per-request timeout (default 120s)
//	AGENTBOX_BRIDGE_ENV_<NAME>=value   passes NAME=value to the MCP server
//	AGENTBOX_BRIDGE_ENV_FILE_<NAME>=p  passes NAME=<contents of file p> to the MCP server
//
// The MCP server inherits only PATH, HOME, LANG and TMPDIR plus the variables
// above; the bridge's own token and the rest of the container environment are
// never visible to it. If the MCP server exits, so does the bridge, so the
// container supervisor can restart the pair.
//
// "mcpbridge healthcheck" probes /healthz for use as a container HEALTHCHECK.
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

	"github.com/Oleg-Imanilov/agent-box/internal/stdiobridge"
	"github.com/Oleg-Imanilov/agent-box/internal/version"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version":
			fmt.Println(version.String("agentbox-mcpbridge"))
			return
		case "healthcheck":
			os.Exit(healthcheck())
		}
	}
	cmd := args
	if len(cmd) > 0 && cmd[0] == "--" {
		cmd = cmd[1:]
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log, cmd); err != nil {
		log.Error("mcpbridge exited", "err", err)
		os.Exit(1)
	}
}

func listenAddr() string {
	if v := os.Getenv("AGENTBOX_BRIDGE_LISTEN"); v != "" {
		return v
	}
	return ":9000"
}

func healthcheck() int {
	_, port, err := net.SplitHostPort(listenAddr())
	if err != nil {
		return 1
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", port)+"/healthz", nil)
	if err != nil {
		return 1
	}
	if hosts := os.Getenv("AGENTBOX_BRIDGE_ALLOWED_HOSTS"); hosts != "" {
		req.Host = strings.TrimSpace(strings.Split(hosts, ",")[0])
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func readToken() (string, error) {
	if f := os.Getenv("AGENTBOX_BRIDGE_TOKEN_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read AGENTBOX_BRIDGE_TOKEN_FILE: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv("AGENTBOX_BRIDGE_TOKEN"), nil
}

// childEnv collects AGENTBOX_BRIDGE_ENV_* and AGENTBOX_BRIDGE_ENV_FILE_*.
func childEnv() ([]string, error) {
	const (
		plain = "AGENTBOX_BRIDGE_ENV_"
		file  = "AGENTBOX_BRIDGE_ENV_FILE_"
	)
	var out []string
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(k, file):
			name := strings.TrimPrefix(k, file)
			b, err := os.ReadFile(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out = append(out, name+"="+strings.TrimSpace(string(b)))
		case strings.HasPrefix(k, plain):
			out = append(out, strings.TrimPrefix(k, plain)+"="+v)
		}
	}
	return out, nil
}

func run(log *slog.Logger, command []string) error {
	if len(command) == 0 {
		return errors.New("usage: mcpbridge -- <mcp server command> [args...]")
	}
	tok, err := readToken()
	if err != nil {
		return err
	}
	env, err := childEnv()
	if err != nil {
		return err
	}
	cfg := stdiobridge.Config{Command: command, Env: env, Token: tok, Logger: log}
	if v := os.Getenv("AGENTBOX_BRIDGE_REQUEST_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return fmt.Errorf("AGENTBOX_BRIDGE_REQUEST_TIMEOUT: invalid duration %q", v)
		}
		cfg.RequestTimeout = d
	}
	for _, h := range strings.Split(os.Getenv("AGENTBOX_BRIDGE_ALLOWED_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.AllowedHosts = append(cfg.AllowedHosts, h)
		}
	}
	b, err := stdiobridge.New(cfg)
	if err != nil {
		return err
	}
	if err := b.Start(); err != nil {
		return err
	}
	defer b.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           b.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("mcpbridge listening", "addr", srv.Addr, "command", command[0], "version", version.Version)
		errCh <- srv.ListenAndServe()
	}()

	var result error
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			result = err
		}
	case <-b.Done():
		// Fail closed: the wrapped server is gone, so stop serving.
		result = fmt.Errorf("mcp server process exited: %v", b.Err())
	case <-ctx.Done():
		log.Info("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return result
}
