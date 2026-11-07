package netgw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/gwclient"
)

// Handler returns the gateway's HTTP handler. It serves:
//
//	CONNECT host:port          tunnels (HTTPS and other TCP) through policy
//	GET http://host/path ...   plain HTTP proxying through policy
//	/llm/<provider>/...        reverse proxy that injects provider credentials
//	/healthz                   liveness
func (g *Gateway) Handler() http.Handler {
	fwd := g.forwardProxy()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodConnect:
			g.handleConnect(w, r)
		case r.URL.IsAbs():
			if r.URL.Scheme != "http" {
				http.Error(w, "use CONNECT for https", http.StatusBadRequest)
				return
			}
			fwd.ServeHTTP(w, r)
		case r.URL.Path == "/healthz":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		case strings.HasPrefix(r.URL.Path, "/llm/"):
			g.handleLLM(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// writeDeniedOrError maps a Dial error to an HTTP response.
func writeDeniedOrError(w http.ResponseWriter, err error) {
	var denied *DeniedError
	if errors.As(err, &denied) {
		w.Header().Set("X-AgentBox-Decision", "deny")
		w.Header().Set("X-AgentBox-Rule", denied.Decision.RuleID)
		http.Error(w, "blocked by AgentBox policy: "+denied.Reason, http.StatusForbidden)
		return
	}
	if errors.Is(err, context.Canceled) {
		http.Error(w, "request cancelled", 499)
		return
	}
	http.Error(w, "upstream connection failed", http.StatusBadGateway)
}

func (g *Gateway) acquire() bool {
	select {
	case g.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *Gateway) release() { <-g.sem }

func (g *Gateway) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	if !g.acquire() {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer g.release()

	upstream, err := g.Dial(r.Context(), host, port)
	if err != nil {
		writeDeniedOrError(w, err)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "tunneling unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	// Bytes the client sent right after the CONNECT request.
	var early []byte
	if n := rw.Reader.Buffered(); n > 0 {
		early, _ = rw.Reader.Peek(n)
	}

	started := time.Now()
	up, down := g.tunnel(client, upstream, early)
	g.reportAsync(gwclient.Event{Kind: "network", Destination: hostPort(host, port), Operation: "connect.closed", Decision: "info",
		Metadata: map[string]any{"bytes_up": up, "bytes_down": down, "duration_ms": time.Since(started).Milliseconds()}})
}

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// idleConn extends the deadline on every read/write so that idle tunnels are
// closed while active ones are not.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

type closeWriter interface{ CloseWrite() error }

// tunnel copies bytes both ways until either side closes or idles out and
// returns the byte counts (client→upstream, upstream→client).
func (g *Gateway) tunnel(client, upstream net.Conn, early []byte) (up, down int64) {
	c := &idleConn{Conn: client, idle: g.cfg.IdleTimeout}
	u := &idleConn{Conn: upstream, idle: g.cfg.IdleTimeout}
	defer client.Close()
	defer upstream.Close()

	var upN, downN atomic.Int64
	done := make(chan struct{}, 2)
	go func() {
		if len(early) > 0 {
			if n, err := u.Write(early); err == nil {
				upN.Add(int64(n))
			} else {
				done <- struct{}{}
				return
			}
		}
		n, _ := io.Copy(u, c)
		upN.Add(n)
		if cw, ok := upstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(c, u)
		downN.Add(n)
		if cw, ok := client.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	// One direction finished; give the other a short grace period to drain.
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
	return upN.Load(), downN.Load()
}

// forwardProxy proxies absolute-URI http:// requests. Each connection goes
// through Dial, so every connection is authorized; keep-alives are disabled
// so policy is re-evaluated for every request.
func (g *Gateway) forwardProxy() http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Out.URL is already the absolute target. Proxy-* and hop-by-hop
			// headers are removed by ReverseProxy; do not add X-Forwarded-*.
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport:     g.transport(),
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeDeniedOrError(w, err)
		},
	}
}

func (g *Gateway) transport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", portStr)
			}
			return g.Dial(ctx, host, port)
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		Proxy:                 nil, // never chain through environment proxies
	}
}
