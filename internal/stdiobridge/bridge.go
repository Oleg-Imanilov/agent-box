// Package stdiobridge exposes a stdio MCP server as an authenticated
// Streamable HTTP endpoint, for use behind the MCP gateway.
//
// The bridge is the point where implicit process trust ("I launched this
// subprocess") becomes network-reachable trust, so it:
//
//   - requires a bearer token and (optionally) an allowed Host,
//   - gives the child a minimal, explicit environment (never the bridge's own
//     token or the container environment),
//   - namespaces JSON-RPC request IDs so multiple HTTP sessions share the
//     single stdin/stdout pipe without colliding,
//   - quarantines stdout lines that are not JSON instead of forwarding them,
//   - answers server-initiated requests with an error when no client stream is
//     attached, so the server never hangs, and
//   - exits when the child exits, so a supervisor restarts the pair (fail closed).
//
// It is meant to run in its own container (non-root, all capabilities dropped,
// attached only to the MCP network) together with the MCP server it wraps. The
// MCP server's credentials live in that container, never in the agent's.
package stdiobridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MinTokenLen is the minimum accepted bearer token length.
const MinTokenLen = 32

// Config configures a Bridge.
type Config struct {
	// Command is the stdio MCP server argv.
	Command []string
	// Env holds extra KEY=VALUE variables for the child. PATH, HOME, LANG and
	// TMPDIR are inherited; nothing else is.
	Env []string
	// Dir is the child's working directory.
	Dir string
	// Token is the bearer token HTTP clients must present (>= 32 chars).
	Token string
	// AllowedHosts, if set, restricts the Host header.
	AllowedHosts []string
	// RequestTimeout bounds one request (default 120s).
	RequestTimeout time.Duration
	// MaxBodyBytes bounds HTTP request bodies (default 4 MiB).
	MaxBodyBytes int64
	// MaxLineBytes bounds one stdout line from the child (default 4 MiB).
	MaxLineBytes int
	// MaxSessions bounds concurrent HTTP sessions (default 64).
	MaxSessions int
	Logger      *slog.Logger
}

type subscriber struct{ ch chan sseMsg }

type sseMsg struct {
	id   int64
	data []byte
}

// Bridge runs the child and serves HTTP.
type Bridge struct {
	cfg Config
	log *slog.Logger

	cmd   *exec.Cmd
	stdin io.WriteCloser
	wmu   sync.Mutex

	nextID  atomic.Int64
	nextSSE atomic.Int64

	mu       sync.Mutex
	pending  map[int64]chan []byte
	sessions map[string]time.Time
	subs     map[int]*subscriber
	nextSub  int
	exitErr  error
	dead     bool

	initMu      sync.Mutex
	initResult  json.RawMessage
	initialized bool

	done chan struct{}
	wg   sync.WaitGroup

	tokenDigest [sha256.Size]byte
	hosts       map[string]bool

	noiseLines atomic.Int64
}

// New validates cfg. Call Start to launch the child.
func New(cfg Config) (*Bridge, error) {
	if len(cfg.Command) == 0 || cfg.Command[0] == "" {
		return nil, errors.New("stdiobridge: command is required")
	}
	if len(cfg.Token) < MinTokenLen {
		return nil, fmt.Errorf("stdiobridge: token must be at least %d characters", MinTokenLen)
	}
	for _, e := range cfg.Env {
		if !strings.Contains(e, "=") || strings.HasPrefix(e, "=") {
			return nil, fmt.Errorf("stdiobridge: invalid env entry %q", e)
		}
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 120 * time.Second
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 4 << 20
	}
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = 4 << 20
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	b := &Bridge{
		cfg: cfg, log: cfg.Logger,
		pending: map[int64]chan []byte{}, sessions: map[string]time.Time{}, subs: map[int]*subscriber{},
		done: make(chan struct{}), hosts: map[string]bool{},
		tokenDigest: sha256.Sum256([]byte(cfg.Token)),
	}
	if b.log == nil {
		b.log = slog.New(slog.DiscardHandler)
	}
	for _, h := range cfg.AllowedHosts {
		b.hosts[strings.ToLower(h)] = true
	}
	return b, nil
}

// childEnv builds the child's environment: a few safe inherited variables
// plus the explicitly configured ones.
func (b *Bridge) childEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "LANG", "TMPDIR", "SystemRoot"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, b.cfg.Env...)
}

// Start launches the child process.
func (b *Bridge) Start() error {
	cmd := exec.Command(b.cfg.Command[0], b.cfg.Command[1:]...)
	cmd.Env = b.childEnv()
	cmd.Dir = b.cfg.Dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", b.cfg.Command[0], err)
	}
	b.cmd, b.stdin = cmd, stdin

	// cmd.Wait closes the pipes, so it must only run after the readers finish.
	var readers sync.WaitGroup
	readers.Add(2)
	b.wg.Add(3)
	go func() { defer b.wg.Done(); defer readers.Done(); b.readLoop(stdout) }()
	go func() { defer b.wg.Done(); defer readers.Done(); b.logStderr(stderr) }()
	go func() {
		defer b.wg.Done()
		readers.Wait()
		b.markDead(cmd.Wait())
	}()
	return nil
}

// Done is closed when the child has exited.
func (b *Bridge) Done() <-chan struct{} { return b.done }

// Err returns the child's exit error once Done is closed.
func (b *Bridge) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exitErr
}

// Close stops the child and waits for goroutines.
func (b *Bridge) Close() {
	if b.cmd != nil && b.cmd.Process != nil {
		_ = b.stdin.Close()
		select {
		case <-b.done:
		case <-time.After(2 * time.Second):
			_ = b.cmd.Process.Kill()
		}
	}
	b.wg.Wait()
}

func (b *Bridge) markDead(err error) {
	b.mu.Lock()
	if b.dead {
		b.mu.Unlock()
		return
	}
	b.dead, b.exitErr = true, err
	for id, ch := range b.pending {
		close(ch)
		delete(b.pending, id)
	}
	for id, s := range b.subs {
		close(s.ch)
		delete(b.subs, id)
	}
	b.mu.Unlock()
	close(b.done)
	b.log.Error("child process exited", "err", err)
}

func (b *Bridge) logStderr(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		b.log.Info("server stderr", "line", sc.Text())
	}
}

func (b *Bridge) readLoop(r io.Reader) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br, b.cfg.MaxLineBytes)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				b.noiseLines.Add(1)
				b.log.Warn("dropped oversized stdout line")
				continue
			}
			return
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var fields map[string]json.RawMessage
		if line[0] != '{' || json.Unmarshal(line, &fields) != nil {
			// Not an MCP message (stray log output). Never forward it.
			b.noiseLines.Add(1)
			b.log.Warn("quarantined non-JSON stdout line", "bytes", len(line))
			continue
		}
		b.dispatch(fields, line)
	}
}

var errLineTooLong = errors.New("line too long")

func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		if !tooLong {
			if len(buf)+len(chunk) > max {
				tooLong = true
				buf = nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if !isPrefix {
			if tooLong {
				return nil, errLineTooLong
			}
			return buf, nil
		}
	}
}

// dispatch routes one message from the child.
func (b *Bridge) dispatch(fields map[string]json.RawMessage, line []byte) {
	method, hasMethod := fields["method"]
	if !hasMethod {
		var id int64
		if err := json.Unmarshal(fields["id"], &id); err != nil {
			b.log.Warn("response with unknown id type dropped")
			return
		}
		b.mu.Lock()
		ch, ok := b.pending[id]
		delete(b.pending, id)
		b.mu.Unlock()
		if !ok {
			b.log.Warn("response for unknown request dropped", "id", id)
			return
		}
		ch <- append([]byte(nil), line...)
		return
	}

	// Server-initiated request or notification: fan out to client streams.
	msg := sseMsg{id: b.nextSSE.Add(1), data: append([]byte(nil), line...)}
	b.mu.Lock()
	delivered := 0
	for _, s := range b.subs {
		select {
		case s.ch <- msg:
			delivered++
		default:
			b.log.Warn("slow client stream: dropped a server message")
		}
	}
	b.mu.Unlock()

	if id, isReq := fields["id"]; isReq && delivered == 0 && string(bytes.TrimSpace(id)) != "null" {
		var m string
		_ = json.Unmarshal(method, &m)
		b.log.Warn("server request with no client stream; answering with an error", "method", m)
		reply, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id),
			"error": map[string]any{"code": -32601, "message": "no client connected to receive this request"}})
		_ = b.writeLine(reply)
	}
}

func (b *Bridge) writeLine(msg []byte) error {
	var buf bytes.Buffer
	if err := json.Compact(&buf, msg); err != nil {
		return err
	}
	buf.WriteByte('\n')
	b.wmu.Lock()
	defer b.wmu.Unlock()
	_, err := b.stdin.Write(buf.Bytes())
	return err
}

var (
	errDead    = errors.New("server process is not running")
	errTimeout = errors.New("request timed out")
)

// roundTrip sends a request with a bridge-assigned id and waits for its
// response. The returned fields have the caller's original id restored.
func (b *Bridge) roundTrip(ctx context.Context, fields map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	origID := fields["id"]
	n := b.nextID.Add(1)
	out := make(map[string]json.RawMessage, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	out["id"] = json.RawMessage(strconv.FormatInt(n, 10))
	payload, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}

	ch := make(chan []byte, 1)
	b.mu.Lock()
	if b.dead {
		b.mu.Unlock()
		return nil, errDead
	}
	b.pending[n] = ch
	b.mu.Unlock()

	if err := b.writeLine(payload); err != nil {
		b.forget(n)
		return nil, errDead
	}
	timer := time.NewTimer(b.cfg.RequestTimeout)
	defer timer.Stop()
	select {
	case raw, ok := <-ch:
		if !ok {
			return nil, errDead
		}
		var resp map[string]json.RawMessage
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, err
		}
		resp["id"] = origID
		return resp, nil
	case <-timer.C:
		b.cancelUpstream(n, "timeout")
		return nil, errTimeout
	case <-ctx.Done():
		b.cancelUpstream(n, "client cancelled")
		return nil, ctx.Err()
	}
}

func (b *Bridge) forget(n int64) {
	b.mu.Lock()
	delete(b.pending, n)
	b.mu.Unlock()
}

// cancelUpstream tells the server a request is abandoned (MCP cancellation).
func (b *Bridge) cancelUpstream(n int64, reason string) {
	b.forget(n)
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled",
		"params": map[string]any{"requestId": n, "reason": reason}})
	_ = b.writeLine(msg)
}

// HTTP.

// Handler returns the HTTP handler: /mcp (POST, GET, DELETE) and /healthz.
func (b *Bridge) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", b.handleHealth)
	mux.HandleFunc("/mcp", b.handleMCP)
	return b.guard(mux)
}

func (b *Bridge) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(b.hosts) > 0 {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if !b.hosts[strings.ToLower(host)] {
				http.Error(w, "host not allowed", http.StatusForbidden)
				return
			}
		}
		if r.URL.Path != "/healthz" {
			tok := ""
			if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
				tok = strings.TrimSpace(h[7:])
			}
			d := sha256.Sum256([]byte(tok))
			if subtle.ConstantTimeCompare(d[:], b.tokenDigest[:]) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="agentbox-mcp-bridge"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (b *Bridge) handleHealth(w http.ResponseWriter, _ *http.Request) {
	b.mu.Lock()
	dead := b.dead
	b.mu.Unlock()
	if dead {
		http.Error(w, `{"status":"server process exited"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func rpcErr(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
	return b
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (b *Bridge) handleMCP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		b.handlePost(w, r)
	case http.MethodGet:
		b.handleGet(w, r)
	case http.MethodDelete:
		b.handleDelete(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (b *Bridge) sessionValid(id string) bool {
	if id == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.sessions[id]; !ok {
		return false
	}
	b.sessions[id] = time.Now()
	return true
}

func (b *Bridge) newSession() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw[:])
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sessions) >= b.cfg.MaxSessions {
		return "", errors.New("too many sessions")
	}
	b.sessions[id] = time.Now()
	return id, nil
}

func (b *Bridge) isDead() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dead
}

func (b *Bridge) handlePost(w http.ResponseWriter, r *http.Request) {
	if b.isDead() {
		writeJSON(w, http.StatusServiceUnavailable, rpcErr(nil, -32003, "server process is not running"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, b.cfg.MaxBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, rpcErr(nil, -32600, "request too large"))
		return
	}
	var fields map[string]json.RawMessage
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '{' || json.Unmarshal(t, &fields) != nil {
		writeJSON(w, http.StatusBadRequest, rpcErr(nil, -32700, "body must be a single JSON-RPC object"))
		return
	}
	var method string
	if raw, ok := fields["method"]; ok {
		_ = json.Unmarshal(raw, &method)
	}
	id := bytes.TrimSpace(fields["id"])
	hasID := len(id) > 0 && string(id) != "null"

	if method == "initialize" && hasID {
		b.handleInitialize(w, r, fields)
		return
	}
	if !b.sessionValid(r.Header.Get("Mcp-Session-Id")) {
		writeJSON(w, http.StatusNotFound, rpcErr(fields["id"], -32002, "session not found"))
		return
	}

	switch {
	case method == "": // client response to a server-initiated request
		if err := b.writeLine(body); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, rpcErr(nil, -32003, "server process is not running"))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	case !hasID: // notification
		if method == "notifications/initialized" {
			b.initMu.Lock()
			first := !b.initialized
			b.initialized = true
			b.initMu.Unlock()
			if !first {
				w.WriteHeader(http.StatusAccepted) // the server already saw one
				return
			}
		}
		if err := b.writeLine(body); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, rpcErr(nil, -32003, "server process is not running"))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		b.respond(w, r, fields)
	}
}

func (b *Bridge) respond(w http.ResponseWriter, r *http.Request, fields map[string]json.RawMessage) {
	resp, err := b.roundTrip(r.Context(), fields)
	switch {
	case err == nil:
		out, _ := json.Marshal(resp)
		writeJSON(w, http.StatusOK, out)
	case errors.Is(err, errTimeout):
		writeJSON(w, http.StatusGatewayTimeout, rpcErr(fields["id"], -32003, "server did not respond in time"))
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// client went away; nothing to send
	default:
		writeJSON(w, http.StatusServiceUnavailable, rpcErr(fields["id"], -32003, "server process is not running"))
	}
}

// handleInitialize forwards the first initialize to the server and answers
// later ones from the cached result, so every HTTP session gets a handshake
// while the server sees exactly one.
func (b *Bridge) handleInitialize(w http.ResponseWriter, r *http.Request, fields map[string]json.RawMessage) {
	b.initMu.Lock()
	defer b.initMu.Unlock()
	var resp map[string]json.RawMessage
	if b.initResult == nil {
		var err error
		resp, err = b.roundTrip(r.Context(), fields)
		if err != nil {
			b.respondInitErr(w, fields, err)
			return
		}
		if _, isErr := resp["error"]; isErr {
			out, _ := json.Marshal(resp)
			writeJSON(w, http.StatusOK, out)
			return
		}
		b.initResult = resp["result"]
	} else {
		resp = map[string]json.RawMessage{"jsonrpc": json.RawMessage(`"2.0"`), "id": fields["id"], "result": b.initResult}
	}
	sid, err := b.newSession()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, rpcErr(fields["id"], -32003, err.Error()))
		return
	}
	out, _ := json.Marshal(resp)
	w.Header().Set("Mcp-Session-Id", sid)
	writeJSON(w, http.StatusOK, out)
}

func (b *Bridge) respondInitErr(w http.ResponseWriter, fields map[string]json.RawMessage, err error) {
	if errors.Is(err, errTimeout) {
		writeJSON(w, http.StatusGatewayTimeout, rpcErr(fields["id"], -32003, "server did not respond in time"))
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, rpcErr(fields["id"], -32003, "server process is not running"))
}

func (b *Bridge) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("Mcp-Session-Id")
	b.mu.Lock()
	_, ok := b.sessions[id]
	delete(b.sessions, id)
	b.mu.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleGet streams server-initiated messages. Resumption via Last-Event-ID is
// not supported: stdio servers have no replay, so missed messages are lost.
func (b *Bridge) handleGet(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		http.Error(w, "Accept must include text/event-stream", http.StatusNotAcceptable)
		return
	}
	if !b.sessionValid(r.Header.Get("Mcp-Session-Id")) {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	sub := &subscriber{ch: make(chan sseMsg, 256)}
	b.mu.Lock()
	if b.dead {
		b.mu.Unlock()
		http.Error(w, "server process is not running", http.StatusServiceUnavailable)
		return
	}
	sid := b.nextSub
	b.nextSub++
	b.subs[sid] = sub
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if cur, ok := b.subs[sid]; ok && cur == sub {
			delete(b.subs, sid)
		}
		b.mu.Unlock()
	}()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	_ = rc.Flush()

	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-sub.ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", msg.id, msg.data); err != nil {
				return
			}
			_ = rc.Flush()
		case <-hb.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}
