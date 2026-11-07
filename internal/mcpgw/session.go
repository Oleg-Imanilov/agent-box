package mcpgw

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var errSessionsFull = errors.New("too many MCP sessions")

type session struct {
	server     string
	upstreamID string
	lastUsed   time.Time
}

// sessionTable maps gateway-minted session IDs to upstream session IDs. IDs
// are bound to one server, so a client cannot present a session minted for one
// MCP server to another, and cannot choose an upstream session ID.
type sessionTable struct {
	mu   sync.Mutex
	ttl  time.Duration
	max  int
	now  func() time.Time
	byID map[string]*session
}

func newSessionTable(ttl time.Duration, max int, now func() time.Time) *sessionTable {
	return &sessionTable{ttl: ttl, max: max, now: now, byID: map[string]*session{}}
}

func (t *sessionTable) create(server, upstreamID string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked()
	if len(t.byID) >= t.max {
		return "", errSessionsFull
	}
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	t.byID[id] = &session{server: server, upstreamID: upstreamID, lastUsed: t.now()}
	return id, nil
}

// get returns the upstream session for id if it belongs to server.
func (t *sessionTable) get(id, server string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.byID[id]
	if !ok || s.server != server || t.now().Sub(s.lastUsed) > t.ttl {
		if ok && t.now().Sub(s.lastUsed) > t.ttl {
			delete(t.byID, id)
		}
		return "", false
	}
	s.lastUsed = t.now()
	return s.upstreamID, true
}

func (t *sessionTable) delete(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byID, id)
}

func (t *sessionTable) expireLocked() {
	cutoff := t.now().Add(-t.ttl)
	for id, s := range t.byID {
		if s.lastUsed.Before(cutoff) {
			delete(t.byID, id)
		}
	}
}

func (t *sessionTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byID)
}
