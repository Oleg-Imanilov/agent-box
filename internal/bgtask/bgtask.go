// Package bgtask runs short background tasks (such as audit event reports) and
// lets a service wait for them at shutdown without the WaitGroup hazard of
// calling Add concurrently with Wait.
package bgtask

import "sync"

// Group tracks background goroutines. After Wait is called, Go refuses new
// work, so late callers (for example a tunnel that finishes during shutdown)
// are safely ignored instead of racing with Wait.
type Group struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// Go runs fn in a new goroutine and reports whether it was started.
func (g *Group) Go(fn func()) bool {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return false
	}
	g.wg.Add(1)
	g.mu.Unlock()
	go func() {
		defer g.wg.Done()
		fn()
	}()
	return true
}

// Wait stops accepting new tasks and blocks until running tasks finish.
func (g *Group) Wait() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
	g.wg.Wait()
}
