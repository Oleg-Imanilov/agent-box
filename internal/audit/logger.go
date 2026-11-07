package audit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

// Decision values recorded in events.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionError = "error"
	DecisionInfo  = "info"
)

// Event kinds.
const (
	KindNetwork  = "network"
	KindDNS      = "dns"
	KindMCP      = "mcp"
	KindPolicy   = "policy"
	KindSession  = "session"
	KindApproval = "approval"
)

var (
	// ErrQueueFull means the event could not be queued. Enforcement points
	// must treat this as "audit unavailable" and fail closed.
	ErrQueueFull = errors.New("audit: queue full")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("audit: logger closed")
)

// Entry is an event before redaction.
type Entry struct {
	SessionID     string
	TS            time.Time
	Kind          string
	Destination   string
	Operation     string
	Decision      string
	RuleID        string
	PolicyVersion string
	Metadata      map[string]any
}

// Options configures a Logger.
type Options struct {
	QueueSize     int           // default 4096
	BatchSize     int           // default 128
	FlushInterval time.Duration // default 200ms
	Redactor      Redactor
	OnError       func(error) // called for persistent write failures
}

// Stats are cumulative logger counters.
type Stats struct {
	Written          uint64
	QueueFull        uint64
	WriteErrors      uint64
	SubscriberDrops  uint64
	CurrentQueuedLen int
}

type flushReq struct{ done chan struct{} }

type subscriber struct {
	ch     chan store.Event
	filter func(store.Event) bool
}

// Logger redacts, queues and persists events and fans them out to subscribers.
type Logger struct {
	st  *store.Store
	opt Options

	includeContent atomic.Bool

	mu     sync.RWMutex // guards closed and sends on ch
	closed bool
	ch     chan any // store.Event or flushReq
	wg     sync.WaitGroup

	subMu  sync.Mutex
	subs   map[int]*subscriber
	nextID int

	written, queueFull, writeErrs, subDrops atomic.Uint64
}

// NewLogger starts a logger backed by st.
func NewLogger(st *store.Store, opt Options) *Logger {
	if opt.QueueSize <= 0 {
		opt.QueueSize = 4096
	}
	if opt.BatchSize <= 0 {
		opt.BatchSize = 128
	}
	if opt.FlushInterval <= 0 {
		opt.FlushInterval = 200 * time.Millisecond
	}
	l := &Logger{st: st, opt: opt, ch: make(chan any, opt.QueueSize), subs: map[int]*subscriber{}}
	l.includeContent.Store(opt.Redactor.IncludeContent)
	l.wg.Add(1)
	go l.run()
	return l
}

// SetIncludeContent toggles collection of prompt/file-content style fields.
// It is off by default and must only be enabled by explicit user opt-in.
func (l *Logger) SetIncludeContent(v bool) { l.includeContent.Store(v) }

func (l *Logger) redactor() Redactor {
	r := l.opt.Redactor
	r.IncludeContent = l.includeContent.Load()
	return r
}

// Log redacts and enqueues an entry without blocking. If it returns an error
// the event was NOT recorded.
func (l *Logger) Log(e Entry) error {
	r := l.redactor()
	ev := store.Event{
		SessionID:     e.SessionID,
		TS:            e.TS,
		Kind:          e.Kind,
		Destination:   r.String(e.Destination),
		Operation:     r.String(e.Operation),
		Decision:      e.Decision,
		RuleID:        e.RuleID,
		PolicyVersion: e.PolicyVersion,
		Metadata:      r.Metadata(e.Metadata),
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return ErrClosed
	}
	select {
	case l.ch <- ev:
		return nil
	default:
		l.queueFull.Add(1)
		return ErrQueueFull
	}
}

// Flush blocks until all events queued before the call are persisted.
func (l *Logger) Flush(ctx context.Context) error {
	req := flushReq{done: make(chan struct{})}
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return ErrClosed
	}
	select {
	case l.ch <- req:
		l.mu.RUnlock()
	case <-ctx.Done():
		l.mu.RUnlock()
		return ctx.Err()
	}
	select {
	case <-req.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops accepting events, persists everything queued and closes all
// subscriber channels.
func (l *Logger) Close(ctx context.Context) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.ch)
	l.mu.Unlock()

	done := make(chan struct{})
	go func() { l.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	l.subMu.Lock()
	for id, s := range l.subs {
		close(s.ch)
		delete(l.subs, id)
	}
	l.subMu.Unlock()
	return nil
}

// Subscribe returns a channel of persisted events passing filter (nil = all)
// and a cancel function. Slow subscribers lose events (counted in Stats);
// clients can resynchronize with a store query using the last seen ID.
func (l *Logger) Subscribe(buffer int, filter func(store.Event) bool) (<-chan store.Event, func()) {
	if buffer <= 0 {
		buffer = 64
	}
	s := &subscriber{ch: make(chan store.Event, buffer), filter: filter}
	l.subMu.Lock()
	id := l.nextID
	l.nextID++
	l.subs[id] = s
	l.subMu.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			l.subMu.Lock()
			defer l.subMu.Unlock()
			if cur, ok := l.subs[id]; ok && cur == s {
				delete(l.subs, id)
				close(s.ch)
			}
		})
	}
	return s.ch, cancel
}

// Stats returns a snapshot of counters.
func (l *Logger) Stats() Stats {
	return Stats{
		Written:          l.written.Load(),
		QueueFull:        l.queueFull.Load(),
		WriteErrors:      l.writeErrs.Load(),
		SubscriberDrops:  l.subDrops.Load(),
		CurrentQueuedLen: len(l.ch),
	}
}

func (l *Logger) run() {
	defer l.wg.Done()
	batch := make([]store.Event, 0, l.opt.BatchSize)
	ticker := time.NewTicker(l.opt.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		l.write(batch)
		batch = batch[:0]
	}
	for {
		select {
		case item, ok := <-l.ch:
			if !ok {
				flush()
				return
			}
			switch v := item.(type) {
			case store.Event:
				batch = append(batch, v)
				if len(batch) >= l.opt.BatchSize {
					flush()
				}
			case flushReq:
				flush()
				close(v.done)
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (l *Logger) write(batch []store.Event) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = l.st.InsertEvents(ctx, batch)
		cancel()
		if err == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	if err != nil {
		l.writeErrs.Add(uint64(len(batch)))
		if l.opt.OnError != nil {
			l.opt.OnError(err)
		}
		return
	}
	l.written.Add(uint64(len(batch)))
	l.publish(batch)
}

func (l *Logger) publish(events []store.Event) {
	l.subMu.Lock()
	defer l.subMu.Unlock()
	for _, s := range l.subs {
		for _, e := range events {
			if s.filter != nil && !s.filter(e) {
				continue
			}
			select {
			case s.ch <- e:
			default:
				l.subDrops.Add(1)
			}
		}
	}
}
