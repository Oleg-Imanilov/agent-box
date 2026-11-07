package bgtask

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoAndWait(t *testing.T) {
	var g Group
	var n atomic.Int32
	for i := 0; i < 10; i++ {
		if !g.Go(func() { time.Sleep(10 * time.Millisecond); n.Add(1) }) {
			t.Fatal("Go refused before Wait")
		}
	}
	g.Wait()
	if n.Load() != 10 {
		t.Fatalf("ran %d tasks", n.Load())
	}
	if g.Go(func() { t.Error("must not run after Wait") }) {
		t.Fatal("Go must refuse after Wait")
	}
}

// Run with -race: Go and Wait may be called concurrently.
func TestConcurrentGoAndWait(t *testing.T) {
	var g Group
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Go(func() { time.Sleep(time.Millisecond) })
		}()
	}
	g.Wait()
	wg.Wait()
}
