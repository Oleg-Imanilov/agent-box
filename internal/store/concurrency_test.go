package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Read-then-write transactions (PutPolicy reads the current version before
// writing) must not fail with SQLITE_BUSY when other writers, such as the
// audit batch writer, commit concurrently. This needs write transactions to
// take the write lock up front (_txlock=immediate) so busy_timeout applies.
func TestMixedConcurrentWritersNeverFailBusy(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	const policyWriters, eventWriters, iterations = 6, 6, 60
	var wg sync.WaitGroup
	errs := make(chan error, policyWriters*iterations+eventWriters*iterations)

	for g := 0; g < policyWriters; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if _, err := s.PutPolicy(ctx, "global", []byte(fmt.Sprintf(`{"n":%d}`, i)), "t"); err != nil {
					errs <- fmt.Errorf("PutPolicy: %w", err)
				}
				if _, err := s.CreateApproval(ctx, Approval{RequestID: fmt.Sprintf("r-%d-%d", g, i), SessionID: "s", Kind: "network", Subject: "x"}); err != nil {
					errs <- fmt.Errorf("CreateApproval: %w", err)
				}
			}
		}(g)
	}
	for g := 0; g < eventWriters; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				batch := []Event{ev("s", "network", "allow", "a", time.Now()), ev("s", "network", "deny", "b", time.Now())}
				if err := s.InsertEvents(ctx, batch); err != nil {
					errs <- fmt.Errorf("InsertEvents: %w", err)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	rec, err := s.GetPolicy(ctx, "global")
	if err != nil || rec.Version != policyWriters*iterations {
		t.Fatalf("policy version = %d (want %d), err %v: versions must be gapless and unique", rec.Version, policyWriters*iterations, err)
	}
	hist, _ := s.PolicyHistory(ctx, "global", 1000)
	if len(hist) != policyWriters*iterations {
		t.Fatalf("history rows = %d", len(hist))
	}
}
