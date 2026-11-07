package audit

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/Oleg-Imanilov/agent-box/internal/store"
)

const exportPageSize = 500

// ExportJSONL writes events matching f to w, one JSON object per line, oldest
// first (f.Desc is ignored). f.Limit, if positive, caps the total number of
// rows. It returns the rows written.
func ExportJSONL(ctx context.Context, st *store.Store, w io.Writer, f store.EventFilter) (int, error) {
	total := f.Limit
	f.Desc = false
	written := 0
	enc := json.NewEncoder(w)
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		page := f
		page.Limit = exportPageSize
		if total > 0 && total-written < page.Limit {
			page.Limit = total - written
		}
		if page.Limit <= 0 {
			return written, nil
		}
		events, err := st.ListEvents(ctx, page)
		if err != nil {
			return written, err
		}
		for _, e := range events {
			if err := enc.Encode(e); err != nil {
				return written, err
			}
			written++
		}
		if len(events) < page.Limit {
			return written, nil
		}
		f.AfterID = events[len(events)-1].ID
	}
}

// Prune deletes events older than retentionDays relative to now. A value <= 0
// keeps events forever. It returns the number of events deleted.
func Prune(ctx context.Context, st *store.Store, retentionDays int, now time.Time) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	return st.PruneEvents(ctx, now.AddDate(0, 0, -retentionDays))
}

// RunRetention prunes expired events every interval until ctx is cancelled.
// days is evaluated on each run so the setting can change at runtime.
func RunRetention(ctx context.Context, st *store.Store, interval time.Duration, days func() int, onErr func(error)) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := Prune(ctx, st, days(), time.Now()); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}
