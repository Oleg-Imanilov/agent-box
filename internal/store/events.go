package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Event is one persisted audit record. Metadata must already be redacted.
type Event struct {
	ID            int64           `json:"id"`
	SessionID     string          `json:"session_id"`
	TS            time.Time       `json:"ts"`
	Kind          string          `json:"kind"`
	Destination   string          `json:"destination"`
	Operation     string          `json:"operation"`
	Decision      string          `json:"decision"`
	RuleID        string          `json:"rule_id"`
	PolicyVersion string          `json:"policy_version"`
	Metadata      json.RawMessage `json:"metadata"`
}

// InsertEvents writes events in one transaction and fills in their IDs.
func (s *Store) InsertEvents(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events
		(session_id, ts, kind, destination, operation, decision, rule_id, policy_version, metadata_redacted)
		VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range events {
		e := &events[i]
		if e.TS.IsZero() {
			e.TS = time.Now()
		}
		meta := "{}"
		if len(e.Metadata) > 0 {
			meta = string(e.Metadata)
		}
		res, err := stmt.ExecContext(ctx, e.SessionID, ms(e.TS), e.Kind, e.Destination, e.Operation, e.Decision, e.RuleID, e.PolicyVersion, meta)
		if err != nil {
			return err
		}
		if e.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		e.TS = e.TS.UTC().Truncate(time.Millisecond)
	}
	return tx.Commit()
}

// EventFilter selects events. Zero values mean "no filter".
type EventFilter struct {
	SessionID string
	Kind      string
	Decision  string
	RuleID    string
	Query     string // substring match on destination, operation or rule_id
	AfterID   int64  // id > AfterID
	BeforeID  int64  // id < BeforeID (when > 0)
	Since     time.Time
	Until     time.Time
	Limit     int  // default 100, max 1000
	Desc      bool // newest first
}

const (
	defaultEventLimit = 100
	maxEventLimit     = 1000
)

// ListEvents returns events matching the filter.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultEventLimit
	}
	if limit > maxEventLimit {
		limit = maxEventLimit
	}
	var (
		where []string
		args  []any
	)
	add := func(cond string, a ...any) {
		where = append(where, cond)
		args = append(args, a...)
	}
	if f.SessionID != "" {
		add("session_id = ?", f.SessionID)
	}
	if f.Kind != "" {
		add("kind = ?", f.Kind)
	}
	if f.Decision != "" {
		add("decision = ?", f.Decision)
	}
	if f.RuleID != "" {
		add("rule_id = ?", f.RuleID)
	}
	if f.Query != "" {
		like := "%" + likeEscape(f.Query) + "%"
		add(`(destination LIKE ? ESCAPE '\' OR operation LIKE ? ESCAPE '\' OR rule_id LIKE ? ESCAPE '\')`, like, like, like)
	}
	if f.AfterID > 0 {
		add("id > ?", f.AfterID)
	}
	if f.BeforeID > 0 {
		add("id < ?", f.BeforeID)
	}
	if !f.Since.IsZero() {
		add("ts >= ?", ms(f.Since))
	}
	if !f.Until.IsZero() {
		add("ts < ?", ms(f.Until))
	}
	q := `SELECT id, session_id, ts, kind, destination, operation, decision, rule_id, policy_version, metadata_redacted FROM events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	if f.Desc {
		q += " ORDER BY id DESC"
	} else {
		q += " ORDER BY id ASC"
	}
	q += " LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var (
			e    Event
			ts   int64
			meta string
		)
		if err := rows.Scan(&e.ID, &e.SessionID, &ts, &e.Kind, &e.Destination, &e.Operation, &e.Decision, &e.RuleID, &e.PolicyVersion, &meta); err != nil {
			return nil, err
		}
		e.TS = fromMS(ts)
		e.Metadata = json.RawMessage(meta)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneEvents deletes events older than the cutoff and returns the count.
func (s *Store) PruneEvents(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, ms(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountEvents returns the number of events matching decision (empty = all).
func (s *Store) CountEvents(ctx context.Context, decision string) (int64, error) {
	var n int64
	var err error
	if decision == "" {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE decision = ?`, decision).Scan(&n)
	}
	return n, err
}

// PolicyRecord is a stored policy version.
type PolicyRecord struct {
	Scope     string          `json:"scope"`
	Version   int             `json:"version"`
	RuleJSON  json.RawMessage `json:"policy"`
	Actor     string          `json:"actor,omitempty"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// PutPolicy stores a new version of the policy for scope, appending to the
// history, and returns the new version number. ruleJSON must be valid JSON.
func (s *Store) PutPolicy(ctx context.Context, scope string, ruleJSON []byte, actor string) (int, error) {
	if scope == "" {
		return 0, errors.New("store: empty policy scope")
	}
	if !json.Valid(ruleJSON) {
		return 0, errors.New("store: policy is not valid JSON")
	}
	now := ms(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var cur sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT version FROM policies WHERE scope = ?`, scope).Scan(&cur); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	next := int(cur.Int64) + 1
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO policies(scope, version, rule_json, updated_at) VALUES (?,?,?,?)
		 ON CONFLICT(scope) DO UPDATE SET version = excluded.version, rule_json = excluded.rule_json, updated_at = excluded.updated_at`,
		scope, next, string(ruleJSON), now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO policy_history(scope, version, rule_json, actor, updated_at) VALUES (?,?,?,?,?)`,
		scope, next, string(ruleJSON), actor, now); err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

// GetPolicy returns the current policy for scope.
func (s *Store) GetPolicy(ctx context.Context, scope string) (PolicyRecord, error) {
	var (
		r       PolicyRecord
		raw     string
		updated int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT scope, version, rule_json, updated_at FROM policies WHERE scope = ?`, scope).
		Scan(&r.Scope, &r.Version, &raw, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyRecord{}, ErrNotFound
	}
	if err != nil {
		return PolicyRecord{}, err
	}
	r.RuleJSON, r.UpdatedAt = json.RawMessage(raw), fromMS(updated)
	return r, nil
}

// ListPolicies returns all current policies ordered by scope.
func (s *Store) ListPolicies(ctx context.Context) ([]PolicyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT scope, version, rule_json, updated_at FROM policies ORDER BY scope`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyRecord
	for rows.Next() {
		var (
			r       PolicyRecord
			raw     string
			updated int64
		)
		if err := rows.Scan(&r.Scope, &r.Version, &raw, &updated); err != nil {
			return nil, err
		}
		r.RuleJSON, r.UpdatedAt = json.RawMessage(raw), fromMS(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

// PolicyHistory returns all versions for scope, newest first.
func (s *Store) PolicyHistory(ctx context.Context, scope string, limit int) ([]PolicyRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT scope, version, rule_json, actor, updated_at FROM policy_history WHERE scope = ? ORDER BY version DESC LIMIT ?`, scope, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyRecord
	for rows.Next() {
		var (
			r       PolicyRecord
			raw     string
			updated int64
		)
		if err := rows.Scan(&r.Scope, &r.Version, &raw, &r.Actor, &updated); err != nil {
			return nil, err
		}
		r.RuleJSON, r.UpdatedAt = json.RawMessage(raw), fromMS(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}
