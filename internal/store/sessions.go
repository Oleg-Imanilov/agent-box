package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Session is one agent run.
type Session struct {
	ID          string     `json:"id"`
	Agent       string     `json:"agent"`
	ImageDigest string     `json:"image_digest"`
	Workspace   string     `json:"workspace"`
	StartedAt   time.Time  `json:"started_at"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`
}

// Active reports whether the session has not ended.
func (s Session) Active() bool { return s.EndedAt == nil }

// HashToken returns the hex SHA-256 of a gateway token. Tokens are 256-bit
// random values, so a fast hash is sufficient and allows indexed lookup.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateSession inserts a new session. tokenHash must come from HashToken.
func (s *Store) CreateSession(ctx context.Context, sess Session, tokenHash string) error {
	if sess.ID == "" || sess.Agent == "" || tokenHash == "" {
		return errors.New("store: session id, agent and token hash are required")
	}
	if sess.StartedAt.IsZero() {
		sess.StartedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(id, agent, image_digest, workspace, token_hash, started_at) VALUES (?,?,?,?,?,?)`,
		sess.ID, sess.Agent, sess.ImageDigest, sess.Workspace, tokenHash, ms(sess.StartedAt))
	return err
}

const sessionCols = `id, agent, image_digest, workspace, started_at, ended_at`

func scanSession(row interface{ Scan(...any) error }) (Session, error) {
	var (
		sess    Session
		started int64
		ended   sql.NullInt64
	)
	if err := row.Scan(&sess.ID, &sess.Agent, &sess.ImageDigest, &sess.Workspace, &started, &ended); err != nil {
		return Session{}, err
	}
	sess.StartedAt = fromMS(started)
	sess.EndedAt = fromNullMS(ended)
	return sess, nil
}

// GetSession returns a session by ID.
func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

// SessionByTokenHash returns the session owning a gateway token hash.
func (s *Store) SessionByTokenHash(ctx context.Context, tokenHash string) (Session, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE token_hash = ?`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

// ListSessions returns sessions newest first. If activeOnly, ended sessions are omitted.
func (s *Store) ListSessions(ctx context.Context, activeOnly bool, limit int) ([]Session, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT ` + sessionCols + ` FROM sessions`
	if activeOnly {
		q += ` WHERE ended_at IS NULL`
	}
	q += ` ORDER BY started_at DESC, id LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// EndSession marks a session ended (idempotent) and returns its final state.
func (s *Store) EndSession(ctx context.Context, id string, at time.Time) (Session, error) {
	if at.IsZero() {
		at = time.Now()
	}
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET ended_at = COALESCE(ended_at, ?) WHERE id = ?`, ms(at), id)
	if err != nil {
		return Session{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Session{}, ErrNotFound
	}
	return s.GetSession(ctx, id)
}

// Approval is a pending or decided request for human approval.
type Approval struct {
	ID        int64      `json:"id"`
	RequestID string     `json:"request_id"`
	SessionID string     `json:"session_id"`
	EventID   *int64     `json:"event_id,omitempty"`
	Kind      string     `json:"kind"`
	Subject   string     `json:"subject"`
	Status    string     `json:"status"`
	Decision  string     `json:"decision"`
	Actor     string     `json:"actor"`
	CreatedAt time.Time  `json:"created_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Approval statuses and decisions.
const (
	ApprovalPending = "pending"
	ApprovalDecided = "decided"
	ApprovalExpired = "expired"

	DecisionOnce    = "once"
	DecisionSession = "session"
	DecisionPersist = "persist"
	DecisionDeny    = "deny"
)

// ValidApprovalDecision reports whether d is a recognized decision.
func ValidApprovalDecision(d string) bool {
	switch d {
	case DecisionOnce, DecisionSession, DecisionPersist, DecisionDeny:
		return true
	}
	return false
}

// CreateApproval inserts a pending approval. A repeated request_id returns the
// existing approval (idempotent) rather than creating a duplicate.
func (s *Store) CreateApproval(ctx context.Context, a Approval) (Approval, error) {
	if a.RequestID == "" || a.SessionID == "" || a.Kind == "" || a.Subject == "" {
		return Approval{}, errors.New("store: approval request_id, session_id, kind and subject are required")
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	var exp any
	if a.ExpiresAt != nil {
		exp = ms(*a.ExpiresAt)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO approvals(request_id, session_id, event_id, kind, subject, status, created_at, expires_at)
		 VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(request_id) DO NOTHING`,
		a.RequestID, a.SessionID, a.EventID, a.Kind, a.Subject, ApprovalPending, ms(a.CreatedAt), exp)
	if err != nil {
		return Approval{}, err
	}
	return s.ApprovalByRequestID(ctx, a.RequestID)
}

const approvalCols = `id, request_id, session_id, event_id, kind, subject, status, decision, actor, created_at, decided_at, expires_at`

func scanApproval(row interface{ Scan(...any) error }) (Approval, error) {
	var (
		a       Approval
		event   sql.NullInt64
		created int64
		decided sql.NullInt64
		expires sql.NullInt64
	)
	if err := row.Scan(&a.ID, &a.RequestID, &a.SessionID, &event, &a.Kind, &a.Subject, &a.Status, &a.Decision, &a.Actor, &created, &decided, &expires); err != nil {
		return Approval{}, err
	}
	if event.Valid {
		v := event.Int64
		a.EventID = &v
	}
	a.CreatedAt = fromMS(created)
	a.DecidedAt = fromNullMS(decided)
	a.ExpiresAt = fromNullMS(expires)
	return a, nil
}

// ApprovalByRequestID returns the approval for a request ID.
func (s *Store) ApprovalByRequestID(ctx context.Context, requestID string) (Approval, error) {
	a, err := scanApproval(s.db.QueryRowContext(ctx, `SELECT `+approvalCols+` FROM approvals WHERE request_id = ?`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	return a, err
}

// ListPendingApprovals returns undecided approvals, oldest first.
func (s *Store) ListPendingApprovals(ctx context.Context, limit int) ([]Approval, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+approvalCols+` FROM approvals WHERE status = ? ORDER BY id LIMIT ?`, ApprovalPending, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DecideApproval records a decision for a pending approval. It fails with
// ErrNotFound if the request is unknown, and ErrAlreadyDecided if it was
// already decided or expired (decisions are never overwritten).
func (s *Store) DecideApproval(ctx context.Context, requestID, decision, actor string, at time.Time) (Approval, error) {
	if !ValidApprovalDecision(decision) {
		return Approval{}, fmt.Errorf("store: invalid approval decision %q", decision)
	}
	if at.IsZero() {
		at = time.Now()
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE approvals SET status = ?, decision = ?, actor = ?, decided_at = ?
		 WHERE request_id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)`,
		ApprovalDecided, decision, actor, ms(at), requestID, ApprovalPending, ms(at))
	if err != nil {
		return Approval{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.ApprovalByRequestID(ctx, requestID); err != nil {
			return Approval{}, err
		}
		return Approval{}, ErrAlreadyDecided
	}
	return s.ApprovalByRequestID(ctx, requestID)
}

// ErrAlreadyDecided is returned when an approval is no longer pending.
var ErrAlreadyDecided = errors.New("approval already decided or expired")

// ExpireApprovals marks pending approvals past their expiry as expired.
func (s *Store) ExpireApprovals(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE approvals SET status = ? WHERE status = ? AND expires_at IS NOT NULL AND expires_at <= ?`,
		ApprovalExpired, ApprovalPending, ms(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Settings.

// GetSetting returns the value for key, or ErrNotFound.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting upserts a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// AllSettings returns every setting.
func (s *Store) AllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
