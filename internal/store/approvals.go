package store

import (
	"context"
)

// ListApprovals returns approvals with the given status (empty = any status),
// newest first.
func (s *Store) ListApprovals(ctx context.Context, status string, limit int) ([]Approval, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT ` + approvalCols + ` FROM approvals`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
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

// PendingApprovalCount returns how many approvals are pending for a session.
func (s *Store) PendingApprovalCount(ctx context.Context, sessionID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM approvals WHERE session_id = ? AND status = ?`, sessionID, ApprovalPending).Scan(&n)
	return n, err
}

// ExpireSessionApprovals expires every pending approval of a session (used
// when the session ends) and returns how many were affected.
func (s *Store) ExpireSessionApprovals(ctx context.Context, sessionID string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE approvals SET status = ? WHERE session_id = ? AND status = ?`, ApprovalExpired, sessionID, ApprovalPending)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
