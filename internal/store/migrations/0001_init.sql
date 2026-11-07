CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    agent        TEXT NOT NULL,
    image_digest TEXT NOT NULL DEFAULT '',
    workspace    TEXT NOT NULL DEFAULT '',
    token_hash   TEXT NOT NULL UNIQUE,   -- sha256 of the per-session gateway token
    started_at   INTEGER NOT NULL,       -- unix milliseconds
    ended_at     INTEGER
);
CREATE INDEX idx_sessions_ended ON sessions(ended_at);

-- events intentionally has no foreign key to sessions: audit records must
-- never be lost because a session row is missing or removed.
CREATE TABLE events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id        TEXT NOT NULL,
    ts                INTEGER NOT NULL,  -- unix milliseconds
    kind              TEXT NOT NULL,     -- network | dns | mcp | policy | session | approval
    destination       TEXT NOT NULL DEFAULT '',
    operation         TEXT NOT NULL DEFAULT '',
    decision          TEXT NOT NULL,     -- allow | deny | error | info
    rule_id           TEXT NOT NULL DEFAULT '',
    policy_version    TEXT NOT NULL DEFAULT '',
    metadata_redacted TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_events_session ON events(session_id, id);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_kind ON events(kind, id);
CREATE INDEX idx_events_decision ON events(decision, id);

CREATE TABLE policies (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL UNIQUE,     -- global | agent:<name> | session:<id>
    version    INTEGER NOT NULL,
    rule_json  TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE policy_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL,
    version    INTEGER NOT NULL,
    rule_json  TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    UNIQUE (scope, version)
);

CREATE TABLE approvals (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,     -- idempotency key
    session_id TEXT NOT NULL,
    event_id   INTEGER,
    kind       TEXT NOT NULL,            -- network | mcp
    subject    TEXT NOT NULL,            -- destination or server/tool
    status     TEXT NOT NULL DEFAULT 'pending',  -- pending | decided | expired
    decision   TEXT NOT NULL DEFAULT '', -- once | session | persist | deny
    actor      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    decided_at INTEGER,
    expires_at INTEGER
);
CREATE INDEX idx_approvals_status ON approvals(status, id);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
