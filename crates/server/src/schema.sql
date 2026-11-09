-- v1. Only explicit init/import applies this file to a newly created database.
PRAGMA application_id = 1381190449;
PRAGMA user_version = 1;
CREATE TABLE service_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation TEXT NOT NULL CHECK (length(generation) = 32),
    server_id TEXT NOT NULL CHECK (length(server_id) = 32),
    source_digest TEXT
) STRICT;
CREATE TABLE users (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 128),
    password_hash TEXT NOT NULL
) STRICT;
CREATE TABLE sessions (
    token_digest BLOB PRIMARY KEY CHECK (length(token_digest) = 32),
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
) STRICT;
CREATE TABLE vault_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    vault_id TEXT NOT NULL CHECK (length(vault_id) = 32),
    vault_revision INTEGER NOT NULL CHECK (vault_revision > 0),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    encryption_json TEXT NOT NULL
) STRICT;
CREATE TABLE entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (id > 0),
    description TEXT NOT NULL CHECK (length(CAST(description AS BLOB)) <= 4096),
    content TEXT NOT NULL CHECK (length(content) BETWEEN 40 AND 43728),
    revision INTEGER NOT NULL CHECK (revision > 0),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0)
) STRICT;
CREATE TABLE operation_results (
    generation TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    operation_id TEXT NOT NULL CHECK (length(operation_id) = 32),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    committed INTEGER NOT NULL CHECK (committed IN (0, 1)),
    outcome_json TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (generation, user_id, operation_id)
) STRICT;
CREATE TABLE rotation_jobs (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    owner INTEGER NOT NULL REFERENCES users(id),
    generation TEXT NOT NULL,
    baseline_revision INTEGER NOT NULL CHECK (baseline_revision > 0),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    encryption_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('staging', 'committed', 'aborted', 'expired', 'conflicted')),
    total_entries INTEGER NOT NULL CHECK (total_entries >= 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    committed_meta_json TEXT
) STRICT;
CREATE INDEX operations_expiry ON operation_results(expires_at);
CREATE INDEX rotation_expiry ON rotation_jobs(state, expires_at);
CREATE TABLE rotation_members (
    job_id TEXT NOT NULL REFERENCES rotation_jobs(id) ON DELETE CASCADE,
    entry_id INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY (job_id, entry_id)
) STRICT;
CREATE TABLE rotation_entries (
    job_id TEXT NOT NULL,
    entry_id INTEGER NOT NULL,
    content TEXT NOT NULL CHECK (length(content) BETWEEN 40 AND 43728),
    PRIMARY KEY (job_id, entry_id),
    FOREIGN KEY (job_id, entry_id) REFERENCES rotation_members(job_id, entry_id) ON DELETE CASCADE
) STRICT;
