-- Run against an existing PostgreSQL custodian database before starting Phase 4.
-- Old blobs have no enrolled credential and cannot be retrieved through the new gate.
BEGIN;

CREATE TABLE IF NOT EXISTS credentials (
    id BYTEA PRIMARY KEY,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE blobs
    ADD COLUMN IF NOT EXISTS credential_id BYTEA REFERENCES credentials(id);

CREATE TABLE IF NOT EXISTS challenges (
    value BYTEA PRIMARY KEY,
    purpose VARCHAR(16) NOT NULL,
    storage_key BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

COMMIT;
