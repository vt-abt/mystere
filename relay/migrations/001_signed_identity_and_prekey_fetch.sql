-- Run once against an existing PostgreSQL relay database before starting the new relay.
-- Existing identities have no signing proof, so clients must register fresh identities.
-- Existing prekeys remain stored but are excluded from new authenticated fetches.
BEGIN;

ALTER TABLE identity_keys
    ADD COLUMN IF NOT EXISTS signing_pubkey BYTEA,
    ADD COLUMN IF NOT EXISTS registration_id SMALLINT;

ALTER TABLE signed_prekeys
    ADD COLUMN IF NOT EXISTS key_id INTEGER;

ALTER TABLE one_time_prekeys
    ADD COLUMN IF NOT EXISTS key_id INTEGER;

CREATE TABLE IF NOT EXISTS prekey_fetches (
    session_id BYTEA PRIMARY KEY REFERENCES session_commitments(session_id),
    prekey_id UUID NOT NULL REFERENCES one_time_prekeys(id),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

COMMIT;
