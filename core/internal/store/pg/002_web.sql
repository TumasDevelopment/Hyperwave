-- Hyperwave: accesso con due fattori, codici di recupero e prefisso visibile dei token API.

ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step bigint;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_codes bytea[] NOT NULL DEFAULT '{}';

-- Secondo passo dell'accesso: tra password e codice passano al massimo 5 minuti e 5 tentativi
CREATE TABLE IF NOT EXISTS login_challenges (
    token_hash bytea PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    attempts   integer NOT NULL DEFAULT 0
);

ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS prefix text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS alerts_device ON alerts (device_id);
CREATE INDEX IF NOT EXISTS alerts_rule ON alerts (rule, last_seen DESC);
