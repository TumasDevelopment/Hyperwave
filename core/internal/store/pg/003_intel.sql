-- Hyperwave: elenchi di indirizzi e domini malevoli (threat intelligence).

-- Un elenco è scaricato da un indirizzo web (kind = url) oppure compilato a mano (kind = manual).
-- Gli elenchi pubblici predefiniti (preset) li inserisce l'hub, spenti: li accende un amministratore.
CREATE TABLE IF NOT EXISTS intel_feeds (
    id            bigserial PRIMARY KEY,
    name          text NOT NULL UNIQUE,
    kind          text NOT NULL CHECK (kind IN ('url', 'manual')),
    url           text NOT NULL DEFAULT '',
    category      text NOT NULL DEFAULT 'malware',
    severity      text NOT NULL DEFAULT 'high' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description   text NOT NULL DEFAULT '',
    enabled       boolean NOT NULL DEFAULT false,
    refresh_hours integer NOT NULL DEFAULT 6 CHECK (refresh_hours BETWEEN 1 AND 168),
    preset        text NOT NULL DEFAULT '',
    entries       integer NOT NULL DEFAULT 0,
    last_fetch    timestamptz,
    last_ok       timestamptz,
    last_error    text NOT NULL DEFAULT '',
    etag          text NOT NULL DEFAULT '',
    retro_at      timestamptz,
    retro_hits    integer,
    created_by    text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS intel_feeds_preset ON intel_feeds (preset) WHERE preset <> '';

CREATE TABLE IF NOT EXISTS intel_indicators (
    feed_id    bigint NOT NULL REFERENCES intel_feeds ON DELETE CASCADE,
    value      text NOT NULL,
    type       text NOT NULL CHECK (type IN ('ip', 'cidr', 'domain')),
    note       text NOT NULL DEFAULT '',
    added_by   text NOT NULL DEFAULT '',
    added_at   timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    PRIMARY KEY (feed_id, value)
);
CREATE INDEX IF NOT EXISTS intel_indicators_value ON intel_indicators (value);

INSERT INTO intel_feeds (name, kind, category, severity, description, enabled)
VALUES ('Elenco interno', 'manual', 'malware', 'high',
        'Indirizzi e domini segnalati dal vostro team, da fornitori o da altre organizzazioni.', true)
ON CONFLICT (name) DO NOTHING;
