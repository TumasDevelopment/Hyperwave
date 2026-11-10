-- Incidenti: allarmi collegati, riuniti dall'hub per dispositivo interno coinvolto.
-- key_entity è l'indirizzo del dispositivo; per ogni indirizzo c'è al massimo un
-- incidente non chiuso, gli allarmi nuovi si aggiungono a quello.

CREATE TABLE incidents (
    id          bigserial PRIMARY KEY,
    key_entity  text NOT NULL,
    device_id   bigint REFERENCES devices ON DELETE SET NULL,
    title       text NOT NULL,
    severity    text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'closed')),
    resolution  text NOT NULL DEFAULT '',
    assignee    text NOT NULL DEFAULT '',
    techniques  text[] NOT NULL DEFAULT '{}',
    alert_count integer NOT NULL DEFAULT 0,
    rule_count  integer NOT NULL DEFAULT 0,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    closed_by   text NOT NULL DEFAULT '',
    closed_at   timestamptz
);
CREATE UNIQUE INDEX incidents_open_entity ON incidents (key_entity) WHERE status <> 'closed';
CREATE INDEX incidents_status ON incidents (status, last_seen DESC);

CREATE TABLE incident_notes (
    id          bigserial PRIMARY KEY,
    incident_id bigint NOT NULL REFERENCES incidents ON DELETE CASCADE,
    ts          timestamptz NOT NULL DEFAULT now(),
    username    text NOT NULL,
    kind        text NOT NULL DEFAULT 'note', -- note | status | assign | system
    text        text NOT NULL
);
CREATE INDEX incident_notes_incident ON incident_notes (incident_id, ts);

ALTER TABLE alerts ADD COLUMN incident_id bigint REFERENCES incidents ON DELETE SET NULL;
-- tolto a mano da un incidente: il correlatore non lo riaggiunge
ALTER TABLE alerts ADD COLUMN incident_skip boolean NOT NULL DEFAULT false;
CREATE INDEX alerts_incident ON alerts (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX alerts_uncorrelated ON alerts (last_seen) WHERE incident_id IS NULL AND status <> 'resolved';
