-- Estrazioni di pacchetti su richiesta. L'interfaccia crea la richiesta, l'hub la consegna al
-- sensore con la risposta all'heartbeat, il sensore cerca nel suo buffer circolare e invia il
-- file, che resta qui a pezzi da 1 MB (pcap compresso) fino alla scadenza. Ogni richiesta e
-- ogni download finiscono nel registro: i pacchetti contengono dati personali.

CREATE TABLE pcap_requests (
    id           bigserial PRIMARY KEY,
    sensor_id    bigint NOT NULL REFERENCES sensors ON DELETE CASCADE,
    status       text NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'running', 'done', 'failed', 'expired')),
    ip_a         inet NOT NULL,
    ip_b         inet,
    port         integer CHECK (port BETWEEN 0 AND 65535),
    proto        text NOT NULL DEFAULT '' CHECK (proto IN ('', 'tcp', 'udp', 'icmp')),
    t_from       timestamptz NOT NULL,
    t_to         timestamptz NOT NULL CHECK (t_to > t_from),
    reason       text NOT NULL,
    alert_id     bigint REFERENCES alerts ON DELETE SET NULL,
    requested_by text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    packets      bigint NOT NULL DEFAULT 0,
    bytes        bigint NOT NULL DEFAULT 0, -- pcap non compresso
    stored       bigint NOT NULL DEFAULT 0, -- compresso, come sta nel database
    truncated    boolean NOT NULL DEFAULT false,
    sha256       text NOT NULL DEFAULT '',
    error        text NOT NULL DEFAULT '',
    expires_at   timestamptz
);

CREATE INDEX pcap_requests_open ON pcap_requests (sensor_id, created_at) WHERE status IN ('pending', 'running');
CREATE INDEX pcap_requests_created ON pcap_requests (created_at DESC);

CREATE TABLE pcap_chunks (
    request_id bigint NOT NULL REFERENCES pcap_requests ON DELETE CASCADE,
    seq        integer NOT NULL,
    data       bytea NOT NULL,
    PRIMARY KEY (request_id, seq)
);

-- ruolo minimo per chiedere e scaricare pacchetti; gli amministratori possono abbassarlo ad analista
INSERT INTO settings (key, value) VALUES ('pcap_role', '"admin"') ON CONFLICT (key) DO NOTHING;
