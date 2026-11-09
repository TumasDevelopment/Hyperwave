-- Hyperwave: schema iniziale di PostgreSQL (configurazione, inventario, allarmi, accessi).

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT ''
);
INSERT INTO settings (key, value) VALUES ('live', 'true');

-- Utenti e accessi (gestiti dall'interfaccia web)
CREATE TABLE users (
    id            bigserial PRIMARY KEY,
    username      text NOT NULL,
    display_name  text NOT NULL DEFAULT '',
    email         text NOT NULL DEFAULT '',
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    totp_secret   text,
    disabled      boolean NOT NULL DEFAULT false,
    must_change   boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login    timestamptz
);
CREATE UNIQUE INDEX users_username ON users (lower(username));

CREATE TABLE sessions (
    token_hash  bytea PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES users ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_active timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    ip          text NOT NULL DEFAULT '',
    user_agent  text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE api_tokens (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    role       text NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    last_used  timestamptz,
    revoked_at timestamptz
);

CREATE TABLE audit_log (
    id       bigserial PRIMARY KEY,
    ts       timestamptz NOT NULL DEFAULT now(),
    username text NOT NULL,
    action   text NOT NULL,
    target   text NOT NULL DEFAULT '',
    detail   jsonb NOT NULL DEFAULT '{}',
    ip       text NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_ts ON audit_log (ts DESC);

-- Sensori: il token vero si mostra una volta sola, qui resta lo sha256
CREATE TABLE sensors (
    id              bigserial PRIMARY KEY,
    name            text NOT NULL UNIQUE,
    site            text NOT NULL DEFAULT '',
    token_hash      bytea NOT NULL UNIQUE,
    enabled         boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    created_by      text NOT NULL DEFAULT '',
    last_seen       timestamptz,
    last_ingest     timestamptz,
    version         text NOT NULL DEFAULT '',
    mode            text NOT NULL DEFAULT '',
    hostname        text NOT NULL DEFAULT '',
    stats           jsonb NOT NULL DEFAULT '{}',
    records         bigint NOT NULL DEFAULT 0
);

-- Inventario: chiave mac:<mac> oppure ip:<ip> finché il MAC non è noto
CREATE TABLE devices (
    id          bigserial PRIMARY KEY,
    key         text NOT NULL UNIQUE,
    mac         text NOT NULL DEFAULT '',
    ip          text NOT NULL DEFAULT '',
    ips         text[] NOT NULL DEFAULT '{}',
    hostname    text NOT NULL DEFAULT '',
    vendor      text NOT NULL DEFAULT '',
    os          text NOT NULL DEFAULT '',
    type        text NOT NULL DEFAULT '',
    vlan        integer NOT NULL DEFAULT 0,
    sensor_id   bigint REFERENCES sensors ON DELETE SET NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    bytes_out   bigint NOT NULL DEFAULT 0,
    bytes_in    bigint NOT NULL DEFAULT 0,
    flows       bigint NOT NULL DEFAULT 0,
    -- campi curati dalle persone
    name        text NOT NULL DEFAULT '',
    owner       text NOT NULL DEFAULT '',
    location    text NOT NULL DEFAULT '',
    notes       text NOT NULL DEFAULT '',
    tags        text[] NOT NULL DEFAULT '{}',
    criticality text NOT NULL DEFAULT 'normal' CHECK (criticality IN ('low', 'normal', 'high', 'critical')),
    approved    boolean NOT NULL DEFAULT false,
    approved_by text NOT NULL DEFAULT '',
    approved_at timestamptz
);
CREATE INDEX devices_ip ON devices (ip);
CREATE INDEX devices_last_seen ON devices (last_seen DESC);

CREATE TABLE device_services (
    device_id  bigint NOT NULL REFERENCES devices ON DELETE CASCADE,
    proto      text NOT NULL,
    port       integer NOT NULL,
    app        text NOT NULL DEFAULT '',
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    flows      bigint NOT NULL DEFAULT 0,
    external   boolean NOT NULL DEFAULT false, -- raggiunto anche da internet
    PRIMARY KEY (device_id, proto, port)
);

-- Regole di rilevamento: il catalogo lo scrive l'hub, le scelte le fanno gli amministratori
CREATE TABLE rule_catalog (
    id               text PRIMARY KEY,
    name             text NOT NULL,
    category         text NOT NULL,
    description      text NOT NULL,
    default_severity text NOT NULL,
    mitre            text NOT NULL DEFAULT '',
    params           jsonb NOT NULL DEFAULT '{}',
    param_help       jsonb NOT NULL DEFAULT '{}',
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE rules (
    id         text PRIMARY KEY,
    enabled    boolean NOT NULL DEFAULT true,
    severity   text,
    params     jsonb NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT ''
);

-- Eccezioni: un allarme che corrisponde non viene creato
CREATE TABLE suppressions (
    id         bigserial PRIMARY KEY,
    rule       text NOT NULL DEFAULT '',  -- '' = tutte le regole
    src        text NOT NULL DEFAULT '',  -- indirizzo o rete CIDR, '' = qualsiasi
    dst        text NOT NULL DEFAULT '',
    reason     text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    hits       bigint NOT NULL DEFAULT 0,
    last_hit   timestamptz
);

CREATE TABLE alerts (
    id          bigserial PRIMARY KEY,
    dedup_key   text NOT NULL,
    rule        text NOT NULL,
    severity    text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title       text NOT NULL,
    summary     text NOT NULL DEFAULT '',
    src_ip      text NOT NULL DEFAULT '',
    dst_ip      text NOT NULL DEFAULT '',
    device_id   bigint REFERENCES devices ON DELETE SET NULL,
    sensor_id   bigint REFERENCES sensors ON DELETE SET NULL,
    mitre       text NOT NULL DEFAULT '',
    detail      jsonb NOT NULL DEFAULT '{}',
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    count       integer NOT NULL DEFAULT 1,
    status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ack', 'resolved')),
    assignee    text NOT NULL DEFAULT '',
    resolved_by text NOT NULL DEFAULT '',
    resolved_at timestamptz,
    resolution  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX alerts_dedup_open ON alerts (dedup_key) WHERE status <> 'resolved';
CREATE INDEX alerts_last_seen ON alerts (last_seen DESC);
CREATE INDEX alerts_status ON alerts (status, severity);
CREATE INDEX alerts_src ON alerts (src_ip);

CREATE TABLE alert_notes (
    id       bigserial PRIMARY KEY,
    alert_id bigint NOT NULL REFERENCES alerts ON DELETE CASCADE,
    ts       timestamptz NOT NULL DEFAULT now(),
    username text NOT NULL,
    kind     text NOT NULL DEFAULT 'note', -- note | status | assign
    text     text NOT NULL
);
CREATE INDEX alert_notes_alert ON alert_notes (alert_id, ts);
