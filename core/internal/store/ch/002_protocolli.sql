-- Protocolli riconosciuti oltre a TLS e HTTP (SSH, RDP, SMB, Kerberos, NTLM) e QUIC.

ALTER TABLE {{db}}.tls ADD COLUMN IF NOT EXISTS transport LowCardinality(String) DEFAULT 'tcp' AFTER port;

CREATE TABLE IF NOT EXISTS {{db}}.sessions (
    ts          DateTime64(3, 'UTC'),
    sensor_id   UInt32,
    client      String,
    server      String,
    port        UInt16,
    transport   LowCardinality(String),
    protocol    LowCardinality(String),
    auth        LowCardinality(String),
    user        String,
    domain      String,
    host        String,
    client_sw   String,
    server_sw   String,
    hash        String,
    server_hash String,
    info        String,
    weak        String,
    demo        UInt8,
    INDEX i_client client TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX i_server server TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX i_user user TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL {{agg_retention_days}} DAY
SETTINGS ttl_only_drop_parts = 1;
