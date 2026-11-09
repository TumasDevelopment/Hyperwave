-- Hyperwave: schema iniziale di ClickHouse. Un'istruzione per blocco, separate da righe che finiscono con ";".
-- {{db}}, {{retention_days}} (dati grezzi) e {{agg_retention_days}} (aggregati) li sostituisce l'hub.

CREATE TABLE IF NOT EXISTS {{db}}.flows (
    ts        DateTime64(3, 'UTC'),
    ts_end    DateTime64(3, 'UTC'),
    sensor_id UInt32,
    site      LowCardinality(String),
    vlan      UInt16,
    proto     LowCardinality(String),
    src       String,
    sport     UInt16,
    dst       String,
    dport     UInt16,
    direction LowCardinality(String),
    app       LowCardinality(String),
    domain    String,
    bytes_out UInt64,
    bytes_in  UInt64,
    pkts_out  UInt32,
    pkts_in   UInt32,
    flags     LowCardinality(String),
    est       UInt8,
    rtt       Float32,
    retrans   UInt32,
    country   LowCardinality(String),
    asn       UInt32,
    as_org    LowCardinality(String),
    src_name  String,
    dst_name  String,
    demo      UInt8,
    INDEX i_src src TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX i_dst dst TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX i_domain domain TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX i_dport dport TYPE set(256) GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL {{retention_days}} DAY
SETTINGS ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS {{db}}.dns (
    ts        DateTime64(3, 'UTC'),
    sensor_id UInt32,
    client    String,
    server    String,
    query     String,
    qtype     LowCardinality(String),
    rcode     LowCardinality(String),
    answers   Array(String),
    rtt       Float32,
    demo      UInt8,
    INDEX i_client client TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX i_query query TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL {{retention_days}} DAY
SETTINGS ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS {{db}}.tls (
    ts           DateTime64(3, 'UTC'),
    sensor_id    UInt32,
    client       String,
    server       String,
    port         UInt16,
    sni          String,
    version      LowCardinality(String),
    alpn         LowCardinality(String),
    ja4          String,
    cert_subject String,
    cert_issuer  String,
    cert_expiry  Int64,
    self_signed  UInt8,
    demo         UInt8,
    INDEX i_server server TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX i_sni sni TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL {{retention_days}} DAY
SETTINGS ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS {{db}}.http (
    ts         DateTime64(3, 'UTC'),
    sensor_id  UInt32,
    client     String,
    server     String,
    port       UInt16,
    method     LowCardinality(String),
    host       String,
    uri        String,
    status     UInt16,
    user_agent String,
    demo       UInt8
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL {{retention_days}} DAY
SETTINGS ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS {{db}}.events (
    ts        DateTime64(3, 'UTC'),
    sensor_id UInt32,
    kind      LowCardinality(String),
    severity  LowCardinality(String),
    title     String,
    src       String,
    dst       String,
    dport     UInt16,
    signature String,
    category  LowCardinality(String),
    detail    String,
    demo      UInt8
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL {{agg_retention_days}} DAY
SETTINGS ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS {{db}}.rates (
    ts             DateTime64(3, 'UTC'),
    sensor_id      UInt32,
    secs           Float32,
    bytes_in       UInt64,
    bytes_out      UInt64,
    bytes_internal UInt64,
    packets        UInt64,
    flows          UInt64,
    drops          UInt64
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (sensor_id, ts)
TTL toDateTime(ts) + INTERVAL {{retention_days}} DAY
SETTINGS ttl_only_drop_parts = 1;

-- Aggregati: restano più a lungo dei dati grezzi e rendono veloci i periodi lunghi.
-- Sono SummingMergeTree: le query devono comunque usare sum() con GROUP BY.

CREATE TABLE IF NOT EXISTS {{db}}.traffic_1m (
    minute    DateTime('UTC'),
    sensor_id UInt32,
    direction LowCardinality(String),
    app       LowCardinality(String),
    country   LowCardinality(String),
    bytes_out UInt64,
    bytes_in  UInt64,
    pkts      UInt64,
    flows     UInt64
) ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (minute, sensor_id, direction, app, country)
TTL minute + INTERVAL {{agg_retention_days}} DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS {{db}}.traffic_1m_mv TO {{db}}.traffic_1m AS
SELECT toStartOfMinute(ts) AS minute, sensor_id, direction, app, country,
       sum(bytes_out) AS bytes_out, sum(bytes_in) AS bytes_in,
       sum(toUInt64(pkts_out) + pkts_in) AS pkts, count() AS flows
FROM {{db}}.flows
GROUP BY minute, sensor_id, direction, app, country;

CREATE TABLE IF NOT EXISTS {{db}}.hosts_1h (
    hour       DateTime('UTC'),
    sensor_id  UInt32,
    ip         String,
    bytes_sent UInt64,
    bytes_recv UInt64,
    flows_out  UInt64,
    flows_in   UInt64
) ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, ip, sensor_id)
TTL hour + INTERVAL {{agg_retention_days}} DAY;

-- Ogni flusso conta per l'estremo interno: per i flussi interni, per entrambi.
CREATE MATERIALIZED VIEW IF NOT EXISTS {{db}}.hosts_1h_mv TO {{db}}.hosts_1h AS
SELECT toStartOfHour(ts) AS hour, sensor_id, e.1 AS ip,
       sum(e.2) AS bytes_sent, sum(e.3) AS bytes_recv, sum(e.4) AS flows_out, sum(e.5) AS flows_in
FROM {{db}}.flows
ARRAY JOIN arrayFilter(x -> x.1 != '', [
    tuple(if(direction IN ('outbound', 'internal'), src, ''), bytes_out, bytes_in, toUInt64(1), toUInt64(0)),
    tuple(if(direction IN ('inbound', 'internal'), dst, ''), bytes_in, bytes_out, toUInt64(0), toUInt64(1))
]) AS e
GROUP BY hour, sensor_id, ip;

CREATE TABLE IF NOT EXISTS {{db}}.dns_1h (
    hour      DateTime('UTC'),
    sensor_id UInt32,
    domain    String,
    rcode     LowCardinality(String),
    queries   UInt64
) ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, domain, rcode, sensor_id)
TTL hour + INTERVAL {{agg_retention_days}} DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS {{db}}.dns_1h_mv TO {{db}}.dns_1h AS
SELECT toStartOfHour(ts) AS hour, sensor_id, cutToFirstSignificantSubdomain(query) AS domain, rcode, count() AS queries
FROM {{db}}.dns
GROUP BY hour, sensor_id, domain, rcode;
