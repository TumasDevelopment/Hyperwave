import "server-only";
import { ch, TS_RANGE } from "../ch";
import { type RangeKey, timeWindow } from "../ranges";

const HOUR_RANGE = "hour >= toStartOfHour(toDateTime({t0:UInt32}, 'UTC')) AND hour < toDateTime({t1:UInt32}, 'UTC')";

// DNS

export async function dnsOverview(range: RangeKey) {
  const { t0, t1 } = timeWindow(range);
  const [totals, domains, nx, clients, types, servers] = await Promise.all([
    ch<{ queries: number; nx: number; clients: number; domains: number; avg_rtt: number }>(
      `SELECT count() AS queries, countIf(rcode = 'NXDOMAIN') AS nx, uniq(client) AS clients,
              uniq(cutToFirstSignificantSubdomain(query)) AS domains, avgIf(rtt, rtt > 0) AS avg_rtt
       FROM dns WHERE ${TS_RANGE}`,
      { t0, t1 },
    ),
    ch<{ domain: string; queries: number; clients: number }>(
      `SELECT cutToFirstSignificantSubdomain(query) AS domain, count() AS queries, uniq(client) AS clients
       FROM dns WHERE ${TS_RANGE} AND domain != '' GROUP BY domain ORDER BY queries DESC LIMIT 25`,
      { t0, t1 },
    ),
    ch<{ domain: string; queries: number; clients: number; example: string }>(
      `SELECT cutToFirstSignificantSubdomain(query) AS domain, count() AS queries, uniq(client) AS clients, any(query) AS example
       FROM dns WHERE ${TS_RANGE} AND rcode = 'NXDOMAIN' GROUP BY domain ORDER BY queries DESC LIMIT 20`,
      { t0, t1 },
    ),
    ch<{ client: string; queries: number; nx: number; domains: number }>(
      `SELECT client, count() AS queries, countIf(rcode = 'NXDOMAIN') AS nx, uniq(query) AS domains
       FROM dns WHERE ${TS_RANGE} GROUP BY client ORDER BY queries DESC LIMIT 20`,
      { t0, t1 },
    ),
    ch<{ qtype: string; queries: number }>(
      `SELECT qtype, count() AS queries FROM dns WHERE ${TS_RANGE} GROUP BY qtype ORDER BY queries DESC LIMIT 10`,
      { t0, t1 },
    ),
    ch<{ server: string; queries: number; clients: number; avg_rtt: number }>(
      `SELECT server, count() AS queries, uniq(client) AS clients, avgIf(rtt, rtt > 0) AS avg_rtt
       FROM dns WHERE ${TS_RANGE} GROUP BY server ORDER BY queries DESC LIMIT 15`,
      { t0, t1 },
    ),
  ]);
  return { totals: totals[0], domains, nx, clients, types, servers };
}

/** Domini che compaiono per la prima volta nel periodo (rispetto ai 30 giorni prima). */
export async function newDomains(range: RangeKey) {
  const { t0, t1 } = timeWindow(range);
  return ch<{ domain: string; queries: number; first: string }>(
    `SELECT domain, sum(queries) AS queries, toString(min(hour)) AS first FROM dns_1h
     WHERE ${HOUR_RANGE} AND domain != '' AND domain NOT IN (
       SELECT domain FROM dns_1h WHERE hour >= toDateTime({t0:UInt32}, 'UTC') - INTERVAL 30 DAY AND hour < toStartOfHour(toDateTime({t0:UInt32}, 'UTC'))
     )
     GROUP BY domain ORDER BY queries DESC LIMIT 25`,
    { t0, t1 },
  );
}

// TLS

export async function tlsOverview(range: RangeKey) {
  const { t0, t1 } = timeWindow(range);
  const [versions, weak, certs, ja4, sni] = await Promise.all([
    ch<{ version: string; sessions: number; servers: number }>(
      `SELECT if(version = '', 'Sconosciuta', version) AS version, count() AS sessions, uniq(server) AS servers
       FROM tls WHERE ${TS_RANGE} GROUP BY version ORDER BY sessions DESC`,
      { t0, t1 },
    ),
    ch<{ server: string; port: number; sni: string; version: string; sessions: number; clients: number }>(
      // Filtro nella sottoquery: in ClickHouse l'alias «version» nasconderebbe la colonna nel WHERE.
      `SELECT server, port, any(sni) AS sni, any(version) AS version, count() AS sessions, uniq(client) AS clients
       FROM (SELECT server, port, sni, version, client FROM tls
             WHERE ${TS_RANGE} AND version IN ('SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'))
       GROUP BY server, port ORDER BY sessions DESC LIMIT 30`,
      { t0, t1 },
    ),
    ch<{ server: string; port: number; sni: string; subject: string; issuer: string; expiry: number; self_signed: number; sessions: number; last: string }>(
      `SELECT server, port, any(sni) AS sni, argMax(cert_subject, ts) AS subject, argMax(cert_issuer, ts) AS issuer,
              argMax(cert_expiry, ts) AS expiry, argMax(self_signed, ts) AS self_signed, count() AS sessions, toString(max(ts)) AS last
       FROM tls WHERE ${TS_RANGE} AND cert_subject != ''
       GROUP BY server, port
       HAVING expiry < toUnixTimestamp(now()) + 30 * 86400 OR self_signed = 1
       ORDER BY expiry LIMIT 50`,
      { t0, t1 },
    ),
    ch<{ ja4: string; clients: number; sessions: number; example_sni: string }>(
      `SELECT ja4, uniq(client) AS clients, count() AS sessions, anyIf(sni, sni != '') AS example_sni
       FROM tls WHERE ${TS_RANGE} AND ja4 != '' GROUP BY ja4 ORDER BY clients ASC, sessions DESC LIMIT 25`,
      { t0, t1 },
    ),
    ch<{ sni: string; sessions: number; clients: number }>(
      `SELECT sni, count() AS sessions, uniq(client) AS clients FROM tls WHERE ${TS_RANGE} AND sni != ''
       GROUP BY sni ORDER BY sessions DESC LIMIT 25`,
      { t0, t1 },
    ),
  ]);
  return { versions, weak, certs, ja4, sni };
}

// HTTP in chiaro

export async function httpOverview(range: RangeKey) {
  const { t0, t1 } = timeWindow(range);
  const [hosts, statuses, agents, recent] = await Promise.all([
    ch<{ host: string; requests: number; clients: number; errors: number }>(
      `SELECT host, count() AS requests, uniq(client) AS clients, countIf(status >= 400) AS errors
       FROM http WHERE ${TS_RANGE} GROUP BY host ORDER BY requests DESC LIMIT 25`,
      { t0, t1 },
    ),
    ch<{ status: number; requests: number }>(
      `SELECT status, count() AS requests FROM http WHERE ${TS_RANGE} GROUP BY status ORDER BY requests DESC LIMIT 15`,
      { t0, t1 },
    ),
    ch<{ user_agent: string; requests: number; clients: number }>(
      `SELECT user_agent, count() AS requests, uniq(client) AS clients FROM http WHERE ${TS_RANGE} AND user_agent != ''
       GROUP BY user_agent ORDER BY clients ASC, requests DESC LIMIT 20`,
      { t0, t1 },
    ),
    ch<{ ts: string; client: string; server: string; port: number; method: string; host: string; uri: string; status: number; user_agent: string }>(
      `SELECT ts, client, server, port, method, host, uri, status, user_agent FROM http WHERE ${TS_RANGE}
       ORDER BY ts DESC LIMIT 100`,
      { t0, t1 },
    ),
  ]);
  return { hosts, statuses, agents, recent };
}

// Eventi IDS

export async function idsEvents(range: RangeKey) {
  const { t0, t1 } = timeWindow(range);
  return ch<{ signature: string; category: string; severity: string; events: number; sources: number; last: string }>(
    `SELECT signature, any(category) AS category, any(severity) AS severity, count() AS events, uniq(src) AS sources,
            toString(max(ts)) AS last
     FROM events WHERE ${TS_RANGE} AND kind = 'ids' GROUP BY signature ORDER BY events DESC LIMIT 30`,
    { t0, t1 },
  );
}
