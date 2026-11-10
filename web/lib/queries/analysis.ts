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
    ch<{ sni: string; sessions: number; clients: number; quic: number }>(
      `SELECT sni, count() AS sessions, uniq(client) AS clients, countIf(transport = 'quic') AS quic FROM tls WHERE ${TS_RANGE} AND sni != ''
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

// Altri protocolli: SSH, RDP, SMB, Kerberos, NTLM (tabella sessions)

export async function protocolsOverview(range: RangeKey) {
  const { t0, t1 } = timeWindow(range);
  const [protocols, weak, users, kerberos, ssh, shares] = await Promise.all([
    ch<{ protocol: string; sessions: number; clients: number; servers: number; weak: number }>(
      `SELECT protocol, count() AS sessions, uniq(client) AS clients, uniq(server) AS servers, countIf(weak != '') AS weak
       FROM sessions WHERE ${TS_RANGE} GROUP BY protocol ORDER BY sessions DESC`,
      { t0, t1 },
    ),
    ch<{ protocol: string; server: string; port: number; weak: string; sessions: number; clients: number; users: string[]; last: string }>(
      `SELECT protocol, server, any(port) AS port, weak, count() AS sessions, uniq(client) AS clients,
              groupUniqArrayIf(5)(user, user != '') AS users, toString(max(ts)) AS last
       FROM sessions WHERE ${TS_RANGE} AND weak != '' GROUP BY protocol, server, weak ORDER BY sessions DESC LIMIT 50`,
      { t0, t1 },
    ),
    ch<{ user: string; domain: string; auth: string; sessions: number; clients: string[]; protocols: string[]; last: string }>(
      `SELECT user, any(domain) AS domain, any(auth) AS auth, count() AS sessions, groupUniqArray(4)(client) AS clients,
              groupUniqArray(protocol) AS protocols, toString(max(ts)) AS last
       FROM sessions WHERE ${TS_RANGE} AND user != '' GROUP BY user ORDER BY sessions DESC LIMIT 40`,
      { t0, t1 },
    ),
    ch<{ error: string; attempts: number; clients: number; users: string[] }>(
      `SELECT extract(info, 'errore: (.*)$') AS error, count() AS attempts, uniq(client) AS clients, groupUniqArrayIf(6)(user, user != '') AS users
       FROM sessions WHERE ${TS_RANGE} AND protocol = 'kerberos' AND position(info, 'errore: ') > 0
       GROUP BY error ORDER BY attempts DESC LIMIT 20`,
      { t0, t1 },
    ),
    ch<{ software: string; side: string; sessions: number; hosts: number }>(
      `SELECT software, side, count() AS sessions, uniq(host) AS hosts FROM (
         SELECT client_sw AS software, 'client' AS side, client AS host FROM sessions WHERE ${TS_RANGE} AND protocol = 'ssh' AND client_sw != ''
         UNION ALL
         SELECT server_sw AS software, 'server' AS side, server AS host FROM sessions WHERE ${TS_RANGE} AND protocol = 'ssh' AND server_sw != ''
       ) GROUP BY software, side ORDER BY sessions DESC LIMIT 30`,
      { t0, t1 },
    ),
    ch<{ server: string; shares: string; sessions: number; clients: number }>(
      `SELECT server, arrayStringConcat(arrayDistinct(arrayFlatten(groupArray(splitByString(', ', extract(info, 'condivisioni: ([^·]+)'))))), ', ') AS shares,
              count() AS sessions, uniq(client) AS clients
       FROM sessions WHERE ${TS_RANGE} AND protocol = 'smb' AND position(info, 'condivisioni: ') > 0
       GROUP BY server ORDER BY sessions DESC LIMIT 30`,
      { t0, t1 },
    ),
  ]);
  return { protocols, weak, users, kerberos, ssh, shares };
}

/** Sessioni di un indirizzo, come client o come server: per la pagina del dispositivo. */
export async function sessionsFor(ips: string[], range: RangeKey = "7d") {
  if (ips.length === 0) return [];
  const { t0, t1 } = timeWindow(range);
  return ch<{ protocol: string; peer: string; role: string; user: string; domain: string; auth: string; info: string; weak: string; sessions: number; last: string }>(
    `SELECT protocol, if(client IN {ips:Array(String)}, server, client) AS peer, if(client IN {ips:Array(String)}, 'client', 'server') AS role,
            user, any(domain) AS domain, any(auth) AS auth, any(info) AS info, any(weak) AS weak, count() AS sessions, toString(max(ts)) AS last
     FROM sessions WHERE ${TS_RANGE} AND (client IN {ips:Array(String)} OR server IN {ips:Array(String)})
     GROUP BY protocol, peer, role, user ORDER BY max(ts) DESC LIMIT 30`,
    { t0, t1, ips },
  );
}
