# API v1

L'API REST permette di leggere traffico, dispositivi e allarmi da altri sistemi (SIEM, ticketing, script) e di aggiornare allarmi e dispositivi.

L'indirizzo base è quello dell'interfaccia: `https://hyperwave.esempio.it/api/v1`.

## Autenticazione

Un amministratore crea i token in **Impostazioni → API**. Per ogni token sceglie:

- un nome;
- un ruolo: lettore, analista o amministratore;
- una scadenza: mai, 30, 90, 180 o 365 giorni.

Il token (`hwk_…`) viene mostrato una volta sola e nel database ne resta solo l'hash. Revocarlo ha effetto immediato.

```bash
curl -H "Authorization: Bearer hwk_..." https://hyperwave.esempio.it/api/v1/status
```

I permessi del token sono quelli del suo ruolo:

| Ruolo | Può |
|---|---|
| `viewer` | tutte le letture |
| `analyst` | in più: aggiornare allarmi e dispositivi |
| `admin` | in più: accendere e spegnere il live |

Le modifiche fatte con l'API finiscono nel registro delle attività. Come utente compare `api:<nome del token>` e i dettagli riportano `"api": true`.

## Risposte ed errori

Le risposte sono in JSON, con `Cache-Control: no-store`. Gli errori hanno la forma `{"error": "messaggio"}`:

| Codice | Significato |
|---|---|
| 400 | parametri o corpo non validi; il messaggio dice quale campo |
| 401 | token mancante, non valido, scaduto o revocato |
| 403 | il ruolo del token non permette l'operazione |
| 404 | risorsa inesistente |
| 409 | conflitto: per esempio, riaprire un allarme quando ne esiste già uno aperto identico |
| 500 | errore interno; il dettaglio è nei log del server |

Le date sono in formato ISO 8601 UTC. Fanno eccezione le date dei flussi, che arrivano come `YYYY-MM-DD HH:MM:SS.mmm` UTC, il formato nativo di ClickHouse.

## Endpoint

### `GET /status`

Mostra lo stato generale del sistema. Ruolo minimo: lettore.

```json
{
  "live": true,
  "time": "2026-11-09T15:53:09.321Z",
  "alerts": { "active": 89, "new_24h": 82, "by_severity": { "critical": { "open": 1, "ack": 0 }, "high": { "open": 40, "ack": 2 } } },
  "devices": { "total": 94, "active_1h": 90, "new_24h": 2, "unapproved": 12 },
  "sensors": [{ "id": 1, "name": "Sede centrale", "state": "online", "last_seen": "2026-11-09T15:53:08.029Z" }],
  "traffic_1h": { "bytes_in": 5300000000, "bytes_out": 820000000, "bytes_internal": 2100000000, "flows": 184000 }
}
```

`state` di un sensore vale:

- `online`: ultimo contatto da meno di 45 secondi;
- `late`: da meno di 2 minuti;
- `offline`;
- `never`: mai collegato;
- `disabled`.

Utile per i controlli di monitoraggio: se `sensors[].state` non è `online` o se `live` è `false`, c'è un problema.

### `GET /alerts`

Restituisce l'elenco degli allarmi. Prima i non chiusi, poi per gravità e per ultima comparsa.

| Parametro | Valori |
|---|---|
| `status` | `active` (aperti e presi in carico), `open`, `ack`, `resolved`; assente = tutti |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `rule` | codice della regola, per esempio `beacon`, `portscan`, `exfil` |
| `q` | testo cercato in titolo, descrizione, origine, destinazione e nome del dispositivo |
| `days` | solo gli allarmi visti negli ultimi N giorni |
| `assignee` | nome utente assegnatario |
| `limit` | da 1 a 1000, predefinito 100 |

```bash
curl -H "Authorization: Bearer $T" "$BASE/alerts?status=active&severity=critical"
```

Risposta: `{"count": N, "alerts": [...]}`. Ogni allarme contiene questi campi:

- identità: `id`, `rule`, `rule_name`, `category`, `severity`, `mitre`;
- descrizione: `title`, `summary`, `src_ip`, `dst_ip`, `device_id`, `detail` (oggetto con i dati specifici della regola);
- tempi e conteggio: `first_seen`, `last_seen`, `count`;
- gestione: `status`, `assignee`, `resolution`, `resolved_by`, `resolved_at`.

### `GET /alerts/{id}`

Restituisce un allarme con la sua cronologia: `{"alert": {...}, "notes": [{"ts", "username", "kind", "text"}]}`. Il campo `kind` vale `status`, `assign` o `note`.

### `POST /alerts/{id}`

Aggiorna un allarme. Ruolo minimo: analista. Il corpo JSON contiene solo i campi da cambiare:

```json
{ "status": "resolved", "resolution": "false_positive", "note": "Backup notturno verso il NAS, previsto." }
```

| Campo | Valori |
|---|---|
| `status` | `open`, `ack`, `resolved` |
| `resolution` | obbligatoria con `resolved`: `true_positive`, `benign`, `false_positive`, `duplicate`, `other` |
| `assignee` | nome di un utente attivo con ruolo analista o amministratore; `""` toglie l'assegnazione |
| `note` | testo libero, massimo 4000 caratteri |

Ogni cambio di stato o di assegnazione viene registrato nella cronologia dell'allarme. La risposta è uguale a quella di `GET /alerts/{id}`.

### `GET /devices`

Restituisce l'inventario dei dispositivi, ordinato per indirizzo IP.

| Parametro | Valori |
|---|---|
| `q` | testo cercato in nome, nome host, IP, MAC, produttore, proprietario, posizione, tipo; etichetta esatta |
| `type` | tipo, per esempio `Server`, `Stampante`, `Postazione` |
| `vlan` | numero di VLAN |
| `status` | `new` (ultime 24 ore), `unapproved`, `active` (ultima ora), `inactive`, `alerts` (con allarmi aperti) |
| `limit` | da 1 a 10000, predefinito 1000 |

Ogni dispositivo contiene questi campi:

- rilevati: `id`, `mac`, `ip`, `ips`, `hostname`, `vendor`, `os`, `type`, `vlan`, `sensor`;
- attività: `first_seen`, `last_seen`, `bytes`, `flows`;
- inseriti dagli utenti: `name`, `owner`, `location`, `notes`, `tags`, `criticality`, `approved`, `approved_by`, `approved_at`;
- conteggi: `open_alerts`, `services`.

### `GET /devices/{id}`

Restituisce il dispositivo con i servizi in ascolto: `{"device": {...}, "services": [{"proto", "port", "app", "first_seen", "last_seen", "flows", "external"}]}`.

### `PATCH /devices/{id}`

Aggiorna un dispositivo. Ruolo minimo: analista. Il corpo JSON contiene solo i campi da cambiare:

```json
{ "name": "Server contabilità", "owner": "Amministrazione", "tags": ["erp", "backup"], "criticality": "high", "approved": true }
```

| Campo | Valori |
|---|---|
| `name`, `owner`, `location` | testo, massimo 100 caratteri |
| `notes` | testo, massimo 4000 caratteri |
| `tags` | elenco di testi, massimo 20, convertiti in minuscolo |
| `criticality` | `low`, `normal`, `high`, `critical` |
| `approved` | `true` oppure `false`; chi approva e quando vengono registrati in automatico |

### `GET /flows`

Cerca nei flussi. I parametri sono gli stessi della pagina Flussi, quindi un indirizzo copiato dall'interfaccia funziona anche qui.

| Parametro | Valori |
|---|---|
| `range` | `15m`, `1h` (predefinito), `6h`, `24h`, `7d`, `30d` |
| `at` | istante finale in secondi Unix; assente = adesso |
| `ip` | indirizzo o rete CIDR, come origine o destinazione |
| `peer` | secondo indirizzo o rete: flussi tra `ip` e `peer` |
| `port` | porta di destinazione |
| `proto` | `TCP`, `UDP`, `ICMP`, `ICMPv6` |
| `app` | applicazione riconosciuta, per esempio `HTTPS`, `Microsoft 365` |
| `domain` | dominio, compresi i sottodomini |
| `cc` | paese, codice ISO a due lettere |
| `dir` | `outbound`, `inbound`, `internal`, `external` |
| `failed` | `1` = solo connessioni non riuscite |
| `min` | byte minimi del flusso |
| `sensor` | id del sensore |
| `limit` | da 1 a 10000, predefinito 1000 |

```bash
curl -H "Authorization: Bearer $T" "$BASE/flows?range=24h&ip=10.0.5.20&dir=outbound&min=10000000"
```

Risposta: `{"count": N, "filter": {...filtri applicati...}, "flows": [...]}`. Per esportazioni più grandi c'è `/api/flussi.csv`, con gli stessi parametri e il cookie di sessione.

### `GET /sensors`

Elenca i sensori con stato, sede, ultimo contatto, versione e statistiche (pacchetti, byte, perdite, record in coda).

### `GET /live` e `PUT /live`

- `GET /live` restituisce `{"live": true}`. Ruolo minimo: lettore.
- `PUT /live` con corpo `{"live": false}` spegne il live (ruolo amministratore). Spegnerlo ferma la raccolta e il motore di rilevamento.

## Esempi

Allarmi critici aperti, per un controllo Nagios/Zabbix:

```bash
n=$(curl -fsS -H "Authorization: Bearer $T" "$BASE/alerts?status=open&severity=critical&limit=1000" | jq .count)
[ "$n" -eq 0 ] && echo "OK" || { echo "CRITICAL: $n allarmi critici"; exit 2; }
```

Chiudere come falso positivo tutti gli allarmi di una regola su un host:

```bash
for id in $(curl -fsS -H "Authorization: Bearer $T" "$BASE/alerts?status=active&rule=insecure&q=10.0.9.4" | jq '.alerts[].id'); do
  curl -fsS -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
    -d '{"status":"resolved","resolution":"false_positive","note":"Stampante legacy, FTP previsto"}' "$BASE/alerts/$id" >/dev/null
done
```

Inventario in CSV per la CMDB:

```bash
curl -fsS -H "Authorization: Bearer $T" "$BASE/devices?limit=10000" \
  | jq -r '.devices[] | [.ip, .mac, .name // .hostname, .vendor, .type, .owner] | @csv'
```
