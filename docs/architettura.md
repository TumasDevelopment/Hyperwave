# Architettura

## Componenti

| Processo | Linguaggio | Ruolo | Ascolta su |
|---|---|---|---|
| `hw-sensor` | Go, binario statico | cattura, ricostruzione dei flussi, analisi DNS/TLS/HTTP, ARP/DHCP/mDNS | nessuna porta |
| `hw-hub` | Go, binario statico | ricezione, arricchimento, inventario, motore di rilevamento, eventi live, pulizia | 127.0.0.1:3121 |
| `web` | Next.js 16, Node | pagine, azioni, API v1, ponte SSE per il live | 127.0.0.1:3120 |
| ClickHouse | — | dati di traffico | 127.0.0.1:8123 |
| PostgreSQL | — | stato e configurazione | 127.0.0.1:5432 |
| NATS | — | bus degli eventi live e dei comandi | 127.0.0.1:4222 |

Tutti i componenti leggono lo stesso file `.env`.

## Percorso dei dati

```
pacchetto ─► sensore ─► lotto (ogni 5 s, gzip, token) ─► hub ─┬─► ClickHouse   flows, dns, tls, http, events
                                                              ├─► PostgreSQL   devices, device_services
                                                              ├─► NATS         hw.live.* (5 s)
                                                              └─► motore       ogni 60 s ─► alerts (PG) + hw.live.event
```

### 1. Sensore

- **Cattura.** Legge i pacchetti con AF_PACKET (`-mode capture`), da un file pcap/pcapng (`-mode pcap`) oppure li genera (`-mode demo`).
- **Flussi.** Ricostruisce i flussi TCP e UDP con queste informazioni:
  - byte e pacchetti per direzione;
  - flag TCP e connessione stabilita o no;
  - RTT e ritrasmissioni.
- **Metadati.** Estrae:
  - DNS: domanda, tipo, codice di risposta, risposte;
  - TLS: SNI, versione, impronta JA4, certificato del server (soggetto, emittente, scadenza, autofirmato);
  - HTTP in chiaro: metodo, host, percorso, user agent, codice di risposta.
- **Inventario.** Da ARP, DHCP e mDNS ricava MAC, nome host, produttore e sistema operativo.
- **Coda di invio.** Se l'hub non risponde, i dati restano in memoria (fino a `HW_MAX_PENDING` record) e ripartono con attese crescenti.
- **Contenuto dei pacchetti.** Non viene mai salvato.

### 2. Hub: ricezione e arricchimento

- **Autenticazione dei sensori.** Ogni sensore si presenta con `Authorization: Bearer hws_…`. L'hub confronta l'hash SHA-256 del token con quello in PostgreSQL, tenendo una cache.
- **Limiti dei lotti.** Un lotto può contenere al massimo 50.000 record e 64 MB compressi. Se il live è spento, l'hub risponde senza registrare nulla e il sensore lo legge nella risposta. Se un database non risponde, l'hub restituisce 503 e il sensore riprova.
- **Arricchimento.** Ogni flusso riceve:
  - **direzione** (`outbound`, `inbound`, `internal`, `external`), calcolata dalle reti interne;
  - **applicazione**, da porta, SNI e dominio;
  - **paese e operatore**, da GeoLite2;
  - **nomi degli host**, dall'inventario.
- **Scrittura.** Le scritture in ClickHouse sono a lotti; le materialized view aggiornano gli aggregati `traffic_1m`, `hosts_1h` e `dns_1h`.

### 3. Hub: inventario

- **Raccolta.** Dispositivi e servizi in ascolto vengono raccolti in memoria e salvati in PostgreSQL ogni 10 secondi.
- **Chiave.** Un dispositivo è identificato dal MAC quando è noto, altrimenti dall'indirizzo IP.
- **Tipo.** Il tipo (postazione, server, stampante, telefono, switch…) è dedotto da produttore, porte e nome.

### 4. Hub: motore di rilevamento

- **Finestre.** Ogni 60 secondi il motore analizza le finestre di un minuto non ancora esaminate. La posizione raggiunta (il cursore) è salvata in `settings.engine_cursor`.
  - Se è rimasto indietro, avanza a passi di 5 minuti.
  - Non analizza mai gli ultimi 90 secondi, per lasciare arrivare i dati in ritardo.
- **Dati in ritardo.** Se un sensore invia dati più vecchi del cursore (dopo un'interruzione), il motore torna indietro e li rianalizza, fino a un massimo di 24 ore.
- **Regole.** Ogni regola è una funzione Go che interroga ClickHouse sulla finestra. Le sue soglie stanno in `rule_catalog` (valori predefiniti) e in `rules` (modifiche degli amministratori).
- **Deduplicazione.** Un allarme ha una chiave (`regola|origine|destinazione…`). Finché un allarme con la stessa chiave è aperto, l'hub aggiorna `last_seen` e il contatore invece di aprirne uno nuovo. Un indice unico parziale in PostgreSQL lo garantisce anche con più scritture contemporanee.
- **Eccezioni.** Le eccezioni (`suppressions`) vengono caricate ogni minuto. Gli allarmi che corrispondono non vengono aperti.
- **Apprendimento.** Le regole basate sulla norma (volume anomalo, paese raro, nuovo dispositivo) aspettano `HW_LEARNING_HOURS` ore dal primo dato. I dati storici (pcap, recupero dopo un'interruzione) non generano allarmi su dispositivi e servizi nuovi.

### 5. Live

Ogni 5 secondi l'hub pubblica su NATS:

| Soggetto | Contenuto |
|---|---|
| `hw.live.state` | banda in entrata/uscita/interna, pacchetti, flussi, sensori attivi, perdite |
| `hw.live.flows` | gli ultimi flussi significativi, già arricchiti |
| `hw.live.rate` | banda e perdite del singolo sensore, a ogni lotto |
| `hw.live.event` | allarme aperto, aggiornato o chiuso; evento IDS |

L'interfaccia si iscrive a `hw.live.>` e inoltra gli eventi al browser con Server-Sent Events (`/api/live`). La connessione resta aperta, con un segnale di attività ogni 20 secondi.

I comandi viaggiano nel verso opposto, su `hw.control.>`:

- `sensors`: svuota la cache dei token;
- `rules`: ricarica regole ed eccezioni;
- `settings`: ricarica il live e le reti.

L'interfaccia li invia subito dopo ogni modifica, così le impostazioni hanno effetto senza riavvii.

### 6. Interruttore «live»

Con il live spento (Impostazioni, oppure `PUT /api/v1/live`) l'hub scarta i dati dei sensori senza registrarli e il motore si ferma. Si usa durante una manutenzione, o quando non si vuole raccogliere dati. Lo stato e chi l'ha cambiato finiscono nel registro.

## Dati

### ClickHouse (`hyperwave`)

| Tabella | Contenuto | Conservazione |
|---|---|---|
| `flows` | un record per flusso | `HW_RETENTION_DAYS` (30) |
| `dns`, `tls`, `http` | metadati applicativi | `HW_RETENTION_DAYS` |
| `events` | eventi IDS e di sistema | `HW_RETENTION_DAYS` |
| `rates` | campioni di banda per sensore | `HW_RETENTION_DAYS` |
| `traffic_1m` | byte e flussi al minuto per direzione, applicazione, paese | `HW_AGG_RETENTION_DAYS` |
| `hosts_1h` | traffico orario per host | `HW_AGG_RETENTION_DAYS` |
| `dns_1h` | domande orarie per dominio e client | `HW_AGG_RETENTION_DAYS` |

Le tabelle sono partizionate per giorno e la scadenza (TTL) elimina partizioni intere, senza riscritture. Gli indici bloom filter su indirizzi e domini rendono veloce la ricerca dei flussi anche su settimane di dati.

### PostgreSQL (`hyperwave`)

| Tabella | Contenuto |
|---|---|
| `sensors` | sensori, hash del token, ultimo contatto, statistiche |
| `devices`, `device_services` | inventario e servizi in ascolto |
| `alerts`, `alert_notes` | allarmi, cronologia, note |
| `rule_catalog`, `rules`, `suppressions` | regole (predefinite e personalizzate), eccezioni |
| `users`, `sessions`, `login_challenges` | utenti, sessioni, secondo passo dei due fattori |
| `api_tokens` | token dell'API (solo hash) |
| `audit_log` | registro delle attività |
| `settings` | live, reti, cursore del motore, stato dei servizi collegati |

Ogni ora l'hub cancella:

- sessioni scadute;
- allarmi chiusi da più di `HW_ALERT_RETENTION_DAYS` giorni;
- voci del registro più vecchie di `HW_AUDIT_RETENTION_DAYS` giorni;
- servizi non più visti.

Le migrazioni stanno in `core/internal/store/{pg,ch}`. Sono incluse nel binario e l'hub le applica all'avvio.

## Sicurezza

**Rete**

- Ogni servizio ascolta solo su loopback.
- ClickHouse accetta l'utente `hyperwave` solo da 127.0.0.1.
- NATS richiede un token.

**Accesso degli utenti**

- **Password.** Protette con scrypt (N=32768); lunghezza minima 12 caratteri; il nome utente non può comparire nella password.
- **Sessioni.** Token casuale da 32 byte in un cookie `HttpOnly`, `Secure`, `SameSite=Lax`; nel database c'è solo l'hash. Durata massima 12 ore, chiusura dopo 60 minuti di inattività. Il cambio password chiude tutte le altre sessioni.
- **Due fattori.** TOTP a 30 secondi. Lo stesso codice non vale due volte (`totp_last_step`). Gli 8 codici di recupero sono salvati come hash e valgono una volta sola.
- **Tentativi.** Dopo 5 tentativi falliti per utente e indirizzo, oppure 20 per indirizzo, l'accesso si blocca per 15 minuti. Per non rivelare quali utenti esistono, il tempo di risposta è lo stesso anche per utenti inesistenti.

**Permessi e dati**

- **Ruoli.** Controllati sul server in ogni azione e in ogni rotta dell'API, non solo nascondendo i pulsanti.
- **Query.** Quelle verso ClickHouse sono parametrizzate e girano con `readonly=2`; quelle verso PostgreSQL sono parametrizzate.
- **Export CSV.** Le celle che iniziano con `=`, `+`, `-` o `@` vengono neutralizzate, per evitare formule nei fogli di calcolo.

**Pagine**

- Ogni pagina ha una Content Security Policy con nonce per richiesta.
- Le intestazioni `X-Frame-Options: DENY`, `nosniff` e `COOP` sono sempre attive.
