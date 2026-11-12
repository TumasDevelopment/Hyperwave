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

Tutti i componenti leggono lo stesso file `.env`. Hub e interfaccia possono girare in più copie sulle stesse basi di dati: vedi [alta-disponibilita.md](alta-disponibilita.md).

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
- **Coda di invio.** I dati partono a lotti ogni 5 secondi. Se l'hub non risponde, in modalità cattura ogni lotto finisce in una coda su disco:
  - un file per lotto, JSON compresso e cifrato con AES-256-GCM; la chiave deriva dal token del sensore (HKDF-SHA256), quindi chi copia la cartella senza il token non legge il traffico;
  - scrittura atomica (file temporaneo, fsync, rename), cartella con permessi 700 (`/var/lib/hyperwave-sensor/coda` con systemd, altrimenti `HW_SPOOL_DIR`);
  - limite di spazio `HW_SPOOL_MAX_MB` (2048): oltre si scartano i lotti più vecchi e si contano in `spool_dropped`;
  - al ritorno dell'hub parte prima il lotto nuovo, poi la coda dal più vecchio, per al massimo 3 secondi a ogni giro, così i dati recenti non restano indietro;
  - tra un tentativo e l'altro l'attesa cresce da 2 secondi a 1 minuto, e intanto i lotti vanno direttamente su disco;
  - l'ultimo stato ricevuto dall'hub (live, reti interne) è salvato: se all'avvio l'hub non risponde, la cattura parte comunque.

  Rinnovando il token, i lotti scritti con quello vecchio non si possono più leggere e vengono scartati. Senza coda su disco (`HW_SPOOL_DIR=off`, nessuna cartella di stato, modalità pcap e demo) i dati restano in memoria fino a `HW_MAX_PENDING` record.
- **Contenuto dei pacchetti.** Di default non viene salvato. Con `HW_PCAP_DIR` il sensore in modalità cattura tiene un buffer circolare su disco (file pcap da 64 MB o 5 minuti, al massimo `HW_PCAP_RING_MB` MB e `HW_PCAP_RING_MINUTES` minuti) da cui estrae i pacchetti richiesti dall'interfaccia (sezione 7). Il buffer resta sulla macchina del sensore: all'hub arriva solo l'estratto chiesto.

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
- **Un solo motore.** Con più istanze dell'hub, motore, correlazione degli incidenti, controllo dei sensori, elenchi di minaccia e pulizie girano solo sull'istanza che tiene il lock consultivo `HWLEAD` di PostgreSQL. Il cursore, le finestre da rianalizzare (`settings.engine_late`) e lo storico ancora in arrivo dai sensori (`backfill_marks`) sono in PostgreSQL: un nuovo capo riprende dal punto esatto. `HW_HUB_LEADER=never` esclude un'istanza dall'elezione.
- **Apprendimento.** Le regole basate sulla norma (volume anomalo, paese raro, nuovo dispositivo) aspettano `HW_LEARNING_HOURS` ore dal primo dato. I dati storici (pcap, recupero dopo un'interruzione) non generano allarmi su dispositivi e servizi nuovi.

### 5. Live

Ogni 5 secondi l'hub pubblica su NATS:

| Soggetto | Contenuto |
|---|---|
| `hw.live.state` | banda in entrata/uscita/interna, pacchetti, flussi, sensori attivi, perdite |
| `hw.live.flows` | gli ultimi flussi significativi, già arricchiti |
| `hw.live.rate` | banda e perdite del singolo sensore, a ogni lotto |
| `hw.live.event` | allarme aperto, aggiornato o chiuso; evento IDS |

Con più istanze dell'hub la panoramica la pubblica il capo; le altre gli inoltrano la banda dei sensori che ricevono su `hw.internal.rates`.

L'interfaccia si iscrive a `hw.live.>` e inoltra gli eventi al browser con Server-Sent Events (`/api/live`). La connessione resta aperta, con un segnale di attività ogni 20 secondi.

I comandi viaggiano nel verso opposto, su `hw.control.>`:

- `sensors`: svuota la cache dei token;
- `rules`: ricarica regole ed eccezioni;
- `settings`: ricarica il live e le reti.

L'interfaccia li invia subito dopo ogni modifica, così le impostazioni hanno effetto senza riavvii.

### 6. Interruttore «live»

Con il live spento (Impostazioni, oppure `PUT /api/v1/live`) l'hub scarta i dati dei sensori senza registrarli e il motore si ferma. Si usa durante una manutenzione, o quando non si vuole raccogliere dati. Lo stato e chi l'ha cambiato finiscono nel registro.

### 7. Pacchetti su richiesta

```
interfaccia ─► pcap_requests (PG) ─► hub: risposta all'heartbeat ─► sensore: ricerca nel buffer
                                                                         │
interfaccia ◄─ pcap_chunks (PG, pezzi da 1 MB) ◄─ POST /v1/pcap/{id}/result ◄┘   (oppure /fail)
```

- **Richiesta.** Un utente con il ruolo scelto in Impostazioni (`pcap_role`, amministratori di default) indica sensore, indirizzo, eventuale secondo indirizzo, porta e protocollo, un periodo di al massimo 6 ore e un motivo. La richiesta finisce nel registro.
- **Consegna.** Il sensore manda un heartbeat ogni 10 secondi. L'hub risponde con al massimo 4 richieste in attesa (`pcap_jobs`) e le segna in corso con `FOR UPDATE SKIP LOCKED`, quindi con più hub una richiesta va a un solo sensore una volta sola.
- **Risultato.** Il sensore filtra i file del buffer e invia il pcap compresso con gzip a `POST /v1/pcap/{id}/result`, con le intestazioni `X-HW-SHA256` (del pcap non compresso), `X-HW-Packets` e `X-HW-Truncated` (1 se il limite `HW_PCAP_EXPORT_MB` ha tagliato l'estratto). L'hub decomprime mentre riceve per verificare il file e calcolarne lo SHA-256. Se non coincide con quello dichiarato, risponde 400 e non salva nulla. Se il sensore non trova il buffer o fallisce la ricerca, chiama `POST /v1/pcap/{id}/fail` con `{"error": "motivo"}`.
- **Scadenze.** Una richiesta mai presa da un sensore scade dopo un'ora; una rimasta in corso dopo 20 minuti. I file si cancellano dopo `HW_PCAP_KEEP_DAYS` giorni.
- **Download.** `/api/pacchetti/{id}` ricompone i pezzi e registra il download nel registro delle attività.

### 8. Rapporti PDF

L'interfaccia prepara tre rapporti: direzione, tecnico e conformità. Quello di conformità collega i dati a NIS2 art. 21 e ISO/IEC 27001:2022 allegato A, ed è visibile solo agli amministratori.

- **Pianificazione.** Ogni lunedì, mezz'ora dopo la mezzanotte (`HW_TZ`), vengono creati i rapporti scelti in **Rapporti** per la settimana appena finita. Un indice unico su `(kind, period_from)` dei rapporti pianificati impedisce i doppioni anche con più istanze.
- **Preparazione.** Ogni istanza dell'interfaccia controlla ogni 30 secondi i rapporti in attesa e ne prende uno con `FOR UPDATE SKIP LOCKED`. Legge i dati da PostgreSQL e ClickHouse e scrive il PDF (pdfkit, font Geist) nella tabella `reports`, con numero di pagine e SHA-256. Un rapporto fermo da oltre 15 minuti viene segnato come fallito. `HW_REPORTS=off` spegne la preparazione su un'istanza.
- **Conservazione.** 400 giorni. Nessun invio: i rapporti si scaricano dalla pagina, e ogni download finisce nel registro.

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
| `login_failures` | tentativi di accesso falliti per indirizzo e per utente, con la scadenza del blocco |
| `api_tokens` | token dell'API (solo hash) |
| `audit_log` | registro delle attività |
| `settings` | live, reti, cursore del motore, stato dei servizi collegati |
| `backfill_marks` | storico che i sensori stanno ancora inviando, per il motore |
| `pcap_requests`, `pcap_chunks` | estrazioni di pacchetti e relativi file a pezzi |
| `reports` | rapporti PDF, compreso il file |

Ogni ora l'hub cancella:

- sessioni scadute;
- allarmi chiusi da più di `HW_ALERT_RETENTION_DAYS` giorni;
- voci del registro più vecchie di `HW_AUDIT_RETENTION_DAYS` giorni;
- servizi non più visti;
- tentativi di accesso falliti scaduti.

Le migrazioni stanno in `core/internal/store/{pg,ch}`. Sono incluse nel binario e l'hub le applica all'avvio.

## Sicurezza

**Rete**

- Ogni servizio ascolta solo su loopback.
- ClickHouse accetta l'utente `hyperwave` solo da 127.0.0.1.
- NATS richiede un token.

**Accesso degli utenti**

- **Password.** Protette con scrypt (N=32768); lunghezza minima 12 caratteri; il nome utente non può comparire nella password.
- **Sessioni.** Token casuale da 32 byte in un cookie `HttpOnly`, `Secure`, `SameSite=Lax`; nel database c'è solo l'hash. Durata massima 12 ore, chiusura dopo 60 minuti di inattività. Il cambio password chiude tutte le altre sessioni.
- **Due fattori.** TOTP a 30 secondi. Lo stesso codice non vale due volte (`totp_last_step`). I 10 codici di recupero sono salvati come hash e valgono una volta sola.
- **Segreti 2FA cifrati.** Il segreto TOTP è cifrato nel database con AES-256-GCM e la chiave `HW_SECRET_KEY` di `.env`. Ogni valore è legato al suo utente: copiato su un altro utente non si decifra. Una copia del database senza `.env` non basta per generare i codici. Formato `enc:v1:<id chiave>:<dati>`; per la rotazione della chiave vedi docs/installazione.md.
- **Tentativi.** Dopo 5 tentativi falliti per utente e indirizzo, oppure 20 per indirizzo, l'accesso si blocca per 15 minuti. I conteggi stanno in PostgreSQL (`login_failures`): valgono per tutte le istanze dell'interfaccia e restano dopo un riavvio. Per non rivelare quali utenti esistono, il tempo di risposta è lo stesso anche per utenti inesistenti. `npm run utente -- sblocca <nome>` toglie il blocco.

**Permessi e dati**

- **Ruoli.** Controllati sul server in ogni azione e in ogni rotta dell'API, non solo nascondendo i pulsanti.
- **Query.** Quelle verso ClickHouse sono parametrizzate e girano con `readonly=2`; quelle verso PostgreSQL sono parametrizzate.
- **Export CSV.** Le celle che iniziano con `=`, `+`, `-` o `@` vengono neutralizzate, per evitare formule nei fogli di calcolo.

**Pagine**

- Ogni pagina ha una Content Security Policy con nonce per richiesta.
- Le intestazioni `X-Frame-Options: DENY`, `nosniff` e `COOP` sono sempre attive.
