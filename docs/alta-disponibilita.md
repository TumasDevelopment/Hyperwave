# Alta disponibilità e backup

L'installazione standard mette tutto su una macchina, e per molte reti basta: se il server si ferma i sensori tengono i dati nella coda su disco e li inviano al ritorno. Questa guida serve quando Hyperwave non deve fermarsi nemmeno per un guasto o per un aggiornamento, e quando i dati devono sopravvivere alla perdita di un server.

## Cosa può avere più copie

| Componente | Più istanze | Come si coordinano |
|---|---|---|
| `hw-hub` | sì, dietro un bilanciatore | tutte ricevono dai sensori; il motore gira su una sola, scelta con un lock di PostgreSQL |
| `web` | sì, dietro un bilanciatore | sessioni e stato in PostgreSQL; i rapporti PDF li prepara una sola istanza per volta |
| NATS | cluster di 3 nodi | trasporta solo eventi live e comandi: se si ferma i dati continuano ad arrivare, si fermano solo gli aggiornamenti in tempo reale |
| PostgreSQL | primario e repliche, con Patroni | l'applicazione vede un solo indirizzo (HAProxy o IP virtuale) |
| ClickHouse | repliche, con ClickHouse Keeper | database `Replicated`: tabelle e dati arrivano su tutti i nodi |

Tutte le istanze di hub e sito devono leggere lo **stesso `.env`**, in particolare `HW_SECRET_KEY`, i token di NATS e le password dei database. Con chiavi diverse un'istanza non riesce a leggere i segreti dei due fattori scritti da un'altra.

## Hub

```
             sensori
                │ HTTPS
        ┌───────▼────────┐
        │  bilanciatore  │  controllo: GET /healthz (200 = PostgreSQL e ClickHouse raggiungibili)
        └──┬──────────┬──┘
     ┌─────▼───┐  ┌───▼─────┐
     │ hw-hub  │  │ hw-hub  │   ricezione e arricchimento su entrambi
     │ (capo)  │  │         │   motore, correlazione, pulizie solo sul capo
     └─────────┘  └─────────┘
```

- **Ricezione.** Non ha stato: ogni istanza accetta i lotti di qualsiasi sensore. Il bilanciatore può distribuirli a turno, senza sessioni persistenti.
- **Capo.** Motore delle regole, correlazione degli incidenti, controllo dei sensori, elenchi di minaccia, scadenza delle estrazioni di pacchetti e pulizie orarie girano su una sola istanza: quella che tiene il lock consultivo `HWLEAD` di PostgreSQL. Il lock vive su una connessione dedicata. Se l'istanza si ferma, o perde il collegamento con PostgreSQL, il server lo libera e un'altra istanza lo prende entro pochi secondi (circa 2 nelle prove). Lo stato del motore (cursore, finestre da rianalizzare) è in PostgreSQL, quindi il nuovo capo riprende da dove era arrivato il precedente.
- **Banda in tempo reale.** Le istanze che non sono capo inoltrano la banda dei sensori che ricevono sul soggetto NATS `hw.internal.rates`. Il capo la somma e pubblica la panoramica.
- **Sola ricezione.** Con `HW_HUB_LEADER=never` un'istanza non diventa mai capo. Serve, per esempio, per un hub vicino a una sede remota che deve solo raccogliere.
- **Controllo.** `GET /healthz` restituisce `"leader": true` sull'istanza capo e `"leader_mode"`. Il codice di risposta è 503 se PostgreSQL o ClickHouse non rispondono: il bilanciatore toglie l'istanza dal giro.
- **Estrazioni di pacchetti.** Le richieste e i file stanno in PostgreSQL. Il sensore può consegnare il risultato a qualsiasi istanza.

Esempio con nginx davanti a due hub (la parte TLS è come in [installazione.md](installazione.md#sensore-remoto)):

```nginx
upstream hyperwave_hub {
    server 10.0.0.11:3121 max_fails=2 fail_timeout=10s;
    server 10.0.0.12:3121 max_fails=2 fail_timeout=10s;
}
server {
    listen 8443 ssl;
    # ... certificati e allow/deny come nell'installazione standard ...
    client_max_body_size 64m;
    location /v1/ { proxy_pass http://hyperwave_hub; }
    location /v1/pcap/ {
        proxy_pass http://hyperwave_hub;
        client_max_body_size 200m;          # HW_PCAP_MAX_MB
        proxy_request_buffering off;
        proxy_read_timeout 15m;
    }
}
```

Se un hub non risponde, nginx passa la richiesta all'altro. Se risponde 503 (database irraggiungibile), il sensore conserva il lotto e riprova. In questo caso `HW_HUB_LISTEN` deve ascoltare sull'interfaccia raggiungibile dal bilanciatore (per esempio `10.0.0.11:3121`), protetta da firewall: solo il bilanciatore deve poterla raggiungere.

## Sito

- **Senza stato.** Sessioni, tentativi di accesso falliti, impostazioni e rapporti stanno in PostgreSQL. Il bilanciatore può mandare ogni richiesta a un'istanza diversa.
- **Live.** Ogni istanza si iscrive a NATS per conto suo. Nel bilanciatore, `/api/live` va servito senza buffer (`proxy_buffering off`), come nella configurazione standard.
- **Indirizzo del browser.** Il blocco dei tentativi e il registro usano `X-Real-IP`. Il bilanciatore deve impostarlo con l'indirizzo vero del browser, e le istanze del sito non devono essere raggiungibili direttamente.
- **Rapporti PDF.** Ogni istanza controlla ogni 30 secondi se ci sono rapporti da preparare. Prende il lavoro con `FOR UPDATE SKIP LOCKED`, quindi due istanze non preparano mai lo stesso rapporto. Un indice unico evita che il rapporto settimanale venga creato due volte. Con `HW_REPORTS=off` un'istanza non ne prepara.
- **Build.** `HW_TZ` entra nella build: compilate una volta e copiate la stessa cartella `web/.next` su tutte le istanze.
- **Controllo.** `GET /api/salute` restituisce 200 se PostgreSQL e ClickHouse rispondono, 503 altrimenti.

## NATS

Un cluster di tre nodi resiste alla perdita di uno. Nella configurazione di ogni nodo:

```
cluster {
  name: hyperwave
  listen: 0.0.0.0:6222
  routes: [nats://10.0.0.21:6222, nats://10.0.0.22:6222, nats://10.0.0.23:6222]
}
```

In `.env` elencate tutti i nodi: `NATS_URL=nats://10.0.0.21:4222,nats://10.0.0.22:4222,nats://10.0.0.23:4222`. Hub e sito si spostano da soli su un nodo attivo. Proteggete le porte 4222 e 6222 con un firewall: il token di NATS autentica i client, non cifra il traffico.

## PostgreSQL

Contiene la parte preziosa: inventario, allarmi, regole, utenti, registro. La soluzione consigliata è **Patroni** (primario più almeno una replica in streaming, con etcd o Consul per l'elezione) e **HAProxy** davanti:

```
listen postgres_primario
    bind *:5000
    option httpchk GET /primary
    http-check expect status 200
    default-server inter 2s fall 2 rise 2 on-marked-down shutdown-sessions
    server pg1 10.0.0.31:5432 check port 8008
    server pg2 10.0.0.32:5432 check port 8008
```

`DATABASE_URL` punta ad HAProxy (`postgres://hyperwave:...@10.0.0.30:5000/hyperwave`). Quando il primario cambia, le connessioni si chiudono e si riaprono sul nuovo: anche il lock del capo si libera e l'hub ne elegge uno nuovo da solo. Le migrazioni vanno sempre sul primario, quindi non serve altro.

Le repliche non sostituiscono i backup: un `DELETE` sbagliato arriva subito anche lì.

## ClickHouse replicato

Hyperwave riconosce da solo un database ClickHouse con il motore `Replicated`. Se il database esiste già con quel motore al primo avvio dell'hub, le migrazioni creano tabelle `ReplicatedMergeTree` e `ReplicatedSummingMergeTree` al posto di quelle semplici. Le istruzioni (comprese le modifiche della conservazione) arrivano a tutti i nodi e i dati si replicano.

1. Configurate ClickHouse Keeper su tre nodi (può girare dentro gli stessi server ClickHouse) e la sezione `<zookeeper>` su ogni server.
2. Su ogni server definite le macro, uniche per nodo:

   ```xml
   <macros><shard>01</shard><replica>ch1</replica></macros>
   ```

3. Prima di avviare l'hub, create il database su ogni nodo con lo stesso percorso:

   ```sql
   CREATE DATABASE hyperwave ENGINE = Replicated('/clickhouse/databases/hyperwave', '{shard}', '{replica}');
   ```

4. Avviate l'hub: crea le tabelle su un nodo e il database le porta sugli altri.

Gli inserimenti possono andare su qualsiasi nodo. `CLICKHOUSE_URL` può puntare a un bilanciatore (HAProxy in modalità HTTP, controllo `GET /ping`) oppure, per ogni istanza di hub e sito, al nodo più vicino.

Un'installazione esistente con tabelle semplici non si converte da sola. Bisogna creare il nuovo database replicato, copiare i dati tabella per tabella con `INSERT INTO nuovo.tabella SELECT * FROM vecchio.tabella` e poi scambiare i nomi. Spesso conviene ripartire da vuoto e tenere il vecchio database finché i dati non scadono.

Oltre i 10 Gbit/s serve anche la suddivisione in shard (tabelle `Distributed`), che Hyperwave non gestisce ancora: è nella [roadmap](ROADMAP.md).

## Backup

`deploy/backup.sh` salva PostgreSQL e ClickHouse in una cartella con data e ora, controlla l'archivio e cancella i backup più vecchi della conservazione. `setup.sh` installa due timer systemd:

| Timer | Quando | Cosa fa |
|---|---|---|
| `hyperwave-backup.timer` | ogni notte alle 2:30 | backup, verifica rapida, conservazione |
| `hyperwave-backup-verifica.timer` | la domenica alle 5:00 | ripristino di prova dell'ultimo backup in database separati e confronto |

```bash
sudo deploy/backup.sh                          # backup immediato
sudo deploy/backup.sh verifica                 # ripristino di prova dell'ultimo backup
sudo deploy/backup.sh ripristina /var/backups/hyperwave/20261112-023000 --si
systemctl list-timers 'hyperwave-backup*'      # prossime esecuzioni
journalctl -u hyperwave-backup                 # esito delle ultime
```

**Cosa contiene ogni backup**

| File | Contenuto |
|---|---|
| `postgres.dump` | `pg_dump` in formato custom: inventario, allarmi, regole, utenti, registro, rapporti, file dei pacchetti estratti |
| `clickhouse.zip` | `BACKUP DATABASE` di ClickHouse: flussi, metadati e aggregati (assente con `HW_BACKUP_CLICKHOUSE=0`) |
| `info.txt` | data, versione, numero di tabelle e righe, usati dalla verifica |
| `SHA256SUMS` | somme di controllo di tutti i file |

**Verifiche**

- **Rapida, a ogni backup.** Somme SHA-256, indice dell'archivio PostgreSQL leggibile (`pg_restore --list`), archivio ClickHouse integro (`unzip -t`). Il backup prende il suo nome definitivo solo se passa.
- **Completa, ogni settimana.** L'ultimo backup viene ripristinato nei database `hw_backup_check` di PostgreSQL e ClickHouse, poi si confrontano tabelle e righe con quanto annotato in `info.txt`. Infine i database di prova vengono cancellati. È lo stesso codice usato dal ripristino vero: se la verifica passa, il ripristino funziona.

**Impostazioni** (in `.env`): `HW_BACKUP_DIR` (`/var/backups/hyperwave`), `HW_BACKUP_KEEP_DAYS` (14; l'ultimo backup riuscito non viene mai cancellato), `HW_BACKUP_CLICKHOUSE` (1). I flussi occupano molto: se lo spazio non basta, `HW_BACKUP_CLICKHOUSE=0` salva solo PostgreSQL.

**Copia fuori dal server.** Un backup sullo stesso disco non protegge da un guasto del disco né da un attacco al server. Copiate la cartella altrove ogni giorno, per esempio con `restic` o `rsync` verso un'altra macchina, oppure montate in `HW_BACKUP_DIR` un volume di rete. I backup contengono dati personali (indirizzi, nomi, traffico): cifrateli e limitate chi può leggerli. Sul server la cartella è leggibile solo da root.

**`.env` va salvato a parte.** Non è incluso perché contiene i segreti. Senza `HW_SECRET_KEY`, i due fattori degli utenti vanno riattivati dopo un ripristino. Conservatene una copia cifrata, per esempio in un gestore di password aziendale.

**Ripristino.** `ripristina` ferma hub e sito, se sono unità systemd attive (con PM2 fermateli prima a mano). Ripristina i flussi nel database di prova, poi PostgreSQL in una sola transazione, infine scambia il database di ClickHouse con quello ripristinato. Se un passo fallisce, i dati attuali restano dov'erano.

**Con più server.** Lo script lavora sulla macchina dove gira ClickHouse, perché ClickHouse scrive l'archivio sul proprio disco. Se ClickHouse sta su un'altra macchina, lanciate lo script lì, oppure usate `HW_BACKUP_CLICKHOUSE=0` e un backup di ClickHouse verso S3 (`BACKUP DATABASE hyperwave TO S3(...)`). Con le repliche basta il backup di un nodo.

ClickHouse deve avere il disco `backups` (in `deploy/clickhouse/hyperwave-config.xml`) e l'utente `hyperwave` il permesso di scriverci (`GRANT READ, WRITE ON DISK('backups')` in `hyperwave-users.xml.tmpl`). `setup.sh` li installa entrambi.
