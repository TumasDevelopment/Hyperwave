# Installazione

Questa guida porta da un server vuoto a Hyperwave funzionante, con interfaccia in HTTPS e uno o più sensori.

## 1. Requisiti

**Server dell'hub** (hub, interfaccia e basi di dati sulla stessa macchina):

| Rete osservata | CPU | RAM | Disco (30 giorni di flussi) |
|---|---|---|---|
| fino a 200 dispositivi, 200 Mbit/s | 2 core | 4 GB | 50 GB SSD |
| fino a 1000 dispositivi, 1 Gbit/s | 4 core | 8 GB | 200 GB SSD |
| oltre | 8+ core | 16+ GB | da stimare dopo una settimana di dati (pagina Impostazioni → Spazio) |

Sistema operativo: Debian 12 o 13, Ubuntu 22.04 o 24.04.

**Sensore**: una macchina Linux collegata a una porta SPAN (mirror dello switch) o a un TAP. Per una rete da 1 Gbit/s bastano 2 core e 1 GB di RAM. La seconda scheda di rete, quella che riceve la copia del traffico, non deve avere un indirizzo IP. Per una rete piccola il sensore può girare sullo stesso server dell'hub.

## 2. Pacchetti

Installate i pacchetti seguendo le guide ufficiali:

- **PostgreSQL** 15 o successivo: `apt install postgresql`
- **ClickHouse** 24 o successivo: repository ufficiale, pacchetti `clickhouse-server` e `clickhouse-client`
- **NATS**: `apt install nats-server`
- **Strumenti**: `apt install openssl curl ieee-data`
  - `ieee-data` fornisce i nomi dei produttori delle schede di rete.

Per compilare servono anche:

- **Go** 1.26 o successivo (go.dev/dl); se la versione patch è più vecchia di quella indicata in `core/go.mod` (`toolchain`), il comando `go` scarica da solo quella giusta;
- **Node.js** 20 o successivo (nodesource o nvm).

Facoltativo: i database **GeoLite2 City e ASN** di MaxMind, gratuiti con registrazione. Servono per il paese e l'operatore degli indirizzi esterni. Indicate il loro percorso in `HW_GEOIP_CITY` e `HW_GEOIP_ASN`.

## 3. Compilazione e configurazione

Come utente normale, non root:

```bash
git clone https://github.com/TumasDevelopment/Hyperwave.git ~/hyperwave
cd ~/hyperwave
deploy/build.sh
```

`build.sh` compila `core/bin/hw-hub` e `core/bin/hw-sensor`, esegue i test e compila l'interfaccia in `web/.next`.

Poi lanciate `sudo deploy/setup.sh`. Lo script:

- crea `.env` con password casuali (permessi 600);
- crea ruolo e database PostgreSQL;
- configura l'utente e i limiti di memoria di ClickHouse;
- configura NATS con un token;
- installa e avvia le unità systemd.

Si può rilanciare senza perdere nulla: i segreti già presenti in `.env` vengono riusati.

Varianti:

```bash
sudo HW_PROCESS=pm2 deploy/setup.sh   # i processi li gestisce PM2 (pm2 start ecosystem.config.cjs)
sudo HW_DEMO=1 deploy/setup.sh        # avvia anche il sensore con dati dimostrativi
sudo CH_RAM_RATIO=0.3 deploy/setup.sh # quota di RAM per ClickHouse (predefinita 0.2)
```

Al primo avvio l'hub crea le tabelle in PostgreSQL e ClickHouse. Controllate che risponda:

```bash
curl -s http://127.0.0.1:3121/healthz
```

## 4. Primo amministratore

```bash
cd ~/hyperwave/web
npm run utente -- aggiungi admin --admin
```

La password temporanea non viene stampata: finisce in `password-admin.txt`, leggibile solo dal vostro utente. Al primo accesso il sito chiede di cambiarla. Dopo il primo accesso cancellate il file e attivate i due fattori da **Account**.

Altri comandi utili:

```bash
npm run utente -- elenco
npm run utente -- reimposta <nome>   # nuova password temporanea, chiude le sessioni
npm run utente -- togli-2fa <nome>   # telefono perso
npm run utente -- sblocca <nome>     # riattiva un utente disattivato
```

Gli altri utenti si creano dall'interfaccia, in **Impostazioni → Utenti**. I ruoli sono tre:

- **Lettore**: vede tutto, non modifica nulla.
- **Analista**: gestisce allarmi, dispositivi ed eccezioni.
- **Amministratore**: in più gestisce regole, sensori, utenti, token e impostazioni.

## 5. HTTPS con nginx

Interfaccia e hub ascoltano solo su 127.0.0.1. Esempio di configurazione con certificato Let's Encrypt:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name hyperwave.esempio.it;

    ssl_certificate     /etc/letsencrypt/live/hyperwave.esempio.it/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hyperwave.esempio.it/privkey.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 1m;

    # Panoramica in tempo reale (Server-Sent Events): niente buffer, connessione lunga
    location = /api/live {
        proxy_pass http://127.0.0.1:3120;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }

    location / {
        proxy_pass http://127.0.0.1:3120;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Due accorgimenti:

- **`X-Real-IP`** serve al blocco dei tentativi e al registro delle attività.
- **Accesso da internet.** Se l'interfaccia è raggiungibile da internet, limitate gli indirizzi ammessi (`allow` / `deny`) o mettetela dietro una VPN.

## 6. Sensori

### Sensore sulla stessa macchina

```bash
cd ~/hyperwave
core/bin/hw-hub sensor-add -name "Sede centrale" -site "Milano" -env-file .env
```

Il token viene scritto in `.env` come `HW_SENSOR_TOKEN`, senza essere stampato. Poi:

1. impostate `HW_IFACE` con l'interfaccia che riceve la copia del traffico;
2. avviate l'unità `hyperwave-sensor`, oppure lanciate `hw-sensor -mode capture`.

### Sensore remoto

I sensori remoti parlano con l'hub in HTTPS. Pubblicate l'hub con nginx su una porta dedicata e accessibile solo dalle reti dei sensori:

```nginx
server {
    listen 8443 ssl;
    server_name hub.esempio.it;
    ssl_certificate     /etc/ssl/hyperwave/hub.crt;
    ssl_certificate_key /etc/ssl/hyperwave/hub.key;
    allow 10.20.0.0/16;     # reti dei sensori
    deny all;
    client_max_body_size 64m;
    location /v1/ { proxy_pass http://127.0.0.1:3121; }
}
```

Sulla macchina del sensore il modo più semplice è il pacchetto del rilascio (Debian/Ubuntu, oppure `.rpm` per RHEL e derivate):

```bash
sudo apt install ./hyperwave-sensor_<versione>_amd64.deb   # oppure: sudo dnf install ./hyperwave-sensor-<versione>-1.x86_64.rpm
sudo nano /etc/hyperwave/sensor.env                         # hub, token, interfaccia
sudo systemctl enable --now hyperwave-sensor
```

Il pacchetto installa `/usr/bin/hw-sensor`, l'unità systemd e `/etc/hyperwave/sensor.env` (permessi 600, non viene sovrascritto dagli aggiornamenti). Aggiornando il pacchetto il sensore riparte da solo e la coda su disco resta.

In alternativa, a mano:

1. Copiate il binario: `install -m 755 hw-sensor /usr/local/bin/`.
2. Create il token dalla pagina **Sensori** e salvatelo in `/etc/hyperwave/sensor.env` (permessi 600):

   ```
   HW_HUB_URL=https://hub.esempio.it:8443
   HW_SENSOR_TOKEN=hws_...
   HW_SENSOR_IFACE=eth1
   # HW_HUB_CA=/etc/hyperwave/ca.crt       se il certificato è firmato da una CA interna
   # HW_CAPTURE_IGNORE=10.20.5.10/32       l'indirizzo dell'hub, per non registrare il proprio traffico
   ```

3. Copiate `deploy/systemd/hyperwave-sensor.service` in `/etc/systemd/system/` e avviatelo con `systemctl enable --now hyperwave-sensor`.

L'unità gira senza privilegi di root: ha solo `CAP_NET_RAW` e `CAP_NET_ADMIN`.

Se l'hub non risponde, il sensore salva i lotti in una coda cifrata su disco (`/var/lib/hyperwave-sensor/coda`, al massimo `HW_SPOOL_MAX_MB` MB, predefinito 2048) e li invia quando la connessione torna, anche dopo un riavvio. La pagina **Sensori** mostra i record e i byte in coda e quelli scartati per mancanza di spazio: dopo una prima interruzione si vede quanto spazio serve al vostro traffico.

### Suricata (facoltativo)

Se Suricata gira sulla stessa macchina del sensore, indicate il suo `eve.json` in `HW_SURICATA_EVE`. Le firme diventano allarmi della regola **Firma IDS** e compaiono in **Analisi → IDS**.

### Analisi di un file pcap

```bash
hw-sensor -mode pcap -file cattura.pcapng
```

I flussi entrano con la loro data originale. Il motore di rilevamento li analizza come dati storici, quindi gli allarmi su dispositivi e servizi nuovi non partono.

## 7. Aggiornamento

```bash
cd ~/hyperwave
git pull
deploy/build.sh
sudo systemctl restart hyperwave-hub hyperwave-web   # oppure: pm2 restart hyperwave-hub hyperwave-web
```

Le migrazioni dei database si applicano da sole all'avvio dell'hub. I sensori remoti vanno aggiornati con il nuovo binario o pacchetto. Il formato dei dati resta compatibile all'interno della stessa versione principale.

Aggiornando da una versione senza cifratura dei segreti 2FA, rilanciate `sudo deploy/setup.sh`: aggiunge `HW_SECRET_KEY` a `.env` senza toccare il resto. Poi, dopo il riavvio:

```bash
cd web && npm run utente -- cifra-segreti
```

I segreti ancora in chiaro funzionano comunque e vengono cifrati al primo accesso di ciascun utente; il comando lo fa subito per tutti. **Impostazioni → Stato dei componenti → Segreti 2FA** mostra se ne resta qualcuno in chiaro.

### Rotazione della chiave dei segreti

1. In `.env` spostate la chiave attuale in `HW_SECRET_KEY_OLD` e mettete in `HW_SECRET_KEY` quella nuova (`openssl rand -hex 32`).
2. Riavviate l'interfaccia web.
3. `cd web && npm run utente -- cifra-segreti`: ricifra tutto con la chiave nuova.
4. Togliete `HW_SECRET_KEY_OLD` e riavviate di nuovo.

Una chiave persa non si recupera: gli utenti interessati vanno sbloccati con `npm run utente -- togli-2fa <nome>` e riattivano i due fattori da **Account**.

### Verificare un rilascio

Ogni rilascio su GitHub contiene `SHA256SUMS`, la sua firma Sigstore (`SHA256SUMS.sigstore.json`, creata dal workflow senza chiavi private) e l'SBOM in formato SPDX. Prima di installare:

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/TumasDevelopment/Hyperwave/\.github/workflows/release\.yml@refs/tags/v'
sha256sum -c SHA256SUMS --ignore-missing
# in alternativa, con la CLI di GitHub:
gh attestation verify hyperwave-sensor_<versione>_amd64.deb -R TumasDevelopment/Hyperwave
```

L'archivio `hyperwave-<versione>-linux-<arch>-completo.tar.gz` contiene i sorgenti e i binari già compilati: sul server dell'hub basta Node.js, `deploy/build.sh` usa i binari presenti se Go non è installato.

## 8. Backup

| Cosa | Come | Note |
|---|---|---|
| `.env` | copia del file | contiene i segreti, compresa `HW_SECRET_KEY`: senza, il backup di PostgreSQL non basta per i due fattori. Conservatelo cifrato e separato dal dump |
| PostgreSQL | `pg_dump -Fc hyperwave > hyperwave.dump` | inventario, allarmi, regole, utenti: è la parte preziosa |
| ClickHouse | `BACKUP DATABASE hyperwave TO Disk('backups', 'hw.zip')` | flussi: grandi, spesso basta conservarne gli ultimi giorni |

## 9. Risoluzione dei problemi

| Sintomo | Controllo |
|---|---|
| L'interfaccia mostra «Impossibile leggere…» | `curl -s http://127.0.0.1:3121/healthz`: postgres, clickhouse e nats devono essere `true` |
| Sensore «Mai collegato» | log del sensore: token errato (401), hub non raggiungibile, certificato non riconosciuto (`HW_HUB_CA`) |
| Nessun traffico ma sensore in linea | la porta SPAN copia davvero il traffico? `tcpdump -ni eth1 -c 20` sulla macchina del sensore |
| Direzioni sbagliate (tutto «Esterno») | reti interne in **Impostazioni → Rete** |
| «Perdite del kernel» in Sensori | CPU del sensore insufficiente o picchi: aumentate le risorse o filtrate le reti con `HW_CAPTURE_IGNORE` |
| Accesso bloccato | dopo 5 tentativi errati si attendono 15 minuti; `npm run utente -- reimposta <nome>` |
