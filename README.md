# Hyperwave

[![CI](https://github.com/TumasDevelopment/Hyperwave/actions/workflows/ci.yml/badge.svg)](https://github.com/TumasDevelopment/Hyperwave/actions/workflows/ci.yml)

Hyperwave monitora la rete aziendale: mostra chi parla con chi, quanto, con quale protocollo, e cosa c'è di strano.

Il sistema ha tre parti:

- **Sensore.** Osserva una copia del traffico (porta SPAN o TAP) e ne ricava flussi, DNS, TLS e HTTP. Il contenuto dei pacchetti non viene salvato, salvo il buffer facoltativo per le estrazioni su richiesta.
- **Hub.** Riceve i dati e li arricchisce con paese, operatore, produttore della scheda di rete e applicazione. Tiene l'inventario dei dispositivi e fa girare il motore di rilevamento.
- **Interfaccia web.** Mostra tutto in tempo reale e permette di gestire allarmi, dispositivi, regole e utenti.

## Cosa fa

- **Panoramica live.** Banda in entrata, in uscita e interna ogni 5 secondi, i flussi che scorrono e gli allarmi appena aperti.
- **Traffico.** Andamento nel tempo; applicazioni, paesi, host e destinazioni più attivi; porte.
- **Flussi.** Ricerca per indirizzo, porta, protocollo, applicazione, dominio, paese e direzione, con export CSV.
- **Dispositivi.** Inventario automatico ricavato da ARP, DHCP, mDNS e traffico. Per ogni dispositivo:
  - dati rilevati: MAC, produttore, nome, sistema operativo, tipo, VLAN, servizi in ascolto;
  - dati che aggiungete voi: proprietario, posizione, criticità, etichette, approvazione.
- **Allarmi.** 21 regole, con i riferimenti MITRE ATT&CK dove esistono. Per ogni allarme:
  - gestione: gravità, stato, esito, assegnazione, note;
  - contesto: cronologia, flussi correlati, eccezioni.
- **Analisi.**
  - DNS: domini nuovi, risposte inesistenti.
  - TLS: versioni obsolete, certificati in scadenza o autofirmati, impronte JA4 rare.
  - HTTP in chiaro.
  - Eventi IDS da Suricata.
- **Pacchetti su richiesta.** Con il buffer facoltativo del sensore, l'estratto di un allarme, di un dispositivo o di un flusso si scarica in pcap per Wireshark. Solo per i ruoli autorizzati, con motivo e registro.
- **Rapporti PDF.** Per la direzione, tecnico e per la conformità NIS2 / ISO 27001, su richiesta o ogni settimana.
- **Amministrazione.** Sensori con token, utenti con ruoli e due fattori, token per l'API, impostazioni di rete, registro delle attività.
- **API REST v1** con token Bearer, per collegare SIEM, ticketing e automazioni.

### Regole di rilevamento

| Categoria | Regole |
|---|---|
| Ricognizione | scansione di porte, ricerca di host attivi |
| Accesso | tentativi di accesso ripetuti (SSH, RDP, SMB, database…) |
| Movimento laterale | un host interno che apre servizi amministrativi su molti altri |
| Comando e controllo | beacon periodici, domini generati da algoritmo, Tor, software di controllo remoto, paesi mai contattati |
| Esfiltrazione | invio anomalo verso internet, tunnel DNS, volume fuori dalla norma appresa |
| Elusione | DNS esterno al posto di quello aziendale |
| Configurazione | protocolli in chiaro, TLS obsoleto, certificati non validi |
| Inventario | nuovo dispositivo, nuovo servizio, servizio raggiungibile da internet |
| IDS | firme Suricata, se Suricata è installato sul sensore |
| Sistema | sensore che smette di inviare |

Dalla pagina **Regole** ogni regola si accende, si spegne e si regola (soglie, finestre di tempo). Le eccezioni escludono coppie origine/destinazione note e possono avere una scadenza.

## Architettura

```
 porta SPAN / TAP                                     browser
       │                                                 │ HTTPS (proxy)
 ┌─────▼──────┐  HTTPS, gzip, token   ┌──────────┐   ┌───▼──────────┐
 │ hw-sensor  ├──────────────────────►│  hw-hub  │   │  web (Next)  │
 │ Go         │   lotti ogni 5 s      │  Go      │   │  pagine, API │
 └────────────┘                       └┬───┬───┬─┘   └──┬───┬───┬───┘
                                       │   │   │        │   │   │
                                       │   │   └─NATS───┘   │   │   eventi live
                                       │   └──────PG────────┘   │   inventario, allarmi, utenti
                                       └──────────CH────────────┘   flussi e metadati
```

- **ClickHouse** contiene flussi e metadati (milioni di righe al giorno), con aggregati al minuto e all'ora e cancellazione automatica dei dati vecchi.
- **PostgreSQL** contiene dispositivi, allarmi, regole, utenti, sessioni e il registro delle attività.
- **NATS** fa da bus locale per gli eventi in tempo reale. Non conserva dati.

Hub e interfaccia possono girare in più copie dietro un bilanciatore, con PostgreSQL e ClickHouse replicati. Un backup notturno verificato è attivo dall'installazione.

I dettagli sono in [docs/architettura.md](docs/architettura.md) e [docs/alta-disponibilita.md](docs/alta-disponibilita.md).

## Installazione

Serve un server Debian o Ubuntu con PostgreSQL, ClickHouse e nats-server già installati da pacchetto, più Go e Node.js per compilare.

```bash
git clone https://github.com/TumasDevelopment/Hyperwave.git hyperwave && cd hyperwave
deploy/build.sh                                     # compila hub, sensore e interfaccia
sudo deploy/setup.sh                                # database, .env con i segreti, servizi systemd
cd web && npm run utente -- aggiungi admin --admin  # password temporanea in un file con permessi 600
```

Per provarlo senza una porta SPAN, usate `sudo HW_DEMO=1 deploy/setup.sh`. Avvia un sensore che genera il traffico realistico di un'azienda di prova, con attacchi simulati.

La guida completa, con proxy HTTPS, sensori remoti e aggiornamenti, è in [docs/installazione.md](docs/installazione.md).

## Documentazione

- [Installazione](docs/installazione.md)
- [Architettura](docs/architettura.md)
- [Alta disponibilità e backup](docs/alta-disponibilita.md)
- [API v1](docs/api.md)
- [Roadmap](docs/ROADMAP.md)
- [Variabili di configurazione](.env.example)

## Sicurezza

- **Esposizione di rete.** Tutti i servizi ascoltano solo su 127.0.0.1. Dall'esterno si arriva attraverso un proxy HTTPS.
- **Accesso.**
  - Password protette con scrypt.
  - Sessioni con scadenza e chiusura per inattività.
  - Due fattori TOTP con codici di recupero; il segreto è cifrato nel database (AES-256-GCM, chiave in `.env`).
  - Blocco dopo troppi tentativi falliti, condiviso tra le istanze e mantenuto ai riavvii.
- **Token.** I token dei sensori e dell'API sono salvati solo come hash e vengono mostrati una volta sola.
- **Coda del sensore.** I dati in attesa dell'hub sono cifrati su disco con una chiave derivata dal token del sensore.
- **Rilasci.** Firmati con Sigstore, con attestazione di provenienza e SBOM. Ogni modifica passa da test, analisi statica e controllo delle vulnerabilità note.
- **Segnalazioni.** Vedi [SECURITY.md](SECURITY.md).
- **ClickHouse.** L'interfaccia lo usa in sola lettura (readonly=2) e con query sempre parametrizzate.
- **Registro.** Ogni modifica finisce nel registro delle attività, che si può esportare.
- **Dati raccolti.** Il sensore salva solo intestazioni e metadati. Il buffer dei pacchetti completi è spento di default; se acceso, resta sulla macchina del sensore e ogni estrazione richiede un motivo e finisce nel registro.

## Licenza

[AGPL-3.0](LICENSE). Sviluppato da [Tumas Development](https://tumas.net).
