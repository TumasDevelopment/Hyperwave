# Roadmap

Stato a novembre 2026. Il nucleo funziona ed è collaudato con il sensore dimostrativo:

- cattura e invio dei dati;
- arricchimento;
- inventario dei dispositivi;
- 21 regole di rilevamento;
- interfaccia completa;
- API v1.

Questo documento elenca le funzionalità che mancano per un uso aziendale serio, in ordine di priorità.

Legenda:

- **Sforzo**: S = giorni, M = 1-2 settimane, L = un mese o più.
- **Priorità**: P1 = prima di mettere in produzione presso un cliente; P2 = differenzianti; P3 = su richiesta.

## Limiti noti della versione attuale

| Limite | Effetto | Soluzione prevista |
|---|---|---|
| Nessuna notifica verso l'esterno | gli allarmi si vedono solo nell'interfaccia e via API | canali da scegliere (P1, vedi sotto) |
| I test coprono funzioni e moduli, non i percorsi completi | un errore nell'integrazione tra pagine, hub e basi di dati si scopre a mano | Playwright e test di integrazione in container (P1) |
| La pagina Flussi carica fino a 500 righe in una volta | pagine pesanti su connessioni lente | paginazione a cursore (P2) |
| L'API non ha limiti di frequenza né una specifica OpenAPI | un token può sovraccaricare ClickHouse | limiti per token e `openapi.yaml` (P1) |
| `anomaly_volume` richiede `HW_LEARNING_HOURS` di storico | sulle installazioni nuove non scatta per il primo giorno | comportamento voluto, da indicare nell'interfaccia |

## P1 — Necessarie per la produzione

### Notifiche e inoltro degli allarmi
**Da decidere con il committente: non implementate di proposito.**

Possibili canali:

- email (SMTP);
- webhook firmati con HMAC;
- syslog/CEF verso il SIEM;
- Microsoft Teams, Slack, Telegram;
- PagerDuty/Opsgenie per la reperibilità.

Qualunque canale venga scelto, servono anche:

- regole di instradamento per gravità, categoria e sede;
- raggruppamento, per non ricevere 50 messaggi per una scansione;
- ripetizione se un allarme critico non viene preso in carico entro N minuti;
- finestre di manutenzione che silenziano le notifiche.

Sforzo M.

### Accesso centralizzato (SSO)
- OIDC (Entra ID, Google, Keycloak) e SAML 2.0.
- LDAP/Active Directory, con associazione tra gruppi e ruoli.
- Provisioning SCIM degli utenti.
- Gli account locali restano per l'emergenza.

Sforzo M.

### Sicurezza dei dati
- ~~**Segreti TOTP.** Cifrati con AES-GCM, chiave in `.env`, con rotazione.~~ Fatto (novembre 2026). Resta: chiave in un KMS o in Vault.
- **Sensori.** mTLS tra sensore e hub, in alternativa o in aggiunta al token, con certificati emessi dall'hub e revocabili.
- **Registro delle attività.** A prova di manomissione: catena di hash tra le righe ed export firmato.
- **Token API.** Limiti di frequenza, ambiti (solo allarmi, solo dispositivi), restrizione per indirizzo IP.

Sforzo M.

### Affidabilità del sensore
- ~~Spool su disco cifrato, con un limite di spazio e scarto dei dati più vecchi.~~ Fatto (novembre 2026).
- Configurazione remota dall'hub: interfacce, reti da ignorare, livello di log.
- Aggiornamento automatico firmato.
- Metriche di salute: CPU, memoria, perdite per interfaccia, ritardo di invio.

Sforzo M.

### Alta disponibilità e scalabilità
- ~~**Hub.** Più istanze dietro un bilanciatore. La ricezione non ha stato; il motore gira su una sola istanza alla volta, eletta con un lock consultivo di PostgreSQL.~~ Fatto (novembre 2026), insieme a più istanze dell'interfaccia e al blocco degli accessi in PostgreSQL.
- ~~**ClickHouse replicato.** ReplicatedMergeTree + Keeper.~~ Fatto (novembre 2026): l'hub riconosce un database `Replicated`. Resta: shard (tabelle `Distributed`) per oltre 10 Gbit/s.
- ~~**PostgreSQL.** Replica in streaming e failover gestito da Patroni.~~ Documentato (novembre 2026) in [alta-disponibilita.md](alta-disponibilita.md).
- ~~**Backup.** Automatici, verificati, con conservazione configurabile.~~ Fatto (novembre 2026): `deploy/backup.sh` con timer notturno e ripristino di prova settimanale. Resta: copia fuori sede integrata (S3, restic).

Sforzo L.

### Qualità e distribuzione
- **Test.** Fatti: unitari su hub, sensore (coda su disco compresa), crittografia e 2FA dell'interfaccia. Restano: azioni e permessi dell'interfaccia, end-to-end con Playwright, integrazione hub↔ClickHouse in container.
- ~~**CI.** GitHub Actions con lint, test, build, analisi delle dipendenze (govulncheck, npm audit) e SBOM.~~ Fatto (novembre 2026), con aggiornamenti delle dipendenze da Dependabot.
- **Rilasci.** Fatti: firmati con Sigstore, attestazione di provenienza, SBOM, pacchetti `.deb` e `.rpm` del sensore, archivio completo con i binari. Restano: immagini container, Helm chart, repository apt.
- **Monitoraggio di Hyperwave stesso.** Endpoint `/metrics` in formato Prometheus per hub e sensore, con dashboard Grafana di esempio.

Sforzo M.

## P2 — Analisi avanzata

### Più visibilità
- **QUIC/HTTP3.** Decifratura dell'Initial per leggere SNI e JA4 del traffico QUIC, oggi visto solo come UDP/443.
- **Protocolli aziendali, alla maniera di Zeek:**
  - SMB: condivisioni, file, comandi;
  - Kerberos e NTLM: utenti, cifrature deboli;
  - LDAP, RDP: nome della macchina, layout della tastiera;
  - SSH: impronte HASSH;
  - DHCP completo.
- **Integrazione con Zeek.** Per chi lo usa già: leggere i log `conn`, `dns`, `ssl` e `notice` come sorgente alternativa al sensore.
- **NetFlow v9, IPFIX e sFlow** da switch e firewall, dove non si può avere una porta SPAN.
- **Log di flusso cloud**: AWS VPC Flow Logs, Azure NSG Flow Logs, GCP.
- **Cattura veloce.** AF_XDP/eBPF per sensori a 10-25 Gbit/s.
- **DoH/DoT**: riconoscimento del DNS cifrato che aggira il DNS aziendale.

### Threat intelligence
- **Feed di indicatori.** MISP, abuse.ch (URLhaus, Feodo, ThreatFox), STIX/TAXII, elenchi propri.
- **Confronto con gli indicatori**: in tempo reale e retroattivo sullo storico ("questo dominio, segnalato oggi, chi l'ha contattato negli ultimi 30 giorni?").
- **Reputazione** di domini e IP, con dominio giovane e categoria.

### PCAP su richiesta
- ~~Buffer circolare sul sensore, per esempio le ultime 2 ore su disco.~~
- ~~Estrazione dei pacchetti di un flusso o di un allarme con un clic, da aprire in Wireshark.~~
- ~~Accesso consentito solo ad alcuni ruoli e registrato: i pacchetti contengono dati personali.~~

Fatto (novembre 2026). Resta: buffer anche per le modalità flow e zeek (oggi solo capture), cifratura del buffer su disco.

### Rilevamento
- **Regole personalizzate** scritte dagli amministratori, in un linguaggio tipo Sigma o come query ClickHouse con soglie, provabili sullo storico prima di attivarle.
- **Norma per host e per fascia oraria.** Comportamento appreso per ora della settimana, confronto con dispositivi simili, punteggio di rischio per dispositivo che tiene conto della criticità.
- **Correlazione in incidenti.** Allarmi collegati (scansione → accesso → movimento laterale → esfiltrazione) raggruppati in un incidente, con vista della catena MITRE ATT&CK.
- **Gestione dei casi.** Incidenti con responsabile, scadenze, checklist di risposta, allegati, esportazione per il rapporto.

### Visualizzazione
- **Mappa delle comunicazioni.** Grafo di chi parla con chi, filtrabile per VLAN, sede, applicazione.
- **Topologia** da LLDP/CDP e dalle tabelle ARP degli switch via SNMP.
- **Dashboard personalizzabili** e ricerche salvate.
- ~~**Rapporti PDF periodici.** Settimanale per la direzione; tecnico; per la conformità NIS2 e ISO 27001 (inventario, eventi, tempi di risposta).~~ Fatto (novembre 2026), solo archivio nell'interfaccia. Resta: invio, quando ci saranno le notifiche.

### Inventario
- **Fonti esterne.** Active Directory, server DHCP, MDM, CMDB (GLPI, ServiceNow).
- **Vulnerabilità.** Associazione tra sistema operativo e servizi rilevati e CVE note (CPE → CVE, catalogo CISA KEV).
- **Ciclo di vita.** Dispositivi spariti, cambi di MAC o di IP, dispositivi non autorizzati in VLAN sensibili.

## P3 — Su richiesta

- **Multi-tenant per MSP.** Organizzazioni separate, isolamento con row-level security in PostgreSQL e filtro obbligatorio in ClickHouse, utenti con accesso a più clienti.
- **Ruoli granulari.** Ruoli personalizzati e permessi limitati a sedi o sensori.
- **Privacy (GDPR).** Pseudonimizzazione degli indirizzi interni per chi non ha un ruolo autorizzato, conservazione distinta per tipo di dato, blocco della cancellazione per indagini (legal hold), registro delle ricerche fatte sui dati personali.
- **Risposta automatica.** Blocco di un IP sul firewall (pfSense, Fortinet, Palo Alto) o isolamento di una porta dello switch, sempre con approvazione esplicita e registro.
- **Integrazione con Vigil** (interpretazione nostra, da confermare). Oggi Hyperwave controlla solo che Vigil risponda. Si potrebbe:
  - sincronizzare l'inventario dei dispositivi;
  - avere una vista unica stato + traffico per dispositivo;
  - aprire gli allarmi dell'uno dall'altro.
- **Interfaccia in inglese** e tema chiaro.
- **App mobile o PWA** per la reperibilità.

## Ordine consigliato

Fatti a novembre 2026: cifratura dei segreti TOTP, coda su disco del sensore, test, CI e rilasci firmati, blocco degli accessi in PostgreSQL, PCAP su richiesta, rapporti PDF, alta disponibilità e backup.

1. Notifiche, dopo la scelta dei canali.
2. SSO.
3. Metriche Prometheus.
4. Limiti di frequenza dell'API e specifica OpenAPI.
5. Test end-to-end e di integrazione.
6. QUIC e threat intelligence: i due miglioramenti di rilevamento con il miglior rapporto tra valore e sforzo.
7. Shard di ClickHouse, quando un cliente supera i 10 Gbit/s.
