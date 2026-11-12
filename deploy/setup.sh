#!/usr/bin/env bash
# Hyperwave: configurazione dei servizi su Debian o Ubuntu.
#
# Prerequisiti già installati: PostgreSQL 15 o successivo, ClickHouse 24 o successivo,
# nats-server 2.10 o successivo (pacchetto apt, servizio systemd), openssl e curl.
# Per compilare servono Go 1.24 o successivo e Node.js 20 o successivo
# (vedi docs/INSTALLAZIONE.md).
#
# Uso, dalla cartella del progetto:
#   deploy/build.sh                          compila (utente normale)
#   sudo deploy/setup.sh                     servizi, .env e unità systemd
#   sudo HW_PROCESS=pm2 deploy/setup.sh      come sopra, ma i processi li gestisce PM2
#   sudo HW_DEMO=1 deploy/setup.sh           avvia anche il sensore con dati di esempio
#   sudo deploy/backup.sh                    backup immediato (di solito lo fa il timer)
#
# Si può rilanciare: i segreti in .env vengono generati solo la prima volta.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
HW_USER="${HW_USER:-${SUDO_USER:-}}"
HW_PROCESS="${HW_PROCESS:-systemd}"
HW_DEMO="${HW_DEMO:-0}"
CH_RAM_RATIO="${CH_RAM_RATIO:-0.2}"

die() { echo "setup: $*" >&2; exit 1; }
step() { echo "==> $*"; }
rand() { openssl rand -hex "${1:-24}"; }
sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
envget() { grep -E "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true; }

[[ $EUID -eq 0 ]] || die "va eseguito con sudo"
[[ -n "$HW_USER" && "$HW_USER" != root ]] || die "indicare l'utente che esegue Hyperwave: sudo HW_USER=nome deploy/setup.sh"
id "$HW_USER" >/dev/null 2>&1 || die "l'utente $HW_USER non esiste"
HW_GROUP="$(id -gn "$HW_USER")"
for bin in openssl sha256sum psql clickhouse nats-server systemctl curl install; do
  command -v "$bin" >/dev/null || die "manca il comando $bin"
done
[[ "$CH_RAM_RATIO" =~ ^0\.[0-9]+$ ]] || die "CH_RAM_RATIO deve essere un numero tra 0 e 1 (es. 0.2)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- .env
step ".env"
if [[ ! -f "$ENV_FILE" ]]; then
  (
    umask 077
    cat >"$ENV_FILE" <<EOF
# Hyperwave: generato da deploy/setup.sh. Contiene segreti: non va mai in git.
DATABASE_URL=postgres://hyperwave:$(rand)@127.0.0.1:5432/hyperwave
CLICKHOUSE_URL=http://127.0.0.1:8123
CLICKHOUSE_DB=hyperwave
CLICKHOUSE_USER=hyperwave
CLICKHOUSE_PASSWORD=$(rand)
NATS_URL=nats://127.0.0.1:4222
NATS_TOKEN=$(rand)
HW_HUB_LISTEN=127.0.0.1:3121
HW_HUB_URL=http://127.0.0.1:3121
HW_WEB_HOST=127.0.0.1
HW_WEB_PORT=3120
HW_INTERNAL_NETS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7
HW_RETENTION_DAYS=30
# cifra i segreti dei due fattori nel database: senza questa chiave un backup del DB non basta a usarli
HW_SECRET_KEY=$(rand 32)
HW_GEOIP_CITY=
HW_GEOIP_ASN=
VIGIL_URL=
SOURCE_URL=
EOF
  )
  chown "$HW_USER:$HW_GROUP" "$ENV_FILE"
  echo "    creato $ENV_FILE (permessi 600)"
else
  echo "    $ENV_FILE esiste già: lo riuso"
  # installazioni precedenti alla cifratura dei segreti: si aggiunge la chiave senza toccare il resto
  if ! grep -qE '^HW_SECRET_KEY=.+' "$ENV_FILE"; then
    echo "HW_SECRET_KEY=$(rand 32)" >>"$ENV_FILE"
    echo "    aggiunta HW_SECRET_KEY (poi: cd web && npm run utente -- cifra-segreti)"
  fi
fi

# ---------------------------------------------------------------- PostgreSQL
step "PostgreSQL"
pg_pw="$(envget DATABASE_URL | sed -E 's#^postgres(ql)?://[^:/]+:([^@]+)@.*#\2#')"
[[ "$pg_pw" =~ ^[A-Za-z0-9._~-]+$ ]] || die "la password in DATABASE_URL deve contenere solo lettere, cifre e ._~-"
(
  cd /
  sudo -u postgres psql -q -X -v ON_ERROR_STOP=1 <<SQL
SELECT 'CREATE ROLE hyperwave LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'hyperwave')\gexec
ALTER ROLE hyperwave LOGIN PASSWORD '${pg_pw}';
SELECT 'CREATE DATABASE hyperwave OWNER hyperwave' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'hyperwave')\gexec
REVOKE ALL ON DATABASE hyperwave FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE hyperwave TO hyperwave;
SQL
)
echo "    ruolo e database hyperwave pronti"

# ---------------------------------------------------------------- ClickHouse
step "ClickHouse"
ch_pw="$(envget CLICKHOUSE_PASSWORD)"
[[ -n "$ch_pw" ]] || die "CLICKHOUSE_PASSWORD è vuota in .env"
mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
query_mem="$(awk -v m="$mem_kb" -v r="$CH_RAM_RATIO" 'BEGIN { printf "%d", m * 1024 * r * 0.6 }')"
spill=$((query_mem / 2))

sed "s/@CH_RAM_RATIO@/$CH_RAM_RATIO/" "$ROOT/deploy/clickhouse/hyperwave-config.xml" >"$TMP/config.xml"
sed -e "s/@HW_SHA256@/$(sha "$ch_pw")/" \
    -e "s/@DEFAULT_SHA256@/$(sha "$(rand 32)")/" \
    -e "s/@CH_QUERY_MEMORY@/$query_mem/" \
    -e "s/@CH_SPILL@/$spill/g" \
    "$ROOT/deploy/clickhouse/hyperwave-users.xml.tmpl" >"$TMP/users.xml"
install -o clickhouse -g clickhouse -m 0400 "$TMP/config.xml" /etc/clickhouse-server/config.d/hyperwave.xml
install -o clickhouse -g clickhouse -m 0400 "$TMP/users.xml" /etc/clickhouse-server/users.d/hyperwave.xml

# verifica che la configurazione unita sia leggibile prima di riavviare
ratio="$(cd / && sudo -u clickhouse clickhouse extract-from-config --config-file /etc/clickhouse-server/config.xml --key max_server_memory_usage_to_ram_ratio 2>/dev/null || true)"
[[ "$ratio" == "$CH_RAM_RATIO" ]] || die "configurazione di ClickHouse non valida (letto: '$ratio')"

systemctl enable clickhouse-server >/dev/null 2>&1
systemctl restart clickhouse-server
for _ in $(seq 1 60); do
  curl -fsS http://127.0.0.1:8123/ping >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:8123/ping >/dev/null 2>&1 || die "ClickHouse non risponde su 127.0.0.1:8123 (journalctl -u clickhouse-server)"
printf 'header = "X-ClickHouse-User: hyperwave"\nheader = "X-ClickHouse-Key: %s"\n' "$ch_pw" >"$TMP/curl.cfg"
echo 'SELECT 1' | curl -fsS -K "$TMP/curl.cfg" --data-binary @- http://127.0.0.1:8123/ >/dev/null \
  || die "l'utente hyperwave non riesce ad accedere a ClickHouse"
echo "    ClickHouse attivo, utente hyperwave verificato"

# ---------------------------------------------------------------- NATS
step "NATS"
systemctl cat nats-server >/dev/null 2>&1 || die "servizio nats-server non trovato (pacchetto apt nats-server)"
nats_conf="$(systemctl show -p ExecStart --value nats-server | grep -oE '(-c|--config) [^ ;]+' | head -n 1 | cut -d' ' -f2 || true)"
nats_conf="${nats_conf:-/etc/nats-server.conf}"
nats_group="$(id -gn nats 2>/dev/null || echo root)"
nats_token="$(envget NATS_TOKEN)"
[[ "$nats_token" =~ ^[A-Za-z0-9]+$ ]] || die "NATS_TOKEN deve contenere solo lettere e cifre"
if [[ -f "$nats_conf" && ! -f "$nats_conf.orig" ]]; then
  cp -p "$nats_conf" "$nats_conf.orig"
  echo "    copia della configurazione originale in $nats_conf.orig"
fi
sed "s/@NATS_TOKEN@/$nats_token/" "$ROOT/deploy/nats/nats-server.conf.tmpl" >"$TMP/nats.conf"
nats-server -c "$TMP/nats.conf" -t >/dev/null 2>&1 || die "configurazione di NATS non valida"
install -o root -g "$nats_group" -m 0640 "$TMP/nats.conf" "$nats_conf"
systemctl enable nats-server >/dev/null 2>&1
systemctl restart nats-server
echo "    NATS su 127.0.0.1:4222 con token ($nats_conf)"

# ---------------------------------------------------------------- processi
if [[ "$HW_PROCESS" == systemd ]]; then
  step "unità systemd"
  units=(hyperwave-hub hyperwave-web)
  [[ "$HW_DEMO" == 1 ]] && units+=(hyperwave-sensor-demo)
  for u in "${units[@]}"; do
    sed -e "s#@ROOT@#$ROOT#g" -e "s#@USER@#$HW_USER#g" -e "s#@GROUP@#$HW_GROUP#g" \
      "$ROOT/deploy/systemd/$u.service" >"/etc/systemd/system/$u.service"
  done
  systemctl daemon-reload
  systemctl enable "${units[@]}" >/dev/null 2>&1
  if [[ -x "$ROOT/core/bin/hw-hub" && -d "$ROOT/web/.next" ]]; then
    systemctl restart "${units[@]}"
    echo "    avviate: ${units[*]}"
  else
    echo "    abilitate ma non avviate: compilare con deploy/build.sh, poi sudo systemctl start ${units[*]}"
  fi
else
  step "processi"
  echo "    HW_PROCESS=$HW_PROCESS: nessuna unità systemd. Con PM2: pm2 start ecosystem.config.cjs"
fi

# ---------------------------------------------------------------- backup
# Unità di root indipendenti da HW_PROCESS: servono anche con PM2.
step "backup notturno"
for u in hyperwave-backup.service hyperwave-backup.timer hyperwave-backup-verifica.service hyperwave-backup-verifica.timer; do
  sed -e "s#@ROOT@#$ROOT#g" "$ROOT/deploy/systemd/$u" >"/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable --now hyperwave-backup.timer hyperwave-backup-verifica.timer >/dev/null 2>&1
echo "    ogni notte alle 2:30 in $(envget HW_BACKUP_DIR | grep . || echo /var/backups/hyperwave), verifica completa la domenica"
echo "    (deploy/backup.sh per lanciarlo subito; .env va salvato a parte)"

cat <<EOF

Fatto. Passi successivi:
  1. primo amministratore:  cd "$ROOT/web" && npm run utente -- aggiungi <nome> --admin
  2. sensore:               "$ROOT/core/bin/hw-hub" sensor-add -name <nome> -site <sede>
                            (stampa il token una sola volta; si può fare anche da Sensori nell'interfaccia)
  3. interfaccia:           http://127.0.0.1:$(envget HW_WEB_PORT), da pubblicare dietro un proxy HTTPS
EOF
