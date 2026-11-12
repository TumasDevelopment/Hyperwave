#!/usr/bin/env bash
# Hyperwave: backup di PostgreSQL e ClickHouse, con verifica e conservazione.
#
# Uso, con sudo (il timer hyperwave-backup.timer lo lancia ogni notte):
#   deploy/backup.sh                         crea un backup e lo verifica
#   deploy/backup.sh verifica [cartella]     ripristina un backup in database di prova e li confronta
#   deploy/backup.sh ripristina <cartella> --si
#                                            sostituisce i dati attuali con quelli del backup
#
# Impostazioni lette da .env (o passate a mano, che valgono di più):
#   HW_BACKUP_DIR         cartella dei backup (predefinita /var/backups/hyperwave)
#   HW_BACKUP_KEEP_DAYS   giorni di conservazione (14); l'ultimo backup riuscito resta sempre
#   HW_BACKUP_CLICKHOUSE  1 (predefinito) per includere i flussi di ClickHouse, 0 per saltarli
#
# Il file .env non viene copiato: contiene HW_SECRET_KEY e va conservato a parte, cifrato.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${HW_ENV_FILE:-$ROOT/.env}"
CH_BACKUP_DISK=backups
CH_BACKUP_PATH=/var/lib/clickhouse/backups
CHECK_DB=hw_backup_check

die() { echo "backup: $*" >&2; exit 1; }
step() { echo "==> $*"; }
envget() { grep -E "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true; }

[[ $EUID -eq 0 ]] || die "va eseguito con sudo"
[[ -r "$ENV_FILE" ]] || die "manca $ENV_FILE"
for bin in pg_dump pg_restore psql curl sha256sum flock runuser; do
  command -v "$bin" >/dev/null || die "manca il comando $bin"
done

# una variabile passata a mano (sudo HW_BACKUP_CLICKHOUSE=0 deploy/backup.sh) vale più di .env
setting() { local v="${!1:-}"; [[ -n "$v" ]] || v="$(envget "$1")"; echo "${v:-$2}"; }
DIR="$(setting HW_BACKUP_DIR /var/backups/hyperwave)"
KEEP_DAYS="$(setting HW_BACKUP_KEEP_DAYS 14)"
WITH_CH="$(setting HW_BACKUP_CLICKHOUSE 1)"
[[ "$KEEP_DAYS" =~ ^[0-9]+$ && "$KEEP_DAYS" -ge 1 ]] || die "HW_BACKUP_KEEP_DAYS deve essere un numero di giorni (almeno 1)"
[[ "$WITH_CH" == 0 || "$WITH_CH" == 1 ]] || die "HW_BACKUP_CLICKHOUSE deve essere 0 o 1"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- PostgreSQL
# La password passa in PGPASSWORD e non sulla riga di comando, visibile a tutti con ps.
db_url="$(envget DATABASE_URL)"
[[ "$db_url" =~ ^postgres(ql)?://([^:@/]+)(:([^@]*))?@([^/?]+)/([^?]+)(\?.*)?$ ]] || die "DATABASE_URL non riconosciuta"
PG_USER="${BASH_REMATCH[2]}"
PG_HOSTPORT="${BASH_REMATCH[5]}"
PG_DB="${BASH_REMATCH[6]}"
PG_PARAMS="${BASH_REMATCH[7]}"
pw="${BASH_REMATCH[4]}"
PGPASSWORD="$(printf '%b' "${pw//%/\\x}")"
export PGPASSWORD
pg_url() { echo "postgresql://$PG_USER@$PG_HOSTPORT/$1$PG_PARAMS"; }
pg_local() { [[ "$PG_HOSTPORT" =~ ^(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?$ ]] && id postgres >/dev/null 2>&1; }
pg_count_tables() {
  psql "$(pg_url "$1")" -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'"
}

# ---------------------------------------------------------------- ClickHouse
CH_URL="$(envget CLICKHOUSE_URL)"; CH_URL="${CH_URL:-http://127.0.0.1:8123}"
CH_DB="$(envget CLICKHOUSE_DB)"; CH_DB="${CH_DB:-hyperwave}"
ch_user="$(envget CLICKHOUSE_USER)"
printf 'header = "X-ClickHouse-User: %s"\nheader = "X-ClickHouse-Key: %s"\n' "${ch_user:-hyperwave}" "$(envget CLICKHOUSE_PASSWORD)" >"$TMP/ch.cfg"
# max_execution_time=0: il profilo hyperwave ferma le query dopo 60 s, un backup può durare di più.
ch() {
  local code
  code="$(curl -sS -K "$TMP/ch.cfg" --data-binary @- -o "$TMP/ch.out" -w '%{http_code}' "$CH_URL/?max_execution_time=0")" || return 1
  if [[ "$code" != 200 ]]; then
    sed 's/^/    clickhouse: /' "$TMP/ch.out" >&2
    return 1
  fi
  cat "$TMP/ch.out"
}
ch_tables() { echo "SELECT name FROM system.tables WHERE database = '$1' AND NOT is_temporary ORDER BY name FORMAT TSV" | ch; }
ch_rows() { echo "SELECT sum(rows) FROM system.parts WHERE database = '$1' AND active FORMAT TSV" | ch; }
ch_local() { [[ "$CH_URL" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?/?$ ]] && [[ -d "$CH_BACKUP_PATH" ]]; }

# ---------------------------------------------------------------- funzioni comuni
latest() { find "$DIR" -mindepth 1 -maxdepth 1 -type d -name '20*' ! -name '*.parziale' | sort | tail -n 1; }

# Il ripristino passa sempre da qui, sia nella verifica sia in quello vero: la verifica
# notturna prova quindi gli stessi comandi che servirebbero il giorno del guasto.
# PostgreSQL: pg_restore in una sola transazione (se fallisce, il database resta com'era).
pg_restore_into() {
  pg_restore --dbname="$(pg_url "$2")" --no-owner --role="$PG_USER" --exit-on-error --single-transaction \
    ${RESTORE_CLEAN:+--clean --if-exists} "$1/postgres.dump"
}
# ClickHouse: RESTORE nel database di prova hw_backup_check, mai direttamente sui dati veri.
ch_restore_check() {
  ch_local || die "ClickHouse non è su questa macchina: ripristino dei flussi da fare sul suo server (docs/alta-disponibilita.md)"
  local name="ripristino-$$.zip"
  install -o clickhouse -g clickhouse -m 0600 "$1/clickhouse.zip" "$CH_BACKUP_PATH/$name"
  echo "DROP DATABASE IF EXISTS \`$CHECK_DB\` SYNC" | ch
  if ! echo "RESTORE DATABASE \`$CH_DB\` AS \`$CHECK_DB\` FROM Disk('$CH_BACKUP_DISK', '$name') FORMAT TSV" | ch >/dev/null; then
    rm -f "$CH_BACKUP_PATH/$name"
    die "RESTORE di ClickHouse non riuscito"
  fi
  rm -f "$CH_BACKUP_PATH/$name"
}
# Confronta il database di prova con quanto annotato in info.txt al momento del backup.
ch_compare_check() {
  local src="$1" want_tables got_tables lo hi rows
  want_tables="$(sed -nE 's/^clickhouse: +([0-9]+) tabelle.*/\1/p' "$src/info.txt")"
  got_tables="$(ch_tables "$CHECK_DB" | wc -l | tr -d ' ')"
  [[ "$got_tables" == "$want_tables" ]] || die "ClickHouse: ripristinate $got_tables tabelle su $want_tables"
  read -r lo hi < <(sed -nE 's/^clickhouse: .*righe tra ([0-9]+) e ([0-9]+).*/\1 \2/p' "$src/info.txt")
  rows="$(ch_rows "$CHECK_DB")"
  echo "    ClickHouse: $got_tables tabelle, $rows righe ripristinate"
  # Durante il backup l'hub continua a scrivere e le scadenze cancellano: il conteggio
  # esatto del momento del backup non è noto, solo quello prima e dopo.
  if [[ -n "$lo" ]] && ((rows < lo || rows > hi)); then
    echo "    attenzione: righe fuori dall'intervallo $lo-$hi annotato durante il backup" >&2
  fi
}

quick_check() {
  local dst="$1"
  (cd "$dst" && sha256sum --quiet -c SHA256SUMS) || die "somme SHA-256 non corrispondenti in $dst"
  pg_restore --list "$dst/postgres.dump" >/dev/null || die "archivio PostgreSQL illeggibile"
  if [[ -f "$dst/clickhouse.zip" ]] && command -v unzip >/dev/null; then
    unzip -tqq "$dst/clickhouse.zip" >/dev/null || die "archivio ClickHouse danneggiato"
  fi
}

# ---------------------------------------------------------------- comandi
cmd_backup() {
  install -d -m 0700 "$DIR"
  exec 9>"$DIR/.lock"
  flock -n 9 || die "un altro backup è in corso"

  local stamp dst
  stamp="$(date +%Y%m%d-%H%M%S)"
  dst="$DIR/$stamp.parziale"
  mkdir "$dst"
  # se qualcosa va storto non resta un backup a metà; quello riuscito viene rinominato prima
  PARTIAL="$dst"
  trap 'rm -rf "$TMP" ${PARTIAL:+"$PARTIAL"}' EXIT

  step "PostgreSQL ($PG_DB)"
  pg_dump --dbname="$(pg_url "$PG_DB")" --format=custom --compress=6 --file="$dst/postgres.dump"
  local pg_tables
  pg_tables="$(pg_count_tables "$PG_DB")"
  echo "    $(du -h "$dst/postgres.dump" | cut -f1), $pg_tables tabelle"

  local ch_info="esclusi (HW_BACKUP_CLICKHOUSE=0)"
  if [[ "$WITH_CH" == 1 ]]; then
    step "ClickHouse ($CH_DB)"
    ch_local || die "ClickHouse non è su questa macchina: usare HW_BACKUP_CLICKHOUSE=0 e un backup sul suo server (docs/alta-disponibilita.md)"
    local name="hyperwave-$stamp.zip" status rows_before
    rows_before="$(ch_rows "$CH_DB")"
    status="$(echo "BACKUP DATABASE \`$CH_DB\` TO Disk('$CH_BACKUP_DISK', '$name') FORMAT TSV" | ch)" \
      || die "BACKUP di ClickHouse non riuscito (il disco '$CH_BACKUP_DISK' è configurato? deploy/clickhouse/hyperwave-config.xml)"
    [[ "$status" == *BACKUP_CREATED* ]] || die "BACKUP di ClickHouse: stato inatteso «$status»"
    mv "$CH_BACKUP_PATH/$name" "$dst/clickhouse.zip"
    chown root:root "$dst/clickhouse.zip"
    chmod 0600 "$dst/clickhouse.zip"
    local rows_after lo hi
    rows_after="$(ch_rows "$CH_DB")"
    lo=$((rows_before < rows_after ? rows_before : rows_after))
    hi=$((rows_before > rows_after ? rows_before : rows_after))
    ch_info="$(ch_tables "$CH_DB" | wc -l | tr -d ' ') tabelle, righe tra $lo e $hi"
    echo "    $(du -h "$dst/clickhouse.zip" | cut -f1), $ch_info"
  fi

  {
    echo "creato:      $(date -Iseconds)"
    echo "versione:    $("$ROOT/core/bin/hw-hub" version 2>/dev/null || echo sconosciuta)"
    echo "postgres:    $pg_tables tabelle ($PG_DB)"
    echo "clickhouse:  $ch_info"
  } >"$dst/info.txt"
  local files=(postgres.dump info.txt)
  [[ -f "$dst/clickhouse.zip" ]] && files+=(clickhouse.zip)
  (cd "$dst" && sha256sum -- "${files[@]}" >SHA256SUMS)

  step "verifica"
  quick_check "$dst"
  mv "$dst" "$DIR/$stamp"
  PARTIAL=""
  echo "    somme SHA-256 e archivi leggibili"

  step "conservazione ($KEEP_DAYS giorni)"
  local removed=0 d
  while IFS= read -r d; do
    [[ "$d" == "$DIR/$stamp" ]] && continue
    rm -rf -- "$d"
    removed=$((removed + 1))
  done < <(find "$DIR" -mindepth 1 -maxdepth 1 -type d -name '20*' -mtime +"$((KEEP_DAYS - 1))")
  # backup interrotti a metà (macchina spenta, disco pieno)
  find "$DIR" -mindepth 1 -maxdepth 1 -type d -name '*.parziale' -mmin +720 -exec rm -rf -- {} +
  echo "    eliminati $removed backup vecchi; spazio occupato $(du -sh "$DIR" | cut -f1)"
  echo "Fatto: $DIR/$stamp"
}

cmd_verifica() {
  local src="${1:-$(latest)}"
  [[ -n "$src" && -f "$src/postgres.dump" ]] || die "nessun backup da verificare in $DIR"
  pg_local || die "PostgreSQL non è su questa macchina: la verifica completa va fatta sul suo server"
  step "verifica completa di $src"
  quick_check "$src"

  cleanup_check() {
    runuser -u postgres -- dropdb --if-exists "$CHECK_DB" >/dev/null 2>&1 || true
    echo "DROP DATABASE IF EXISTS \`$CHECK_DB\` SYNC" | ch >/dev/null 2>&1 || true
  }
  cleanup_check
  trap 'cleanup_check; rm -rf "$TMP"' EXIT
  runuser -u postgres -- createdb --owner="$PG_USER" "$CHECK_DB"
  pg_restore_into "$src" "$CHECK_DB"

  local want got
  want="$(sed -nE 's/^postgres: +([0-9]+) tabelle.*/\1/p' "$src/info.txt")"
  got="$(pg_count_tables "$CHECK_DB")"
  [[ "$got" == "$want" ]] || die "PostgreSQL: ripristinate $got tabelle su $want"
  echo "    PostgreSQL: $got tabelle ripristinate"
  if [[ -f "$src/clickhouse.zip" ]]; then
    ch_restore_check "$src"
    ch_compare_check "$src"
  fi
  echo "Backup valido."
}

cmd_ripristina() {
  local src="${1:-}"
  [[ -n "$src" && -f "$src/postgres.dump" ]] || die "indicare la cartella del backup (es. $(latest))"
  [[ "${2:-}" == --si ]] || die "il ripristino sostituisce tutti i dati attuali: aggiungere --si per confermare"
  quick_check "$src"
  local units=() u
  for u in hyperwave-hub hyperwave-web; do
    systemctl is-active --quiet "$u" 2>/dev/null && units+=("$u")
  done
  if ((${#units[@]})); then
    step "arresto di ${units[*]}"
    systemctl stop "${units[@]}"
    trap 'systemctl start '"${units[*]}"'; rm -rf "$TMP"' EXIT
  else
    echo "    nessuna unità systemd attiva: con PM2 fermare prima hub e sito (pm2 stop hyperwave-hub hyperwave-web)"
  fi
  step "ripristino di $src"
  # Ordine scelto perché un errore non lasci dati a metà: i flussi vengono prima ripristinati
  # nel database di prova (i dati veri non si toccano), poi PostgreSQL in una sola
  # transazione, infine lo scambio dei flussi, che dura un attimo.
  local with_ch=0
  if [[ -f "$src/clickhouse.zip" ]]; then
    with_ch=1
    ch_restore_check "$src"
    ch_compare_check "$src"
  fi
  RESTORE_CLEAN=1 pg_restore_into "$src" "$PG_DB"
  echo "    PostgreSQL ripristinato"
  if ((with_ch)); then
    echo "DROP DATABASE IF EXISTS \`$CH_DB\` SYNC" | ch
    echo "RENAME DATABASE \`$CHECK_DB\` TO \`$CH_DB\`" | ch
    echo "    ClickHouse ripristinato"
  fi
  echo "Ripristino completato."
}

case "${1:-backup}" in
  backup) cmd_backup ;;
  verifica) shift; cmd_verifica "$@" ;;
  ripristina) shift; cmd_ripristina "$@" ;;
  *) die "comando sconosciuto: $1 (backup, verifica, ripristina)" ;;
esac
