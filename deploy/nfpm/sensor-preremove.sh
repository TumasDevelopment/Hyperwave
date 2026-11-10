#!/bin/sh
# Prima della rimozione del pacchetto (non durante un aggiornamento).
# deb passa "remove", rpm passa 0 quando non resta nessuna versione installata.
set -e
case "$1" in
  remove | purge | 0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now hyperwave-sensor >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
