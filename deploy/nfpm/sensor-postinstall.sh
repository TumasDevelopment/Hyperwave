#!/bin/sh
# Dopo l'installazione o l'aggiornamento del pacchetto hyperwave-sensor.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  if systemctl is-enabled --quiet hyperwave-sensor 2>/dev/null; then
    # aggiornamento: riparte con il binario nuovo, la coda su disco resta
    systemctl try-restart hyperwave-sensor || true
  else
    echo "Hyperwave: compila /etc/hyperwave/sensor.env (hub, token, interfaccia),"
    echo "poi avvia il sensore con:  systemctl enable --now hyperwave-sensor"
  fi
fi
exit 0
