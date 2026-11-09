// Processi PM2 di Hyperwave, in alternativa alle unità systemd di deploy/systemd.
// Tutti leggono il file .env di questa cartella.
//
//   pm2 start ecosystem.config.cjs                      hub e interfaccia
//   pm2 start ecosystem.config.cjs --only hyperwave-sensor-demo   dati dimostrativi
//
// Il sensore in cattura reale va avviato sulla macchina che riceve la copia del traffico,
// con i permessi per leggere l'interfaccia (vedi docs/installazione.md).
const cwd = __dirname;

module.exports = {
  apps: [
    {
      name: "hyperwave-hub",
      cwd,
      script: "core/bin/hw-hub",
      args: "serve",
      interpreter: "none",
      max_memory_restart: "1G",
      kill_timeout: 15000,
    },
    {
      name: "hyperwave-web",
      cwd: `${cwd}/web`,
      script: "scripts/start.mjs",
      env: { NODE_ENV: "production" },
      max_memory_restart: "500M",
    },
    {
      name: "hyperwave-sensor-demo",
      cwd,
      script: "core/bin/hw-sensor",
      args: "-mode demo",
      interpreter: "none",
      max_memory_restart: "400M",
      kill_timeout: 10000,
    },
  ],
};
