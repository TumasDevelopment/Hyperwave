// Avvia il sito compilato leggendo indirizzo e porta da ../.env (HW_WEB_HOST, HW_WEB_PORT).
// Tutte le variabili di ../.env arrivano al sito: database, ClickHouse, NATS, SOURCE_URL.
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";

for (const file of [".env", "../.env"]) {
  if (existsSync(file)) {
    try {
      process.loadEnvFile(file);
    } catch (error) {
      console.error(`Lettura di ${file} non riuscita:`, error.message);
      process.exit(1);
    }
  }
}

const host = process.env.HW_WEB_HOST || "127.0.0.1";
const port = process.env.HW_WEB_PORT || "3120";
const next = createRequire(import.meta.url).resolve("next/dist/bin/next");
const child = spawn(process.execPath, [next, "start", "-H", host, "-p", port], { stdio: "inherit", env: process.env });
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
child.on("exit", (code) => process.exit(code ?? 0));
