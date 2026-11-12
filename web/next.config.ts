import { existsSync } from "node:fs";
import type { NextConfig } from "next";

// La configurazione sta in ../.env (la stessa dell'hub). Serve anche in compilazione:
// il fuso orario delle pagine (HW_TZ) viene scritto nel codice che gira nel browser.
if (existsSync("../.env")) process.loadEnvFile("../.env");

const nextConfig: NextConfig = {
  poweredByHeader: false,
  env: { NEXT_PUBLIC_HW_TZ: process.env.HW_TZ || process.env.NEXT_PUBLIC_HW_TZ || "Europe/Rome" },
  serverExternalPackages: ["pg", "nats", "pdfkit"],
  turbopack: { root: process.cwd() },
  async headers() {
    // HSTS si imposta in nginx, quando tutto il dominio è in HTTPS
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
