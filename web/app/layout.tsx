import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { connection } from "next/server";
import type { ReactNode } from "react";
import "uplot/dist/uPlot.min.css";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Hyperwave", template: "%s · Hyperwave" },
  description: "Monitoraggio della rete: traffico, dispositivi e allarmi",
  robots: { index: false, follow: false },
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Una pagina statica non avrebbe il nonce e la Content-Security-Policy ne bloccherebbe gli script
  await connection();
  return (
    <html lang="it" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
