import Link from "next/link";
import type { ReactNode } from "react";
import { Credito, Logo } from "@/components/Brand";
import { Nav, type NavItem } from "@/components/Nav";
import { logout } from "@/lib/actions/session";
import { can, requireUser, ROLE_LABELS } from "@/lib/auth";
import { db, setting } from "@/lib/db";

export default async function AppLayout({ children }: { children: ReactNode }) {
  const user = await requireUser({ allowMustChange: true });
  const [live, open] = await Promise.all([
    setting<boolean>("live", true).catch(() => true),
    db()
      .query<{ n: number }>("SELECT count(*)::int AS n FROM alerts WHERE status = 'open'")
      .then((r) => r.rows[0]?.n ?? 0)
      .catch(() => 0),
  ]);

  const items: NavItem[] = user.mustChange
    ? [{ href: "/account", label: "Account", icon: "account" }]
    : [
        { href: "/", label: "Panoramica", icon: "overview" },
        { href: "/traffico", label: "Traffico", icon: "traffic" },
        { href: "/flussi", label: "Flussi", icon: "flows" },
        { href: "/dispositivi", label: "Dispositivi", icon: "devices" },
        { href: "/allarmi", label: "Allarmi", icon: "alerts", badge: open },
        { href: "/minacce", label: "Minacce note", icon: "intel" },
        { href: "/analisi", label: "Analisi", icon: "analysis" },
        { href: "/regole", label: "Regole", icon: "rules" },
        { href: "/sensori", label: "Sensori", icon: "sensors" },
        ...(can(user, "admin") ? [{ href: "/impostazioni", label: "Impostazioni", icon: "settings" as const }] : []),
        { href: "/account", label: "Account", icon: "account" },
      ];

  return (
    <div className="shell">
      <aside className="side">
        <Link href="/" className="brand">
          <Logo />
          <span>Hyperwave</span>
        </Link>
        <Nav items={items} />
        <div className="side__foot">
          <Link href={can(user, "admin") ? "/impostazioni" : "/"} className={`live-pill ${live ? "live-pill--on" : "live-pill--off"}`}>
            <span className="live-dot" aria-hidden="true" /> {live ? "Live acceso" : "Live spento"}
          </Link>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar__user">
            <span className="topbar__name">{user.displayName || user.username}</span>
            <span className="muted">{ROLE_LABELS[user.role]}</span>
          </div>
          <form action={logout}>
            <button type="submit" className="btn btn--small btn--ghost">
              Esci
            </button>
          </form>
        </header>
        <main className="content">{children}</main>
        <footer className="footer">
          <Credito />
        </footer>
      </div>
    </div>
  );
}
