"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

export interface NavItem {
  href: string;
  label: string;
  icon: keyof typeof ICONS;
  badge?: number;
}

// Icone a tratto, 20x20: decorative, il testo accanto dice già tutto.
const ICONS = {
  overview: "M3 11l7-7 7 7M5 9v8h4v-5h2v5h4V9",
  traffic: "M2 14l4-5 4 3 4-7 4 4",
  flows: "M3 6h11l-3-3M17 14H6l3 3",
  devices: "M3 4h14v9H3zM7 17h6M10 13v4",
  alerts: "M10 3l8 14H2zM10 8v4M10 14.5v.5",
  intel: "M10 2l7 3v5c0 4-3 7-7 8-4-1-7-4-7-8V5zM7.5 10l2 2 3.5-4",
  incidents: "M3 5h14v4H3zM3 11h14v4H3zM6 7h.01M6 13h.01",
  map: "M5 5m-2 0a2 2 0 104 0 2 2 0 10-4 0M15 6m-2 0a2 2 0 104 0 2 2 0 10-4 0M10 15m-2 0a2 2 0 104 0 2 2 0 10-4 0M7 5.5l6 .5M6.2 6.8l2.8 6.5M14 7.8l-3 5.5",
  analysis: "M8.5 3a5.5 5.5 0 104 9.3L17 17M8.5 6v5M6 8.5h5",
  rules: "M4 5h12M4 10h12M4 15h7",
  sensors: "M10 10m-2 0a2 2 0 104 0 2 2 0 10-4 0M5.5 5.5a6.4 6.4 0 000 9M14.5 5.5a6.4 6.4 0 010 9",
  settings: "M10 7a3 3 0 100 6 3 3 0 000-6zM10 2v2M10 16v2M2 10h2M16 10h2M4.3 4.3l1.4 1.4M14.3 14.3l1.4 1.4M4.3 15.7l1.4-1.4M14.3 5.7l1.4-1.4",
  pcap: "M10 2l7 4v8l-7 4-7-4V6zM3 6l7 4 7-4M10 10v8",
  reports: "M5 2h7l4 4v12H5zM12 2v4h4M8 14v-3M10.5 14V9M13 14v-2",
  account: "M10 10a3.5 3.5 0 100-7 3.5 3.5 0 000 7zM3 18c1-3.5 4-5 7-5s6 1.5 7 5",
};

export function Nav({ items }: { items: NavItem[] }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [pathname]);
  const active = (href: string) => (href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`));
  return (
    <>
      <button type="button" className="nav-toggle" aria-expanded={open} aria-controls="nav" onClick={() => setOpen(!open)}>
        <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
          <path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
        <span className="sr-only">Menu</span>
      </button>
      <nav id="nav" className={`nav ${open ? "nav--open" : ""}`} aria-label="Sezioni">
        <ul>
          {items.map((item) => (
            <li key={item.href}>
              <Link href={item.href} aria-current={active(item.href) ? "page" : undefined}>
                <svg width="18" height="18" viewBox="0 0 20 20" aria-hidden="true">
                  <path d={ICONS[item.icon]} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <span>{item.label}</span>
                {item.badge ? <span className="nav__badge">{item.badge > 999 ? "999+" : item.badge}</span> : null}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
    </>
  );
}
