"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { fmtBps, fmtBytes, fmtNum, fmtTime, flag } from "@/lib/format";
import { SERIES_COLORS, SEVERITY_LABELS } from "@/lib/labels";
import { ChartLegend, TimeSeriesChart } from "./TimeSeriesChart";

interface Seed {
  t: number[];
  in: number[];
  out: number[];
  int: number[];
}

interface LiveState {
  ts: number;
  live: boolean;
  sensors_sending: number;
  bps_in: number;
  bps_out: number;
  bps_int: number;
  pps: number;
  drops: number;
}

interface LiveFlow {
  t: string;
  s: string;
  d: string;
  sn?: string;
  dn?: string;
  p: string;
  dp: number;
  a?: string;
  dom?: string;
  b: number;
  cc?: string;
  dir: string;
}

interface LiveEvent {
  kind: string;
  ts: number;
  id?: number;
  severity?: string;
  title?: string;
  src?: string;
  dst?: string;
  rule?: string;
  sensor?: string;
}

const WINDOW = 15 * 60;
const MAX_FLOWS = 40;
const MAX_EVENTS = 12;

/**
 * Vista in tempo reale: banda degli ultimi 15 minuti (5 s per punto), flussi che
 * scorrono e allarmi appena aperti. Arriva tutto da /api/live (Server-Sent Events).
 */
export function LiveOverview({ seed, initialLive }: { seed: Seed; initialLive: boolean }) {
  const [points, setPoints] = useState(seed);
  const [state, setState] = useState<LiveState | null>(null);
  const [flows, setFlows] = useState<(LiveFlow & { key: number })[]>([]);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState<"connecting" | "open" | "lost">("connecting");
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const counter = useRef(0);

  useEffect(() => {
    const source = new EventSource("/api/live");
    source.onopen = () => setConnected("open");
    source.onerror = () => setConnected("lost");
    source.addEventListener("state", (message) => {
      const s = JSON.parse((message as MessageEvent).data) as LiveState;
      setState(s);
      const t = Math.floor(s.ts / 5000) * 5;
      setPoints((prev) => {
        const keep = prev.t.findIndex((x) => x > t - WINDOW);
        const from = keep < 0 ? prev.t.length : keep;
        const last = prev.t[prev.t.length - 1];
        const next = {
          t: prev.t.slice(from),
          in: prev.in.slice(from),
          out: prev.out.slice(from),
          int: prev.int.slice(from),
        };
        if (last === t) {
          next.in[next.in.length - 1] = s.bps_in;
          next.out[next.out.length - 1] = s.bps_out;
          next.int[next.int.length - 1] = s.bps_int;
        } else {
          next.t.push(t);
          next.in.push(s.bps_in);
          next.out.push(s.bps_out);
          next.int.push(s.bps_int);
        }
        return next;
      });
    });
    source.addEventListener("flows", (message) => {
      if (pausedRef.current) return;
      const list = JSON.parse((message as MessageEvent).data) as LiveFlow[];
      setFlows((prev) => [...list.map((f) => ({ ...f, key: counter.current++ })).reverse(), ...prev].slice(0, MAX_FLOWS));
    });
    source.addEventListener("event", (message) => {
      const e = JSON.parse((message as MessageEvent).data) as LiveEvent;
      if (e.kind === "alert" || e.kind === "ids" || e.kind === "alert_resolved") setEvents((prev) => [e, ...prev].slice(0, MAX_EVENTS));
    });
    return () => source.close();
  }, []);

  const series = useMemo(
    () => [
      { label: "Da internet", color: SERIES_COLORS.in, values: points.in },
      { label: "Verso internet", color: SERIES_COLORS.out, values: points.out },
      { label: "Interno", color: SERIES_COLORS.internal, values: points.int },
    ],
    [points],
  );

  const live = state ? state.live : initialLive;
  const last = (arr: number[]) => (arr.length ? arr[arr.length - 1] : 0);

  return (
    <div className="live">
      <div className="live__head">
        <span className={`live-dot live-dot--${!live ? "off" : connected}`} aria-hidden="true" />
        <strong>{!live ? "Live spento" : connected === "open" ? "In tempo reale" : connected === "lost" ? "Connessione persa, riprovo…" : "Collegamento…"}</strong>
        {state && (
          <span className="muted">
            {state.sensors_sending} {state.sensors_sending === 1 ? "sensore invia" : "sensori inviano"} · {fmtNum(Math.round(state.pps))} pacchetti/s
            {state.drops > 0 && <span className="text-warn"> · {fmtNum(state.drops)} persi</span>}
          </span>
        )}
      </div>
      {!live && <p className="notice notice--warn">Il live è spento: i sensori non inviano dati e i rilevamenti sono fermi. Un amministratore può riaccenderlo da Impostazioni.</p>}
      <TimeSeriesChart t={points.t} series={series} rangeSeconds={WINDOW} unit="bps" ariaLabel="Banda degli ultimi 15 minuti" height={200} />
      <ChartLegend
        items={[
          { label: "Da internet", color: SERIES_COLORS.in, value: fmtBps(state?.bps_in ?? last(points.in)) },
          { label: "Verso internet", color: SERIES_COLORS.out, value: fmtBps(state?.bps_out ?? last(points.out)) },
          { label: "Interno", color: SERIES_COLORS.internal, value: fmtBps(state?.bps_int ?? last(points.int)) },
        ]}
      />
      <div className="live__grid">
        <div>
          <div className="live__sub">
            <h3>Flussi in questo momento</h3>
            <button type="button" className="btn btn--small btn--ghost" onClick={() => setPaused(!paused)}>
              {paused ? "Riprendi" : "Pausa"}
            </button>
          </div>
          <div className="ticker" aria-live="off">
            {flows.length === 0 ? (
              <p className="empty">In attesa dei primi flussi…</p>
            ) : (
              <table className="table table--compact">
                <tbody>
                  {flows.map((f) => (
                    <tr key={f.key}>
                      <td className="mono muted">{fmtTime(f.t)}</td>
                      <td className="mono">
                        <span title={f.s}>{f.sn || f.s}</span>
                      </td>
                      <td className="muted">→</td>
                      <td className="mono">
                        <span title={f.d}>{f.dom || f.dn || f.d}</span>
                        <span className="muted">:{f.dp}</span>
                      </td>
                      <td>{f.a || f.p}</td>
                      <td>{f.cc ? `${flag(f.cc)} ${f.cc}` : ""}</td>
                      <td className="num">{fmtBytes(f.b)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
        <div>
          <div className="live__sub">
            <h3>Ultimi allarmi ed eventi</h3>
          </div>
          {events.length === 0 ? (
            <p className="empty">Nessun nuovo allarme da quando hai aperto la pagina.</p>
          ) : (
            <ul className="events">
              {events.map((e, i) => (
                <li key={`${e.ts}-${i}`}>
                  <span className={`badge badge--${e.severity ?? "info"}`}>{SEVERITY_LABELS[e.severity ?? "info"] ?? e.severity}</span>
                  <span className="events__body">
                    {e.kind === "alert" && e.id ? <Link href={`/allarmi/${e.id}`}>{e.title}</Link> : e.kind === "alert_resolved" ? `Sensore ${e.sensor} di nuovo in linea` : e.title}
                    <span className="muted mono">
                      {" "}
                      {fmtTime(e.ts)} {e.src && `· ${e.src}`} {e.dst && `→ ${e.dst}`}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
