"use client";

import { useEffect, useRef } from "react";
import uPlot from "uplot";
import { CHART_COLORS, fmtAxisTime, fmtTicks, fmtValue, withAlpha, type ChartUnit } from "@/lib/chart";
import { fmtDateTimeFull, TZ } from "@/lib/format";

export interface ChartSeries {
  label: string;
  color: string;
  values: (number | null)[];
  kind?: "line" | "bars";
}

interface Props {
  t: number[];
  series: ChartSeries[];
  rangeSeconds: number;
  unit: ChartUnit;
  ariaLabel: string;
  height?: number;
  area?: boolean;
}

const AXIS_FONT = '12px var(--font-geist-sans), system-ui, sans-serif';

function tooltipPlugin(unit: () => ChartUnit, series: () => ChartSeries[]) {
  let tip: HTMLDivElement;
  return {
    hooks: {
      init: (plot: uPlot) => {
        tip = document.createElement("div");
        tip.className = "chart-tip";
        tip.hidden = true;
        plot.over.parentElement?.appendChild(tip);
      },
      setCursor: (plot: uPlot) => {
        const { idx, left, top } = plot.cursor;
        if (idx === null || idx === undefined || left === undefined || top === undefined || left < 0) {
          tip.hidden = true;
          return;
        }
        // le etichette possono venire dai dati: solo textContent, mai innerHTML
        tip.replaceChildren();
        const time = document.createElement("div");
        time.className = "chart-tip__time";
        time.textContent = fmtDateTimeFull(plot.data[0][idx] * 1000);
        tip.appendChild(time);
        series().forEach((entry, index) => {
          const value = plot.data[index + 1]?.[idx];
          const row = document.createElement("div");
          row.className = "chart-tip__row";
          const key = document.createElement("span");
          key.className = "chart-tip__key";
          key.style.background = entry.color;
          const shown = document.createElement("span");
          shown.className = "chart-tip__value";
          shown.textContent = value === null || value === undefined ? "—" : fmtValue(value, unit());
          const name = document.createElement("span");
          name.className = "chart-tip__name";
          name.textContent = entry.label;
          row.append(key, shown, name);
          tip.appendChild(row);
        });
        tip.hidden = false;
        const width = tip.offsetWidth;
        const x = plot.over.offsetLeft + left;
        const fitsRight = x + width + 16 < plot.over.parentElement!.clientWidth;
        tip.style.left = `${fitsRight ? x + 14 : x - width - 14}px`;
        tip.style.top = `${Math.max(0, plot.over.offsetTop + top - tip.offsetHeight / 2)}px`;
      },
    },
  };
}

export function TimeSeriesChart({ t, series, rangeSeconds, unit, ariaLabel, height = 240, area = true }: Props) {
  const container = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const latest = useRef({ series, unit, t });
  latest.current = { series, unit, t };
  const shape = series.map((entry) => `${entry.label}|${entry.color}|${entry.kind ?? "line"}`).join("~");

  useEffect(() => {
    const element = container.current;
    if (!element) return;
    const current = latest.current;
    const bars = uPlot.paths.bars?.({ size: [0.7, 24], radius: 0.15 });
    const options: uPlot.Options = {
      width: element.clientWidth,
      height,
      legend: { show: false },
      tzDate: (ts) => uPlot.tzDate(new Date(ts * 1000), TZ),
      cursor: { y: false, drag: { x: false, y: false }, points: { size: 7, width: 2, stroke: CHART_COLORS.surface } },
      scales: {
        x: { time: true },
        y: { range: (_plot, _min, max) => [0, max !== null && max > 0 ? max * 1.15 : 1] },
      },
      series: [
        {},
        ...current.series.map((entry): uPlot.Series =>
          entry.kind === "bars"
            ? { label: entry.label, stroke: entry.color, fill: withAlpha(entry.color, 0.85), width: 0, paths: bars, points: { show: false } }
            : {
                label: entry.label,
                stroke: entry.color,
                width: 1.75,
                fill: area ? withAlpha(entry.color, 0.08) : undefined,
                points: { show: false },
                spanGaps: false,
              },
        ),
      ],
      axes: [
        {
          stroke: CHART_COLORS.axis,
          font: AXIS_FONT,
          space: 80,
          grid: { show: false },
          ticks: { stroke: CHART_COLORS.baseline, width: 1, size: 4 },
          values: (_plot, splits) => splits.map((value) => fmtAxisTime(value, rangeSeconds)),
        },
        {
          stroke: CHART_COLORS.axis,
          font: AXIS_FONT,
          size: 72,
          grid: { stroke: CHART_COLORS.grid, width: 1 },
          ticks: { show: false },
          values: (_plot, splits) => fmtTicks(splits, latest.current.unit),
        },
      ],
      plugins: [tooltipPlugin(() => latest.current.unit, () => latest.current.series)],
    };
    const instance = new uPlot(options, [current.t, ...current.series.map((entry) => entry.values)] as uPlot.AlignedData, element);
    plot.current = instance;
    const observer = new ResizeObserver(() => instance.setSize({ width: element.clientWidth, height }));
    observer.observe(element);
    return () => {
      observer.disconnect();
      instance.destroy();
      plot.current = null;
    };
  }, [shape, rangeSeconds, height, area]);

  useEffect(() => {
    plot.current?.setData([t, ...series.map((entry) => entry.values)] as uPlot.AlignedData);
  }, [t, series]);

  return <div ref={container} className="chart" style={{ height }} role="img" aria-label={ariaLabel} />;
}

/** Legenda sotto il grafico. */
export function ChartLegend({ items }: { items: { label: string; color: string; value?: string }[] }) {
  return (
    <ul className="legend">
      {items.map((item) => (
        <li key={item.label}>
          <span className="legend__key" style={{ background: item.color }} />
          {item.label}
          {item.value && <strong>{item.value}</strong>}
        </li>
      ))}
    </ul>
  );
}
