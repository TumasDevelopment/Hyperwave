import "server-only";
import { existsSync } from "node:fs";
import path from "node:path";
import PDFDocument from "pdfkit";

// Impaginazione dei rapporti: A4, testo in Geist (lo stesso carattere del sito) se c'è,
// altrimenti Helvetica. Intestazione e piè di pagina si scrivono alla fine, quando si
// conosce il numero di pagine.

const MARGIN = 50;
const FOOTER = 28;

export const COLORS = {
  text: "#111827",
  muted: "#6b7280",
  line: "#e5e7eb",
  band: "#f3f4f6",
  accent: "#0e7490",
  ok: "#15803d",
  warn: "#b45309",
  bad: "#b91c1c",
};

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#991b1b",
  high: "#dc2626",
  medium: "#d97706",
  low: "#2563eb",
  info: "#9ca3af",
};

export interface Column {
  label: string;
  /** frazione della larghezza utile */
  width: number;
  align?: "left" | "right";
}

export interface Kpi {
  label: string;
  value: string;
  note?: string;
  tone?: "ok" | "warn" | "bad";
}

export interface BarSeries {
  label: string;
  color: string;
  values: number[];
}

function fontFile(name: string) {
  const file = path.join(process.cwd(), "node_modules", "geist", "dist", "fonts", "geist-sans", name);
  return existsSync(file) ? file : null;
}

export class ReportDoc {
  readonly doc: PDFKit.PDFDocument;
  private readonly chunks: Buffer[] = [];
  private readonly done: Promise<Buffer>;
  private readonly regular: string;
  private readonly bold: string;

  constructor(
    private readonly title: string,
    private readonly footerNote: string,
  ) {
    this.doc = new PDFDocument({
      size: "A4",
      margins: { top: MARGIN, bottom: MARGIN + FOOTER, left: MARGIN, right: MARGIN },
      bufferPages: true,
      info: { Title: title, Author: "Hyperwave", Creator: "Hyperwave", Producer: "Hyperwave" },
      lang: "it-IT",
      displayTitle: true,
    });
    const regular = fontFile("Geist-Regular.ttf");
    const bold = fontFile("Geist-SemiBold.ttf");
    if (regular && bold) {
      this.doc.registerFont("R", regular);
      this.doc.registerFont("B", bold);
      this.regular = "R";
      this.bold = "B";
    } else {
      this.regular = "Helvetica";
      this.bold = "Helvetica-Bold";
    }
    this.doc.on("data", (c: Buffer) => this.chunks.push(c));
    this.done = new Promise((resolve, reject) => {
      this.doc.on("end", () => resolve(Buffer.concat(this.chunks)));
      this.doc.on("error", reject);
    });
    this.noLigatures();
    this.doc.font(this.regular).fontSize(10).fillColor(COLORS.text);
  }

  /**
   * Geist unisce "ff", "fi", "tt"... in un solo glifo: a vista non cambia nulla, ma nel testo
   * del PDF (ricerca, copia, lettori di schermo) "Attività" diventerebbe "Atività". Le legature
   * si spengono su ogni scrittura e misura; pdfkit passa le opzioni così come sono a fontkit.
   */
  private noLigatures() {
    const features = { liga: false, clig: false, dlig: false, calt: false } as unknown as PDFKit.Mixins.OpenTypeFeatures[];
    const d = this.doc as unknown as Record<string, (...args: unknown[]) => unknown>;
    const withFeatures = (o: unknown) => ({ features, ...(typeof o === "object" && o !== null ? o : {}) });
    const text = d.text.bind(d);
    d.text = (s: unknown, x?: unknown, y?: unknown, o?: unknown) =>
      typeof x === "object" && x !== null ? text(s, withFeatures(x)) : text(s, x, y, withFeatures(o));
    for (const name of ["widthOfString", "heightOfString"]) {
      const measure = d[name].bind(d);
      d[name] = (s: unknown, o?: unknown) => measure(s, withFeatures(o));
    }
  }

  get width() {
    return this.doc.page.width - MARGIN * 2;
  }

  private get bottom() {
    return this.doc.page.height - this.doc.page.margins.bottom;
  }

  /** Nuova pagina se mancano `height` punti di spazio. */
  ensure(height: number) {
    if (this.doc.y + height > this.bottom) this.doc.addPage();
  }

  cover(subtitle: string, lines: string[]) {
    const d = this.doc;
    d.rect(0, 0, d.page.width, 6).fill(COLORS.accent);
    d.fillColor(COLORS.accent).font(this.bold).fontSize(11).text("HYPERWAVE", MARGIN, MARGIN, { characterSpacing: 2 });
    d.moveDown(0.6);
    d.fillColor(COLORS.text).font(this.bold).fontSize(22).text(this.title);
    d.font(this.regular).fontSize(12).fillColor(COLORS.muted).text(subtitle);
    d.moveDown(0.5);
    d.fontSize(9);
    for (const line of lines) d.text(line);
    d.moveDown(0.8);
    this.rule();
    d.moveDown(0.6);
    d.fillColor(COLORS.text);
  }

  rule() {
    const d = this.doc;
    d.moveTo(MARGIN, d.y).lineTo(MARGIN + this.width, d.y).lineWidth(0.6).strokeColor(COLORS.line).stroke();
  }

  h1(text: string) {
    this.ensure(120);
    this.doc.moveDown(0.6).font(this.bold).fontSize(15).fillColor(COLORS.text).text(text, MARGIN);
    this.doc.moveDown(0.3);
  }

  h2(text: string) {
    this.ensure(90);
    this.doc.moveDown(0.5).font(this.bold).fontSize(11.5).fillColor(COLORS.text).text(text, MARGIN);
    this.doc.moveDown(0.2);
  }

  /** Riferimento a un controllo di una norma, sotto il titolo di una sezione. */
  ref(text: string) {
    this.doc.font(this.regular).fontSize(8.5).fillColor(COLORS.accent).text(text, MARGIN);
    this.doc.moveDown(0.3);
  }

  p(text: string, opts: { muted?: boolean; size?: number; bold?: boolean } = {}) {
    this.doc
      .font(opts.bold ? this.bold : this.regular)
      .fontSize(opts.size ?? 10)
      .fillColor(opts.muted ? COLORS.muted : COLORS.text)
      .text(text, MARGIN, undefined, { width: this.width, lineGap: 1.5 });
    this.doc.moveDown(0.4);
  }

  bullets(items: string[], tone?: keyof typeof COLORS) {
    const d = this.doc;
    for (const item of items) {
      this.ensure(16);
      const y = d.y;
      d.circle(MARGIN + 3, y + 5, 1.8).fill(tone ? COLORS[tone] : COLORS.accent);
      d.font(this.regular).fontSize(10).fillColor(COLORS.text).text(item, MARGIN + 12, y, { width: this.width - 12, lineGap: 1.5 });
      d.moveDown(0.25);
    }
    d.x = MARGIN;
    d.moveDown(0.2);
  }

  /** Riquadri con i numeri principali, tre per riga. */
  kpis(items: Kpi[]) {
    const d = this.doc;
    const perRow = 3;
    const gap = 10;
    const w = (this.width - gap * (perRow - 1)) / perRow;
    const h = 58;
    for (let i = 0; i < items.length; i += perRow) {
      this.ensure(h + gap);
      const y = d.y;
      items.slice(i, i + perRow).forEach((k, j) => {
        const x = MARGIN + j * (w + gap);
        d.roundedRect(x, y, w, h, 4).fill(COLORS.band);
        d.font(this.regular).fontSize(8).fillColor(COLORS.muted).text(k.label.toUpperCase(), x + 10, y + 9, { width: w - 20, characterSpacing: 0.4, lineBreak: false, ellipsis: true });
        d.font(this.bold).fontSize(17).fillColor(k.tone ? COLORS[k.tone] : COLORS.text).text(k.value, x + 10, y + 21, { width: w - 20, lineBreak: false, ellipsis: true });
        if (k.note) d.font(this.regular).fontSize(7.5).fillColor(COLORS.muted).text(k.note, x + 10, y + 42, { width: w - 20, lineBreak: false, ellipsis: true });
      });
      d.y = y + h + gap;
    }
    d.x = MARGIN;
    d.moveDown(0.3);
  }

  /** Tabella con intestazione ripetuta a ogni cambio pagina. */
  table(cols: Column[], rows: string[][], opts: { empty?: string; size?: number } = {}) {
    const d = this.doc;
    if (rows.length === 0) {
      this.p(opts.empty ?? "Nessun dato nel periodo.", { muted: true, size: 9 });
      return;
    }
    const size = opts.size ?? 8.5;
    const pad = 4;
    const widths = cols.map((c) => c.width * this.width);
    const header = () => {
      const y = d.y;
      d.rect(MARGIN, y, this.width, size + pad * 2 + 2).fill(COLORS.band);
      let x = MARGIN;
      cols.forEach((c, i) => {
        d.font(this.bold).fontSize(size - 0.5).fillColor(COLORS.muted).text(c.label, x + pad, y + pad + 1, { width: widths[i] - pad * 2, align: c.align ?? "left", lineBreak: false, ellipsis: true });
        x += widths[i];
      });
      d.y = y + size + pad * 2 + 2;
    };
    this.ensure(size * 4 + 20);
    header();
    for (const row of rows) {
      d.font(this.regular).fontSize(size);
      const h = Math.max(...row.map((cell, i) => d.heightOfString(cell || "—", { width: widths[i] - pad * 2 }))) + pad * 2;
      if (d.y + h > this.bottom) {
        d.addPage();
        header();
      }
      const y = d.y;
      let x = MARGIN;
      row.forEach((cell, i) => {
        d.font(this.regular).fontSize(size).fillColor(COLORS.text).text(cell || "—", x + pad, y + pad, { width: widths[i] - pad * 2, align: cols[i].align ?? "left" });
        x += widths[i];
      });
      d.y = y + h;
      d.moveTo(MARGIN, d.y).lineTo(MARGIN + this.width, d.y).lineWidth(0.4).strokeColor(COLORS.line).stroke();
    }
    d.x = MARGIN;
    d.moveDown(0.6);
  }

  /** Istogramma a barre impilate (per esempio allarmi al giorno per gravità). */
  bars(labels: string[], series: BarSeries[], format: (v: number) => string, height = 130) {
    const d = this.doc;
    this.ensure(height + 40);
    const top = d.y + 4;
    const left = MARGIN + 46;
    const w = this.width - 46;
    const totals = labels.map((_, i) => series.reduce((s, x) => s + (x.values[i] ?? 0), 0));
    const max = Math.max(1, ...totals);
    // tre linee guida con i valori
    for (const f of [0, 0.5, 1]) {
      const y = top + height - height * f;
      d.moveTo(left, y).lineTo(left + w, y).lineWidth(0.4).strokeColor(COLORS.line).stroke();
      d.font(this.regular).fontSize(7).fillColor(COLORS.muted).text(format(max * f), MARGIN, y - 4, { width: 42, align: "right", lineBreak: false });
    }
    const slot = w / Math.max(1, labels.length);
    const bw = Math.min(28, slot * 0.6);
    labels.forEach((label, i) => {
      let y = top + height;
      const x = left + i * slot + (slot - bw) / 2;
      for (const s of series) {
        const v = s.values[i] ?? 0;
        if (v <= 0) continue;
        const h = (v / max) * height;
        d.rect(x, y - h, bw, h).fill(s.color);
        y -= h;
      }
      d.font(this.regular).fontSize(7).fillColor(COLORS.muted).text(label, left + i * slot, top + height + 4, { width: slot, align: "center", lineBreak: false });
    });
    // legenda
    let lx = left;
    const ly = top + height + 18;
    for (const s of series) {
      d.rect(lx, ly + 1, 7, 7).fill(s.color);
      d.font(this.regular).fontSize(7.5).fillColor(COLORS.muted);
      const tw = d.widthOfString(s.label);
      d.text(s.label, lx + 10, ly, { lineBreak: false });
      lx += tw + 24;
    }
    d.x = MARGIN;
    d.y = ly + 18;
  }

  /** Righe da compilare a mano (firma, data...). */
  signature(labels: string[]) {
    const d = this.doc;
    this.ensure(30 * labels.length + 20);
    d.moveDown(1);
    for (const label of labels) {
      this.ensure(30);
      const y = d.y;
      d.font(this.regular).fontSize(9).fillColor(COLORS.muted).text(label, MARGIN, y);
      d.moveTo(MARGIN + 110, y + 10).lineTo(MARGIN + this.width, y + 10).lineWidth(0.5).strokeColor(COLORS.line).stroke();
      d.y = y + 28;
    }
    d.x = MARGIN;
  }

  /** Chiude il documento: piè di pagina su ogni pagina, poi il PDF completo. */
  async finish(): Promise<{ pdf: Buffer; pages: number }> {
    const d = this.doc;
    const range = d.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      d.switchToPage(i);
      const bottomMargin = d.page.margins.bottom;
      d.page.margins.bottom = 0; // scrivere nel margine non deve aggiungere pagine
      const y = d.page.height - MARGIN - 6;
      d.moveTo(MARGIN, y - 6).lineTo(MARGIN + this.width, y - 6).lineWidth(0.4).strokeColor(COLORS.line).stroke();
      d.font(this.regular).fontSize(7.5).fillColor(COLORS.muted);
      d.text(`Hyperwave · ${this.title} · ${this.footerNote}`, MARGIN, y, { width: this.width - 80, lineBreak: false, ellipsis: true });
      d.text(`Pagina ${i - range.start + 1} di ${range.count}`, MARGIN + this.width - 80, y, { width: 80, align: "right", lineBreak: false });
      d.page.margins.bottom = bottomMargin;
    }
    d.end();
    return { pdf: await this.done, pages: range.count };
  }
}
