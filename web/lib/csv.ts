// CSV per Excel in italiano: separatore punto e virgola, BOM UTF-8, valori sempre tra virgolette.
// Le celle che iniziano con = + - @ vengono precedute da un apostrofo: niente formule eseguite all'apertura.

export function csvCell(value: unknown) {
  let text = value === null || value === undefined ? "" : value instanceof Date ? value.toISOString() : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export function toCsv(header: string[], rows: unknown[][]) {
  return `﻿${[header, ...rows].map((row) => row.map(csvCell).join(";")).join("\r\n")}\r\n`;
}

export function csvResponse(name: string, body: string) {
  return new Response(body, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${name}"`,
      "Cache-Control": "no-store",
    },
  });
}

export const stamp = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
