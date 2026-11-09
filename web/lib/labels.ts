// Etichette e colori condivisi.

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critica",
  high: "Alta",
  medium: "Media",
  low: "Bassa",
  info: "Info",
};

export const STATUS_LABELS: Record<string, string> = {
  open: "Aperto",
  ack: "In carico",
  resolved: "Risolto",
};

export const RESOLUTIONS: Record<string, string> = {
  true_positive: "Minaccia confermata e gestita",
  benign: "Attività legittima",
  false_positive: "Falso positivo",
  duplicate: "Duplicato",
  other: "Altro",
};

export const CRITICALITY_LABELS: Record<string, string> = {
  low: "Bassa",
  normal: "Normale",
  high: "Alta",
  critical: "Critica",
};

export const DIRECTION_LABELS: Record<string, string> = {
  outbound: "Verso internet",
  inbound: "Da internet",
  internal: "Interno",
  external: "Esterno",
};

/** Colori delle serie: entrata, uscita, interno. Uguali in tutte le pagine. */
export const SERIES_COLORS = {
  in: "#22d3ee",
  out: "#a78bfa",
  internal: "#34d399",
  other: "#f59e0b",
};

export const PALETTE = ["#22d3ee", "#a78bfa", "#34d399", "#f59e0b", "#f472b6", "#60a5fa", "#fb7185", "#a3e635", "#2dd4bf", "#c084fc"];

export const mitreUrl = (id: string) =>
  /^T\d{4}(\.\d{3})?$/.test(id) ? `https://attack.mitre.org/techniques/${id.replace(".", "/")}/` : null;
