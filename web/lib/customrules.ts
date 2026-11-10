// Tipi condivisi tra pagina, costruttore e azioni delle regole personalizzate.
// Sorgenti, campi e operatori li decide l'hub (internal/hub/custom.go) e li scrive in settings.

export type FieldKind = "str" | "ip" | "num";

export interface RuleSchema {
  sources: { id: string; label: string; fields: { id: string; label: string; kind: FieldKind }[] }[];
  ops: Record<FieldKind, { id: string; label: string; values: "" | "one" | "list" }[]>;
  max_conds: number;
  max_groups: number;
}

export interface RuleSpec {
  source: string;
  where: { field: string; op: string; value: string[] }[];
  group_by: string[];
  metric: "count" | "uniq" | "sum";
  metric_field: string;
  threshold: number;
  window_min: number;
  every_min: number;
}

export interface CustomRuleInput {
  id?: number;
  name: string;
  description: string;
  severity: string;
  mitre: string;
  spec: RuleSpec;
}

export interface RuleTestResult {
  ok: boolean;
  error?: string;
  sql?: string;
  rows?: { bucket: string; groups: string[]; value: string; n: number }[];
  windows: number;
  groups: number;
  more: boolean;
  ms: number;
  columns?: string[];
}

export const emptySpec = (source = "flows"): RuleSpec => ({
  source,
  where: [],
  group_by: [],
  metric: "count",
  metric_field: "",
  threshold: 10,
  window_min: 5,
  every_min: 0,
});
