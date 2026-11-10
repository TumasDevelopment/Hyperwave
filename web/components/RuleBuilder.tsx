"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState, useTransition } from "react";
import { saveCustomRule, testCustomRule } from "@/lib/actions/customrules";
import { emptySpec, type CustomRuleInput, type RuleSchema, type RuleSpec, type RuleTestResult } from "@/lib/customrules";
import { SEVERITIES, SEVERITY_LABELS } from "@/lib/labels";

type Cond = { field: string; op: string; raw: string };

const HOURS = [
  [1, "ultima ora"],
  [6, "ultime 6 ore"],
  [24, "ultime 24 ore"],
  [72, "ultimi 3 giorni"],
  [168, "ultimi 7 giorni"],
] as const;

/** Costruttore guidato delle regole personalizzate: niente SQL, solo scelte da elenchi. */
export function RuleBuilder({ schema, initial, canEdit }: { schema: RuleSchema; initial?: CustomRuleInput; canEdit: boolean }) {
  const router = useRouter();
  const start = initial?.spec ?? emptySpec(schema.sources[0]?.id);
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [severity, setSeverity] = useState(initial?.severity ?? "medium");
  const [mitre, setMitre] = useState(initial?.mitre ?? "");
  const [source, setSource] = useState(start.source);
  const [conds, setConds] = useState<Cond[]>(start.where.map((w) => ({ field: w.field, op: w.op, raw: w.value.join("\n") })));
  const [groups, setGroups] = useState<string[]>(start.group_by);
  const [metric, setMetric] = useState<RuleSpec["metric"]>(start.metric);
  const [metricField, setMetricField] = useState(start.metric_field);
  const [threshold, setThreshold] = useState(String(start.threshold));
  const [windowMin, setWindowMin] = useState(String(start.window_min));
  const [everyMin, setEveryMin] = useState(String(start.every_min || ""));
  const [hours, setHours] = useState(24);
  const [test, setTest] = useState<RuleTestResult | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, startTest] = useTransition();
  const [saving, startSave] = useTransition();

  const src = schema.sources.find((s) => s.id === source) ?? schema.sources[0];
  const fieldOf = (id: string) => src.fields.find((f) => f.id === id);
  const opsOf = (id: string) => schema.ops[fieldOf(id)?.kind ?? "str"] ?? [];

  function spec(): RuleSpec {
    return {
      source,
      where: conds.map((c) => {
        const op = opsOf(c.field).find((o) => o.id === c.op);
        const value = !op?.values ? [] : op.values === "one" ? [c.raw.trim()] : c.raw.split(/[\n,]+/).map((v) => v.trim()).filter(Boolean);
        return { field: c.field, op: c.op, value };
      }),
      group_by: groups.filter(Boolean),
      metric,
      metric_field: metric === "count" ? "" : metricField,
      threshold: Number(threshold.replace(",", ".")),
      window_min: Number(windowMin),
      every_min: Number(everyMin || 0),
    };
  }

  function changeSource(id: string) {
    setSource(id);
    setConds([]);
    setGroups([]);
    setMetricField("");
    setTest(null);
  }

  function addCond() {
    const f = src.fields[0];
    setConds([...conds, { field: f.id, op: schema.ops[f.kind][0].id, raw: "" }]);
  }

  function updateCond(i: number, patch: Partial<Cond>) {
    setConds(
      conds.map((c, j) => {
        if (j !== i) return c;
        const next = { ...c, ...patch };
        // cambiando campo, l'operatore deve esistere per il nuovo tipo
        if (patch.field && !opsOf(patch.field).some((o) => o.id === next.op)) next.op = opsOf(patch.field)[0]?.id ?? "";
        return next;
      }),
    );
  }

  const sentence = useMemo(() => {
    const g = groups.filter(Boolean).map((id) => fieldOf(id)?.label ?? id);
    const what =
      metric === "count"
        ? "il numero di record"
        : metric === "uniq"
          ? `il numero di valori diversi di «${fieldOf(metricField)?.label ?? "…"}»`
          : `la somma di «${fieldOf(metricField)?.label ?? "…"}»`;
    return `Allarme quando, in ${windowMin || "…"} minuti${g.length ? `, per ogni combinazione di ${g.join(" · ")}` : ""}, ${what} tra ${src.label.toLowerCase()}${conds.length ? " che rispettano tutte le condizioni" : ""} è almeno ${threshold || "…"}.`;
  }, [groups, metric, metricField, windowMin, threshold, src, conds.length]);

  function runTest() {
    setMessage(null);
    startTest(async () => setTest(await testCustomRule(spec(), hours)));
  }

  function save() {
    setMessage(null);
    startSave(async () => {
      const res = await saveCustomRule({ id: initial?.id, name, description, severity, mitre, spec: spec() });
      if (res.ok && res.id) {
        setMessage({ ok: true, text: "Regola salvata: l'hub la usa dal prossimo giro." });
        if (!initial?.id) router.push(`/regole/personalizzate/${res.id}`);
        else router.refresh();
      } else setMessage({ ok: false, text: res.error ?? "Salvataggio non riuscito." });
    });
  }

  const numFields = src.fields.filter((f) => f.kind === "num");
  const disabled = !canEdit;

  return (
    <div className="stack">
      <section className="card">
        <div className="card__head">
          <h2>Descrizione</h2>
        </div>
        <div className="form-grid">
          <label className="field">
            <span className="field__label">Nome</span>
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={120} disabled={disabled} />
          </label>
          <label className="field">
            <span className="field__label">Gravità</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} disabled={disabled}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span className="field__label">Tecnica MITRE ATT&amp;CK</span>
            <input value={mitre} onChange={(e) => setMitre(e.target.value)} placeholder="T1046" maxLength={20} disabled={disabled} />
            <span className="field__hint">Facoltativa.</span>
          </label>
          <label className="field field--wide">
            <span className="field__label">Descrizione</span>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} maxLength={1000} disabled={disabled} />
            <span className="field__hint">Compare nell&apos;elenco delle regole: spiega cosa cerca e perché.</span>
          </label>
        </div>
      </section>

      <section className="card">
        <div className="card__head">
          <h2>Cosa cercare</h2>
        </div>
        <div className="form-grid">
          <label className="field field--wide">
            <span className="field__label">Dati da analizzare</span>
            <select value={source} onChange={(e) => changeSource(e.target.value)} disabled={disabled}>
              {schema.sources.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <h3 className="mt">Condizioni</h3>
        <p className="muted small">Devono essere vere tutte. Senza condizioni la regola considera tutti i record.</p>
        <div className="stack">
          {conds.map((c, i) => {
            const op = opsOf(c.field).find((o) => o.id === c.op);
            const kind = fieldOf(c.field)?.kind;
            return (
              <div key={i} className="row rule-cond">
                <select value={c.field} onChange={(e) => updateCond(i, { field: e.target.value })} aria-label="Campo" disabled={disabled}>
                  {src.fields.map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.label}
                    </option>
                  ))}
                </select>
                <select value={c.op} onChange={(e) => updateCond(i, { op: e.target.value })} aria-label="Operatore" disabled={disabled}>
                  {opsOf(c.field).map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.label}
                    </option>
                  ))}
                </select>
                {op?.values === "one" && (
                  <input
                    value={c.raw}
                    onChange={(e) => updateCond(i, { raw: e.target.value })}
                    aria-label="Valore"
                    className="grow"
                    inputMode={kind === "num" ? "decimal" : undefined}
                    placeholder={kind === "ip" ? "198.51.100.7" : kind === "num" ? "0" : "valore"}
                    disabled={disabled}
                  />
                )}
                {op?.values === "list" && (
                  <textarea
                    value={c.raw}
                    onChange={(e) => updateCond(i, { raw: e.target.value })}
                    aria-label="Valori"
                    className="grow"
                    rows={2}
                    placeholder={kind === "ip" ? "Reti o indirizzi, uno per riga o separati da virgole" : "Valori, uno per riga o separati da virgole"}
                    disabled={disabled}
                  />
                )}
                {canEdit && (
                  <button type="button" className="btn btn--small btn--ghost" onClick={() => setConds(conds.filter((_, j) => j !== i))}>
                    Togli
                  </button>
                )}
              </div>
            );
          })}
        </div>
        {canEdit && conds.length < schema.max_conds && (
          <button type="button" className="btn btn--small mt" onClick={addCond}>
            Aggiungi condizione
          </button>
        )}

        <h3 className="mt">Soglia</h3>
        <div className="form-grid">
          {Array.from({ length: schema.max_groups }, (_, i) => (
            <label key={i} className="field">
              <span className="field__label">{i === 0 ? "Raggruppa per" : "e per"}</span>
              <select
                value={groups[i] ?? ""}
                onChange={(e) => {
                  const next = [...groups];
                  next[i] = e.target.value;
                  setGroups(next.slice(0, schema.max_groups));
                }}
                disabled={disabled || (i > 0 && !groups[i - 1])}
              >
                <option value="">{i === 0 ? "Nessun raggruppamento (tutto insieme)" : "—"}</option>
                {src.fields.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.label}
                  </option>
                ))}
              </select>
            </label>
          ))}
          <label className="field">
            <span className="field__label">Misura</span>
            <select value={metric} onChange={(e) => setMetric(e.target.value as RuleSpec["metric"])} disabled={disabled}>
              <option value="count">Numero di record</option>
              <option value="uniq">Valori diversi di un campo</option>
              <option value="sum">Somma di un campo numerico</option>
            </select>
          </label>
          {metric !== "count" && (
            <label className="field">
              <span className="field__label">Campo</span>
              <select value={metricField} onChange={(e) => setMetricField(e.target.value)} disabled={disabled}>
                <option value="">Scegli…</option>
                {(metric === "sum" ? numFields : src.fields).map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.label}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="field">
            <span className="field__label">Almeno</span>
            <input value={threshold} onChange={(e) => setThreshold(e.target.value)} inputMode="decimal" disabled={disabled} />
            {metric === "sum" && fieldOf(metricField)?.id.startsWith("bytes") && <span className="field__hint">In byte: 1048576 = 1 MB.</span>}
          </label>
          <label className="field">
            <span className="field__label">Finestra (minuti)</span>
            <input value={windowMin} onChange={(e) => setWindowMin(e.target.value)} inputMode="numeric" disabled={disabled} />
            <span className="field__hint">Da 1 a 1440.</span>
          </label>
          <label className="field">
            <span className="field__label">Controlla ogni (minuti)</span>
            <input value={everyMin} onChange={(e) => setEveryMin(e.target.value)} inputMode="numeric" placeholder="automatico" disabled={disabled} />
            <span className="field__hint">Vuoto: la finestra, al massimo 5.</span>
          </label>
        </div>
        <p className="rule-sentence mt">{sentence}</p>
      </section>

      {canEdit && (
        <section className="card">
          <div className="row">
            <button type="button" className="btn btn--primary" onClick={save} disabled={saving || testing}>
              {saving ? "Salvataggio…" : initial?.id ? "Salva le modifiche" : "Crea la regola"}
            </button>
            <span className="muted small">oppure</span>
            <select value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Periodo della prova">
              {HOURS.map(([h, l]) => (
                <option key={h} value={h}>
                  {l}
                </option>
              ))}
            </select>
            <button type="button" className="btn" onClick={runTest} disabled={testing || saving}>
              {testing ? "Prova in corso…" : "Prova sullo storico"}
            </button>
          </div>
          {message && (
            <div className={`notice ${message.ok ? "notice--ok" : "notice--error"} mt`} role={message.ok ? "status" : "alert"}>
              {message.text}
            </div>
          )}
          {test && <TestResult test={test} />}
        </section>
      )}
    </div>
  );
}

function TestResult({ test }: { test: RuleTestResult }) {
  if (!test.ok)
    return (
      <div className="notice notice--error mt" role="alert">
        {test.error}
      </div>
    );
  const cols = test.columns ?? [];
  return (
    <div className="mt">
      <p>
        {test.windows === 0 ? (
          <strong>Nessun allarme nel periodo scelto.</strong>
        ) : (
          <>
            <strong>
              {test.more ? "Più di " : ""}
              {test.windows} {test.windows === 1 ? "finestra" : "finestre"}
            </strong>{" "}
            avrebbero dato un allarme{cols.length > 0 && `, per ${test.groups} ${test.groups === 1 ? "combinazione diversa" : "combinazioni diverse"}`}.
          </>
        )}{" "}
        <span className="muted small">Query eseguita in {test.ms} ms; le finestre della prova sono consecutive, nel motore scorrono.</span>
      </p>
      {test.rows && test.rows.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Finestra</th>
                {cols.map((c) => (
                  <th key={c}>{c}</th>
                ))}
                <th className="num">Valore</th>
                <th className="num">Record</th>
              </tr>
            </thead>
            <tbody>
              {test.rows.map((r, i) => (
                <tr key={i}>
                  <td className="small mono">{r.bucket.slice(0, 16)} UTC</td>
                  {r.groups.map((g, j) => (
                    <td key={j} className="mono">
                      {g || "—"}
                    </td>
                  ))}
                  <td className="num">{r.value}</td>
                  <td className="num">{r.n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {test.sql && (
        <details className="mt">
          <summary className="muted small">Query generata (i valori viaggiano come parametri)</summary>
          <pre className="small">{test.sql}</pre>
        </details>
      )}
    </div>
  );
}
