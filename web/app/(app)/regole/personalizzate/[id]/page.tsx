import Link from "next/link";
import { notFound } from "next/navigation";
import { ActionForm, ConfirmSubmit } from "@/components/forms";
import { RuleBuilder } from "@/components/RuleBuilder";
import { Badge, Card, Empty, PageHead } from "@/components/ui";
import { deleteCustomRule } from "@/lib/actions/customrules";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtDateTime, fmtNum } from "@/lib/format";
import { getCustomRule, ruleSchema } from "@/lib/queries/customrules";

export const metadata = { title: "Regola personalizzata" };

type Props = { params: Promise<{ id: string }> };

export default async function CustomRulePage({ params }: Props) {
  const user = await requireUser();
  const { id: raw } = await params;
  const admin = can(user, "admin");
  const isNew = raw === "nuova";
  const id = Number(raw);
  if (!isNew && (!Number.isSafeInteger(id) || id <= 0)) notFound();
  if (isNew && !admin) notFound();
  const [schema, rule] = await Promise.all([ruleSchema(), isNew ? Promise.resolve(null) : getCustomRule(id)]);
  if (!isNew && !rule) notFound();
  const now = Date.now();

  return (
    <>
      <PageHead
        title={rule ? rule.name : "Nuova regola personalizzata"}
        sub={
          <>
            <Link href="/regole">Regole</Link> · scegli i dati, le condizioni e la soglia: l&apos;hub la traduce in una query di sola lettura e
            la esegue come le regole predefinite.
          </>
        }
      />
      {rule && (
        <div className="row mb">
          {rule.enabled ? <Badge tone="ok">Attiva</Badge> : <Badge>Spenta</Badge>}
          {rule.last_error ? (
            <Badge tone="bad">Errore: {rule.last_error}</Badge>
          ) : rule.last_run ? (
            <span className="muted small" title={fmtDateTime(rule.last_run)}>
              Ultimo controllo {fmtAgo(rule.last_run, now)}: {fmtNum(rule.last_hits)} allarmi
            </span>
          ) : (
            <span className="muted small">Non ancora eseguita (il motore gira solo con il live acceso).</span>
          )}
          <Link href={`/allarmi?status=all&rule=custom:${rule.id}&days=30`} className="small">
            {fmtNum(rule.alerts_30d)} allarmi in 30 giorni
          </Link>
          <span className="muted small">
            Creata da {rule.created_by} il {fmtDateTime(rule.created_at)}
            {rule.updated_by && ` · modificata da ${rule.updated_by} ${fmtAgo(rule.updated_at, now)}`}
          </span>
        </div>
      )}
      {!schema ? (
        <Empty>L&apos;elenco dei campi arriva dall&apos;hub al suo avvio: controlla che sia attivo.</Empty>
      ) : (
        <RuleBuilder schema={schema} initial={rule ?? undefined} canEdit={admin} />
      )}
      {rule && admin && (
        <Card title="Altre azioni" className="mt">
          <p className="muted small">
            Accensione e gravità si cambiano anche dall&apos;elenco delle regole. Eliminando la regola gli allarmi già aperti restano.
          </p>
          <ActionForm action={deleteCustomRule} className="row">
            <input type="hidden" name="id" value={rule.id} />
            <ConfirmSubmit label="Elimina la regola" confirmLabel="Conferma eliminazione" />
          </ActionForm>
        </Card>
      )}
    </>
  );
}
