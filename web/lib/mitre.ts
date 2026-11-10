// Tattiche MITRE ATT&CK nell'ordine della catena d'attacco, con le tecniche usate dalle regole.
// Servono a mostrare in che fase si trova un incidente.

export const TACTICS = [
  { id: "reconnaissance", label: "Ricognizione" },
  { id: "initial-access", label: "Accesso iniziale" },
  { id: "credential-access", label: "Furto di credenziali" },
  { id: "discovery", label: "Esplorazione della rete" },
  { id: "lateral-movement", label: "Movimento laterale" },
  { id: "command-and-control", label: "Comando e controllo" },
  { id: "exfiltration", label: "Esfiltrazione" },
] as const;

export type TacticId = (typeof TACTICS)[number]["id"];

const TECHNIQUES: Record<string, { tactic: TacticId; name: string }> = {
  T1595: { tactic: "reconnaissance", name: "Scansione attiva" },
  T1190: { tactic: "initial-access", name: "Sfruttamento di un servizio esposto" },
  T1133: { tactic: "initial-access", name: "Servizi remoti esterni" },
  T1110: { tactic: "credential-access", name: "Forza bruta" },
  T1040: { tactic: "credential-access", name: "Intercettazione del traffico" },
  T1557: { tactic: "credential-access", name: "Attacco man-in-the-middle" },
  T1558: { tactic: "credential-access", name: "Furto di ticket Kerberos" },
  T1046: { tactic: "discovery", name: "Ricerca dei servizi di rete" },
  T1018: { tactic: "discovery", name: "Ricerca degli host" },
  T1021: { tactic: "lateral-movement", name: "Servizi remoti" },
  T1071: { tactic: "command-and-control", name: "Protocollo applicativo" },
  T1090: { tactic: "command-and-control", name: "Proxy" },
  T1219: { tactic: "command-and-control", name: "Software di accesso remoto" },
  T1568: { tactic: "command-and-control", name: "Risoluzione dinamica" },
  T1572: { tactic: "command-and-control", name: "Tunnel di protocollo" },
  T1041: { tactic: "exfiltration", name: "Esfiltrazione sul canale di comando" },
  T1048: { tactic: "exfiltration", name: "Esfiltrazione su altro protocollo" },
};

/** Tattica e nome di una tecnica (anche sotto-tecnica, per esempio T1110.003). */
export function technique(id: string): { tactic: TacticId | null; name: string } {
  const t = TECHNIQUES[id.split(".")[0]];
  return t ?? { tactic: null, name: id };
}

export const tacticLabel = (id: TacticId | null) => TACTICS.find((t) => t.id === id)?.label ?? "Altro";

/** Fasi ATT&CK toccate da un insieme di tecniche, nell'ordine della catena. */
export function stages(techniques: string[]) {
  const hit = new Set(techniques.map((t) => technique(t).tactic));
  return TACTICS.filter((t) => hit.has(t.id));
}
