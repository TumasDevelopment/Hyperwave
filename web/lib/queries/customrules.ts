import "server-only";
import type { CustomRuleInput, RuleSchema } from "../customrules";
import { db, setting } from "../db";

export async function ruleSchema(): Promise<RuleSchema | null> {
  const schema = await setting<RuleSchema | null>("custom_rule_schema", null);
  return schema && Array.isArray(schema.sources) ? schema : null;
}

export interface CustomRuleRow extends CustomRuleInput {
  id: number;
  created_by: string;
  created_at: Date;
  updated_by: string;
  updated_at: Date;
  last_run: Date | null;
  last_error: string;
  last_hits: number;
  enabled: boolean;
  alerts_30d: number;
}

export async function getCustomRule(id: number): Promise<CustomRuleRow | null> {
  const { rows } = await db().query<CustomRuleRow>(
    `SELECT c.id::int AS id, c.name, c.description, c.severity, c.mitre, c.spec, c.created_by, c.created_at, c.updated_by, c.updated_at,
            c.last_run, c.last_error, c.last_hits, coalesce(r.enabled, true) AS enabled,
            (SELECT count(*)::int FROM alerts a WHERE a.rule = 'custom:' || c.id AND a.first_seen > now() - interval '30 days') AS alerts_30d
     FROM custom_rules c LEFT JOIN rules r ON r.id = 'custom:' || c.id WHERE c.id = $1`,
    [id],
  );
  return rows[0] ?? null;
}
