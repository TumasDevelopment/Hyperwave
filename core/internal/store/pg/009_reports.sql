-- Rapporti PDF: generati dal sito (a richiesta o con la pianificazione settimanale) e conservati qui,
-- così ogni istanza del sito li vede e li può scaricare.
CREATE TABLE IF NOT EXISTS reports (
    id           bigserial PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('executive', 'technical', 'compliance')),
    period_from  timestamptz NOT NULL,
    period_to    timestamptz NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'failed')),
    scheduled    boolean NOT NULL DEFAULT false,
    requested_by text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    pages        integer NOT NULL DEFAULT 0,
    bytes        bigint NOT NULL DEFAULT 0,
    sha256       text NOT NULL DEFAULT '',
    error        text NOT NULL DEFAULT '',
    pdf          bytea
);

-- la pianificazione crea un solo rapporto per tipo e settimana anche con più istanze del sito
CREATE UNIQUE INDEX IF NOT EXISTS reports_scheduled_once ON reports (kind, period_from) WHERE scheduled;
CREATE INDEX IF NOT EXISTS reports_created ON reports (created_at DESC);
CREATE INDEX IF NOT EXISTS reports_pending ON reports (created_at) WHERE status = 'pending';

-- tipi generati ogni lunedì per la settimana precedente (Impostazioni → Generale)
INSERT INTO settings (key, value) VALUES ('report_schedule', '["executive"]') ON CONFLICT (key) DO NOTHING;
