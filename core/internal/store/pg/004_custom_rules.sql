-- Regole personalizzate: scritte dagli amministratori con il costruttore della pagina Regole.
-- spec è la definizione strutturata (sorgente, condizioni, raggruppamento, soglia, finestra):
-- l'hub la traduce in una query di sola lettura con parametri. Abilitazione e gravità
-- modificata stanno, come per le altre regole, nella tabella rules con id 'custom:<id>'.

CREATE TABLE custom_rules (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE CHECK (length(name) BETWEEN 2 AND 120),
    description text NOT NULL DEFAULT '',
    severity    text NOT NULL DEFAULT 'medium' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    mitre       text NOT NULL DEFAULT '',
    spec        jsonb NOT NULL,
    created_by  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    last_run    timestamptz,
    last_error  text NOT NULL DEFAULT '',
    last_hits   integer NOT NULL DEFAULT 0
);
