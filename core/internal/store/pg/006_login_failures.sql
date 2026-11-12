-- Tentativi di accesso non riusciti, condivisi tra tutte le istanze dell'interfaccia
-- e conservati ai riavvii. key è "u:<indirizzo>:<utente>" oppure "a:<indirizzo>".
-- Le righe scadute le cancella l'hub nella pulizia oraria.

CREATE TABLE login_failures (
    key      text PRIMARY KEY,
    count    integer NOT NULL,
    reset_at timestamptz NOT NULL
);

CREATE INDEX login_failures_reset ON login_failures (reset_at);
