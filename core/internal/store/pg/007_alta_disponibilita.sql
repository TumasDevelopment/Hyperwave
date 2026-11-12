-- Più istanze dell'hub: lo stato che il motore deve conoscere sta qui e non nella memoria
-- dell'istanza che riceve i dati. backfill_marks segue lo storico che i sensori stanno
-- ancora inviando (ts = dato più recente ricevuto, in ms): il motore non analizza oltre.

CREATE TABLE backfill_marks (
    sensor_id bigint PRIMARY KEY REFERENCES sensors ON DELETE CASCADE,
    ts        bigint NOT NULL,
    at        timestamptz NOT NULL DEFAULT now()
);
