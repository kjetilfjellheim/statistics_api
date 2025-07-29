ALTER TABLE IF EXISTS public.data
    ADD CONSTRAINT uq_data UNIQUE (id_municipality, id_statistic, year);

CREATE SEQUENCE IF NOT EXISTS public.data_id_seq
    INCREMENT 1
    START 1
    MINVALUE 1
    MAXVALUE 9223372036854775807
    CACHE 1;

ALTER SEQUENCE public.data_id_seq
    OWNER TO postgres;