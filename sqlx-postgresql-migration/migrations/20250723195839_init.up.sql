-- Add up migration script here

CREATE TABLE IF NOT EXISTS public.municipality
(
    id bigint NOT NULL,
    name character varying(200) COLLATE pg_catalog."default" NOT NULL,
    inserted_by character varying(200) COLLATE pg_catalog."default",
    inserted_at timestamp with time zone,
    CONSTRAINT municipality_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.municipality
    OWNER to postgres;

GRANT ALL ON TABLE public.municipality TO postgres;

CREATE TABLE IF NOT EXISTS public.statistics
(
    id bigint NOT NULL,
    name character varying(200) COLLATE pg_catalog."default" NOT NULL,
    inserted_by character varying(200) COLLATE pg_catalog."default",
    inserted_at timestamp with time zone,
    CONSTRAINT statistics_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.statistics
    OWNER to postgres;

GRANT ALL ON TABLE public.statistics TO postgres;

CREATE TABLE IF NOT EXISTS public.data
(
    id bigint NOT NULL,
    id_municipality bigint,
    id_statistic bigint,
    value numeric(12,2),
    year bigint,
    updated_by character varying(200) COLLATE pg_catalog."default",
    inserted_by character varying(200) COLLATE pg_catalog."default",
    updated_at timestamp with time zone,
    inserted_at timestamp with time zone,
    CONSTRAINT data_pkey PRIMARY KEY (id),
    CONSTRAINT fk_municipality FOREIGN KEY (id_municipality)
        REFERENCES public.municipality (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    CONSTRAINT fk_statistic FOREIGN KEY (id_statistic)
        REFERENCES public.statistics (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.data
    OWNER to postgres;

GRANT ALL ON TABLE public.data TO postgres;
