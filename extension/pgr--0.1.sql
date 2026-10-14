CREATE OR REPLACE FUNCTION pgr.cstart() RETURNS boolean
AS 'MODULE_PATHNAME', 'sql_capture_start'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.cstop() RETURNS boolean
AS 'MODULE_PATHNAME', 'sql_capture_stop'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.tstart() RETURNS boolean
AS 'MODULE_PATHNAME', 'sql_trace_start'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.tstop() RETURNS boolean
AS 'MODULE_PATHNAME', 'sql_trace_stop'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.getstats(
    OUT commits bigint,
    OUT rollbacks bigint,
    OUT failed_commits bigint
)
AS 'MODULE_PATHNAME', 'sql_get_stats'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.resetstats()
RETURNS void
AS 'MODULE_PATHNAME', 'sql_reset_stats'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE TABLE pgr.temp_backups (
    owner       name NOT NULL DEFAULT current_user,
    backup_name text NOT NULL,
    table_name  text NOT NULL,
    columns_ddl text NOT NULL,
    post_ddl    text[] NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, backup_name, table_name)
);

ALTER TABLE pgr.temp_backups ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_rows ON pgr.temp_backups
    USING (owner = current_user)
    WITH CHECK (owner = current_user);

GRANT USAGE ON SCHEMA pgr TO PUBLIC;
GRANT SELECT, INSERT, DELETE ON pgr.temp_backups TO PUBLIC;

CREATE FUNCTION pgr.store_name(p_name text, p_table text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT 'b_' || md5(session_user || '/' || p_name || '/' || p_table)
$$;

CREATE FUNCTION pgr.write_snapshot(p_name text, p_table text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_store text := pgr.store_name(p_name, p_table);
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class
        WHERE relnamespace = pg_my_temp_schema() AND relname = p_table AND relkind = 'r'
    ) THEN
        RAISE EXCEPTION 'no temp table %', p_table;
    END IF;
    EXECUTE format('DROP TABLE IF EXISTS pgr.%I', v_store);
    EXECUTE format('CREATE UNLOGGED TABLE pgr.%I AS SELECT * FROM pg_temp.%I', v_store, p_table);
END $$;

CREATE FUNCTION pgr.read_snapshot(p_name text, p_table text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    EXECUTE format('INSERT INTO pg_temp.%I SELECT * FROM pgr.%I',
                   p_table, pgr.store_name(p_name, p_table));
END $$;

CREATE FUNCTION pgr.tbackup(p_name text) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    r record;
    n int := 0;
    v_cols text;
    v_post text[];
BEGIN
    DELETE FROM pgr.temp_backups WHERE backup_name = p_name;

    FOR r IN
        SELECT c.oid, c.relname
        FROM pg_class c
        WHERE c.relnamespace = pg_my_temp_schema()
          AND c.relkind = 'r'
        ORDER BY c.relname
    LOOP
        SELECT string_agg(
                   format('%I %s%s%s',
                          a.attname,
                          format_type(a.atttypid, a.atttypmod),
                          CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END,
                          coalesce(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), '')),
                   ', ' ORDER BY a.attnum)
        INTO v_cols
        FROM pg_attribute a
        LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped;

        SELECT coalesce(array_agg(s.ddl ORDER BY s.ord, s.ddl), '{}')
        INTO v_post
        FROM (
            SELECT 1 AS ord,
                   format('ALTER TABLE pg_temp.%I ADD CONSTRAINT %I %s',
                          r.relname, k.conname, pg_get_constraintdef(k.oid)) AS ddl
            FROM pg_constraint k
            WHERE k.conrelid = r.oid AND k.contype IN ('p', 'u', 'c')
            UNION ALL
            SELECT 2,
                   regexp_replace(pg_get_indexdef(i.indexrelid),
                                  ' ON (ONLY )?pg_temp_[0-9]+\.', ' ON pg_temp.')
            FROM pg_index i
            WHERE i.indrelid = r.oid
              AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = i.indexrelid)
        ) s;

        PERFORM pgr.write_snapshot(p_name, r.relname);

        INSERT INTO pgr.temp_backups (backup_name, table_name, columns_ddl, post_ddl)
        VALUES (p_name, r.relname, v_cols, v_post);

        n := n + 1;
    END LOOP;

    RETURN n;
END $$;

CREATE FUNCTION pgr.trestore(p_name text, p_replace boolean DEFAULT false) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    r pgr.temp_backups;
    n int := 0;
    stmt text;
BEGIN
    FOR r IN
        SELECT * FROM pgr.temp_backups
        WHERE backup_name = p_name
        ORDER BY table_name
    LOOP
        IF to_regclass('pg_temp.' || quote_ident(r.table_name)) IS NOT NULL THEN
            IF p_replace THEN
                EXECUTE format('DROP TABLE pg_temp.%I', r.table_name);
            ELSE
                RAISE EXCEPTION 'temp table % already exists', r.table_name;
            END IF;
        END IF;

        EXECUTE format('CREATE TEMP TABLE %I (%s)', r.table_name, r.columns_ddl);

        PERFORM pgr.read_snapshot(p_name, r.table_name);

        FOREACH stmt IN ARRAY r.post_ddl LOOP
            EXECUTE stmt;
        END LOOP;

        n := n + 1;
    END LOOP;

    RETURN n;
END $$;

CREATE FUNCTION pgr.tdrop(p_name text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT table_name FROM pgr.temp_backups
        WHERE owner = session_user AND backup_name = p_name
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS pgr.%I', pgr.store_name(p_name, r.table_name));
    END LOOP;
    DELETE FROM pgr.temp_backups WHERE owner = session_user AND backup_name = p_name;
END $$;
