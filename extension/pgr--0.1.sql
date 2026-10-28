CREATE OR REPLACE FUNCTION pgr.cstart() RETURNS int
AS 'MODULE_PATHNAME', 'sql_capture_start'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.cstop() RETURNS boolean
AS 'MODULE_PATHNAME', 'sql_capture_stop'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.tstart() RETURNS int
AS 'MODULE_PATHNAME', 'sql_trace_start'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.tstop() RETURNS boolean
AS 'MODULE_PATHNAME', 'sql_trace_stop'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.timestart() RETURNS int
AS 'MODULE_PATHNAME', 'sql_time_start'
LANGUAGE C STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pgr.timestop() RETURNS boolean
AS 'MODULE_PATHNAME', 'sql_time_stop'
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

CREATE OR REPLACE FUNCTION pgr.sdump(p_name text) RETURNS int
AS 'MODULE_PATHNAME', 'sql_session_dump'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION pgr.srestore(p_name text) RETURNS int
AS 'MODULE_PATHNAME', 'sql_session_restore'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION pgr.sdebug(debug_enabled boolean) RETURNS void
AS 'MODULE_PATHNAME', 'sql_session_debug'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION pgr.ttdescribe(p_relids oid[] DEFAULT NULL)
RETURNS TABLE(relid oid, table_name text, columns_ddl text, post_ddl text)
LANGUAGE plpgsql AS $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.oid, c.relname
        FROM pg_class c
        WHERE c.relnamespace = pg_my_temp_schema()
          AND c.relkind = 'r'
          AND (p_relids IS NULL OR c.oid = ANY(p_relids))
        ORDER BY c.relname
    LOOP
        relid := r.oid;
        table_name := r.relname;

        SELECT string_agg(
                   format('%I %s%s%s',
                          a.attname,
                          format_type(a.atttypid, a.atttypmod),
                          CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END,
                          coalesce(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), '')),
                   ', ' ORDER BY a.attnum)
        INTO columns_ddl
        FROM pg_attribute a
        LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped;

        SELECT coalesce(string_agg(s.ddl, ';' ORDER BY s.ord, s.ddl), '')
        INTO post_ddl
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

        RETURN NEXT;
    END LOOP;
END $$;
