#include "pgr.h"

#include "access/table.h"
#include "access/xact.h"
#include "commands/copy.h"
#include "commands/prepare.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "parser/parse_node.h"
#include "parser/parse_relation.h"
#include "parser/parsetree.h"
#include "storage/fd.h"
#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/guc_tables.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/plancache.h"
#include "utils/snapmgr.h"

#define SQL_ALL                                                                \
  "SELECT relid, table_name, columns_ddl, post_ddl FROM pgr.ttdescribe()"

enum { SessGucs = 1, SessPrepared, SessTable, SessDropAll };

static FILE *SessionFile = NULL;
static char SessionPath[MAXPGPATH];
static FILE *ReadFile = NULL;
static uint64 ReadLeft = 0;
static StringInfoData LastGucs;
static StringInfoData LastPrep;
static bool LastInit = false;
static bool SchemaDirty = false;
static List *DirtyRels = NIL;

PG_FUNCTION_INFO_V1(sql_session_dump);
PG_FUNCTION_INFO_V1(sql_session_restore);

static void session_path(const char *name, char *path) {
  size_t n = strlen(name);
  if (n == 0 || n > 200)
    ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                    errmsg("pgr: invalid session name")));
  for (const char *p = name; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-')
      ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                      errmsg("pgr: invalid session name")));
  }
  snprintf(path, MAXPGPATH, "sessions/%s.pgsession", name);
}

static void wr(const void *p, size_t n) {
  if (fwrite(p, 1, n, SessionFile) != n)
    ereport(ERROR,
            (errcode_for_file_access(), errmsg("pgr: write failed: %m")));
}

static void wr_u32(uint32 v) { wr(&v, sizeof(v)); }

static void wr_str(const char *s) {
  uint32 n = s ? (uint32)strlen(s) : 0;
  wr_u32(n);
  if (n)
    wr(s, n);
}

static void put_rec(uint8 type, StringInfo b) {
  uint64 len = b ? (uint64)b->len : 0;
  wr(&type, sizeof(type));
  wr(&len, sizeof(len));
  if (len)
    wr(b->data, len);
  fflush(SessionFile);
}

static void sb_raw(StringInfo b, const void *p, size_t n) {
  appendBinaryStringInfo(b, p, n);
}
static void sb_u8(StringInfo b, uint8 v) { sb_raw(b, &v, sizeof(v)); }
static void sb_u16(StringInfo b, uint16 v) { sb_raw(b, &v, sizeof(v)); }
static void sb_u32(StringInfo b, uint32 v) { sb_raw(b, &v, sizeof(v)); }
static void sb_bytes(StringInfo b, const char *s, uint32 n) {
  sb_u32(b, n);
  sb_raw(b, s, n);
}
static void sb_str(StringInfo b, const char *s) {
  sb_bytes(b, s, (uint32)strlen(s));
}

static bool guc_is_session_state(struct config_generic *guc) {
  if (guc->context == PGC_INTERNAL || guc->context == PGC_POSTMASTER)
    return false;
  return guc->source >= PGC_S_DATABASE && guc->source != PGC_S_OVERRIDE;
}

static void build_gucs(StringInfo b) {
  int num_vars;
  struct config_generic **gucs = get_guc_variables(&num_vars);
  size_t pos = b->len;
  uint32 count = 0;
  sb_u32(b, 0);
  for (int i = 0; i < num_vars; i++) {
    if (!guc_is_session_state(gucs[i]))
      continue;
    char *val = ShowGUCOption(gucs[i], false);
    sb_str(b, gucs[i]->name);
    sb_str(b, val ? val : "");
    count++;
  }
  memcpy(b->data + pos, &count, sizeof(count));
}

static void sb_plansource(StringInfo b, const char *name, bool from_sql,
                          CachedPlanSource *src) {
  const char *q = src->query_string;
  size_t len = strlen(q);
  RawStmt *raw = src->raw_parse_tree;
  if (raw && raw->stmt_location >= 0 && (size_t)raw->stmt_location <= len) {
    q += raw->stmt_location;
    len -= raw->stmt_location;
    if (raw->stmt_len > 0 && (size_t)raw->stmt_len < len)
      len = raw->stmt_len;
  }
  sb_str(b, name);
  sb_u8(b, from_sql);
  sb_bytes(b, q, (uint32)len);
  sb_u16(b, src->num_params);
  for (int i = 0; i < src->num_params; i++)
    sb_u32(b, src->param_types[i]);
}

typedef struct {
  StringInfo b;
  uint32 n;
} PrepCtx;

static void each_prepared(PreparedStatement *ps, void *arg) {
  PrepCtx *c = arg;
  sb_plansource(c->b, ps->stmt_name, ps->from_sql, ps->plansource);
  c->n++;
}

static void build_prepared(StringInfo b) {
  PrepCtx c = {b, 0};
  size_t pos = b->len;
  sb_u32(b, 0);
  CachedPlanSource *unnamed = GetUnnamedStatementSource();
  if (unnamed) {
    sb_plansource(b, "", false, unnamed);
    c.n++;
  }
  ForEachPreparedStatement(each_prepared, &c);
  memcpy(b->data + pos, &c.n, sizeof(c.n));
}

static void put_section(uint8 type, StringInfo cur, StringInfo last) {
  if (cur->len == last->len && memcmp(cur->data, last->data, cur->len) == 0)
    return;
  put_rec(type, cur);
  resetStringInfo(last);
  appendBinaryStringInfo(last, cur->data, cur->len);
}

static void write_state(void) {
  StringInfoData cur;
  initStringInfo(&cur);
  build_gucs(&cur);
  put_section(SessGucs, &cur, &LastGucs);
  resetStringInfo(&cur);
  build_prepared(&cur);
  put_section(SessPrepared, &cur, &LastPrep);
  pfree(cur.data);
}

static void dump_cb(void *data, int len) { wr(data, len); }

static void dump_tables(const char *sql) {
  if (SPI_connect() != SPI_OK_CONNECT)
    elog(ERROR, "pgr: SPI_connect failed");
  if (SPI_execute(sql, true, 0) != SPI_OK_SELECT)
    elog(ERROR, "pgr: ttdescribe failed");

  uint64 n = SPI_processed;
  SPITupleTable *tt = SPI_tuptable;

  for (uint64 i = 0; i < n; i++) {
    HeapTuple t = tt->vals[i];
    bool isnull;
    Oid relid = DatumGetObjectId(SPI_getbinval(t, tt->tupdesc, 1, &isnull));
    uint8 type = SessTable;
    uint64 zero = 0;

    wr(&type, sizeof(type));
    wr(&zero, sizeof(zero));
    off_t start = ftello(SessionFile);

    wr_str(SPI_getvalue(t, tt->tupdesc, 2));
    wr_str(SPI_getvalue(t, tt->tupdesc, 3));
    wr_str(SPI_getvalue(t, tt->tupdesc, 4));

    Relation rel = table_open(relid, AccessShareLock);
    ParseState *pstate = make_parsestate(NULL);
    List *opts =
        list_make1(makeDefElem("format", (Node *)makeString("binary"), -1));
    CopyToState cs =
        BeginCopyTo(pstate, rel, NULL, relid, NULL, false, dump_cb, NIL, opts);
    DoCopyTo(cs);
    EndCopyTo(cs);
    free_parsestate(pstate);
    table_close(rel, AccessShareLock);

    off_t end = ftello(SessionFile);
    uint64 len = (uint64)(end - start);
    fseeko(SessionFile, start - (off_t)sizeof(uint64), SEEK_SET);
    wr(&len, sizeof(len));
    fseeko(SessionFile, end, SEEK_SET);
  }
  fflush(SessionFile);
  SPI_finish();
}

static void write_table_delta(void) {
  if (SchemaDirty) {
    put_rec(SessDropAll, NULL);
    dump_tables(SQL_ALL);
  } else if (DirtyRels != NIL) {
    StringInfoData sql;
    bool first = true;
    initStringInfo(&sql);
    appendStringInfoString(&sql,
                           "SELECT relid, table_name, columns_ddl, post_ddl "
                           "FROM pgr.ttdescribe(ARRAY[");
    foreach_oid(o, DirtyRels) {
      appendStringInfo(&sql, "%s%u", first ? "" : ",", o);
      first = false;
    }
    appendStringInfoString(&sql, "]::oid[])");
    dump_tables(sql.data);
    pfree(sql.data);
  }
}

static void start_body(void) {
  write_state();
  dump_tables(SQL_ALL);
}

static void commit_body(void) {
  write_state();
  write_table_delta();
}

static bool guarded(void (*fn)(void)) {
  bool ok = true;
  MemoryContext oldcxt = CurrentMemoryContext;
  ResourceOwner oldowner = CurrentResourceOwner;

  CommandCounterIncrement();
  BeginInternalSubTransaction(NULL);
  PG_TRY();
  {
    PushActiveSnapshot(GetLatestSnapshot());
    fn();
    PopActiveSnapshot();
    ReleaseCurrentSubTransaction();
  }
  PG_CATCH();
  {
    MemoryContextSwitchTo(oldcxt);
    ErrorData *edata = CopyErrorData();
    FlushErrorState();
    RollbackAndReleaseCurrentSubTransaction();
    ereport(WARNING,
            (errmsg("pgr: session capture failed: %s", edata->message)));
    FreeErrorData(edata);
    ok = false;
  }
  PG_END_TRY();

  MemoryContextSwitchTo(oldcxt);
  CurrentResourceOwner = oldowner;
  return ok;
}

void session_tx_reset(void) {
  list_free(DirtyRels);
  DirtyRels = NIL;
  SchemaDirty = false;
}

bool session_active(void) { return SessionFile != NULL; }

void session_stop(void) {
  if (SessionFile != NULL) {
    fclose(SessionFile);
    SessionFile = NULL;
  }
  session_tx_reset();
}

static void session_abandon(void) {
  session_stop();
  unlink(SessionPath);
}

bool session_start(const char *name) {
  session_stop();
  session_path(name, SessionPath);
  MakePGDirectory("sessions");

  SessionFile = fopen(SessionPath, "wb");
  if (SessionFile == NULL) {
    ereport(WARNING, (errmsg("pgr: cannot create %s", SessionPath)));
    return false;
  }

  if (!LastInit) {
    MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);
    initStringInfo(&LastGucs);
    initStringInfo(&LastPrep);
    MemoryContextSwitchTo(old);
    LastInit = true;
  } else {
    resetStringInfo(&LastGucs);
    resetStringInfo(&LastPrep);
  }

  if (!guarded(start_body)) {
    session_abandon();
    return false;
  }
  return true;
}

void session_commit(void) {
  if (SessionFile == NULL)
    return;
  if (!guarded(commit_body))
    session_abandon();
  session_tx_reset();
}

void session_note_query(QueryDesc *qd) {
  if (SessionFile == NULL)
    return;
  PlannedStmt *ps = qd->plannedstmt;
  int rti = -1;
  while ((rti = bms_next_member(ps->resultRelationRelids, rti)) >= 0) {
    RangeTblEntry *rte = rt_fetch(rti, ps->rtable);
    if (rte->rtekind != RTE_RELATION)
      continue;
    if (get_rel_persistence(rte->relid) == RELPERSISTENCE_TEMP) {
      MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);
      DirtyRels = list_append_unique_oid(DirtyRels, rte->relid);
      MemoryContextSwitchTo(old);
    }
  }
}

void session_note_utility(Node *n) {
  if (SessionFile == NULL)
    return;
  switch (nodeTag(n)) {
  case T_TransactionStmt:
  case T_VariableSetStmt:
  case T_VariableShowStmt:
  case T_PrepareStmt:
  case T_ExecuteStmt:
  case T_DeallocateStmt:
  case T_FetchStmt:
  case T_ClosePortalStmt:
  case T_DeclareCursorStmt:
  case T_ExplainStmt:
  case T_VacuumStmt:
  case T_DoStmt:
  case T_CallStmt:
    return;
  default:
    SchemaDirty = true;
  }
}

typedef struct {
  const char *p;
} Cur;

static uint8 c_u8(Cur *c) {
  uint8 v = *(const uint8 *)c->p;
  c->p += 1;
  return v;
}
static uint16 c_u16(Cur *c) {
  uint16 v;
  memcpy(&v, c->p, sizeof(v));
  c->p += sizeof(v);
  return v;
}
static uint32 c_u32(Cur *c) {
  uint32 v;
  memcpy(&v, c->p, sizeof(v));
  c->p += sizeof(v);
  return v;
}
static char *c_str(Cur *c) {
  uint32 n = c_u32(c);
  char *s = pnstrdup(c->p, n);
  c->p += n;
  return s;
}

static void rd(void *p, size_t n) {
  if (fread(p, 1, n, ReadFile) != n)
    ereport(ERROR, (errcode(ERRCODE_DATA_CORRUPTED),
                    errmsg("pgr: session file is truncated")));
}

static uint32 rd_u32(void) {
  uint32 v;
  rd(&v, sizeof(v));
  return v;
}

static uint64 rd_u64(void) {
  uint64 v;
  rd(&v, sizeof(v));
  return v;
}

static char *rd_str(void) {
  uint32 n = rd_u32();
  char *s = palloc(n + 1);
  rd(s, n);
  s[n] = '\0';
  return s;
}

static int load_cb(void *buf, int minread, int maxread) {
  size_t want = (size_t)maxread;
  if (want > ReadLeft)
    want = ReadLeft;
  size_t got = fread(buf, 1, want, ReadFile);
  ReadLeft -= got;
  return (int)got;
}

static void exec_sql(const char *sql) {
  if (SPI_execute(sql, false, 0) < 0)
    elog(ERROR, "pgr: restore failed: %s", sql);
}

static void restore_table(uint64 len) {
  off_t start = ftello(ReadFile);
  char *tname = rd_str();
  char *cols = rd_str();
  char *post = rd_str();
  ReadLeft = len - (uint64)(ftello(ReadFile) - start);

  StringInfoData sql;
  initStringInfo(&sql);
  appendStringInfo(&sql, "DROP TABLE IF EXISTS pg_temp.%s",
                   quote_identifier(tname));
  exec_sql(sql.data);
  resetStringInfo(&sql);
  appendStringInfo(&sql, "CREATE TEMP TABLE %s (%s)", quote_identifier(tname),
                   cols);
  exec_sql(sql.data);

  Relation rel =
      table_openrv(makeRangeVar("pg_temp", tname, -1), RowExclusiveLock);
  ParseState *pstate = make_parsestate(NULL);
  ParseNamespaceItem *nsitem = addRangeTableEntryForRelation(
      pstate, rel, RowExclusiveLock, NULL, false, false);
  nsitem->p_perminfo->requiredPerms = ACL_INSERT;
  List *opts =
      list_make1(makeDefElem("format", (Node *)makeString("binary"), -1));
  CopyFromState cs =
      BeginCopyFrom(pstate, rel, NULL, NULL, false, load_cb, NIL, opts);
  CopyFrom(cs);
  EndCopyFrom(cs);
  free_parsestate(pstate);
  table_close(rel, RowExclusiveLock);

  if (post[0])
    exec_sql(post);
}

static void drop_all_temp(void) {
  if (SPI_execute("SELECT format('DROP TABLE pg_temp.%I', relname) FROM "
                  "pg_class WHERE relnamespace = pg_my_temp_schema() AND "
                  "relkind = 'r'",
                  true, 0) != SPI_OK_SELECT)
    elog(ERROR, "pgr: cannot list temp tables");
  uint64 n = SPI_processed;
  SPITupleTable *tt = SPI_tuptable;
  for (uint64 i = 0; i < n; i++)
    exec_sql(SPI_getvalue(tt->vals[i], tt->tupdesc, 1));
}

static void apply_gucs(const char *buf) {
  Cur c = {buf};
  uint32 n = c_u32(&c);
  for (uint32 i = 0; i < n; i++) {
    char *name = c_str(&c);
    char *val = c_str(&c);
    set_config_option(name, val, superuser() ? PGC_SUSET : PGC_USERSET,
                      PGC_S_SESSION, GUC_ACTION_SET, true, WARNING, false);
  }
}

static void restore_protocol_prepared(const char *name, const char *q, int np,
                                      const Oid *types) {
  List *trees = pg_parse_query(q);
  if (list_length(trees) != 1)
    ereport(ERROR,
            (errmsg("pgr: cannot restore prepared statement \"%s\"", name)));
  RawStmt *raw = linitial_node(RawStmt, trees);
  CachedPlanSource *psrc =
      CreateCachedPlan(raw, q, CreateCommandTag(raw->stmt));

  Oid *pt = palloc((np + 1) * sizeof(Oid));
  memcpy(pt, types, np * sizeof(Oid));
  int n = np;
  List *qtrees = pg_analyze_and_rewrite_varparams(raw, q, &pt, &n, NULL);

  CompleteCachedPlan(psrc, qtrees, NULL, pt, n, NULL, NULL,
                     CURSOR_OPT_PARALLEL_OK, true);
  StorePreparedStatement(name, psrc, false);
}

static void apply_prepared(const char *buf) {
  Cur c = {buf};
  uint32 n = c_u32(&c);
  for (uint32 i = 0; i < n; i++) {
    char *name = c_str(&c);
    bool from_sql = c_u8(&c);
    char *q = c_str(&c);
    uint16 np = c_u16(&c);
    Oid *types = palloc((np + 1) * sizeof(Oid));
    for (int j = 0; j < np; j++)
      types[j] = c_u32(&c);
    if (name[0] == '\0')
      continue;

    if (!from_sql) {
      restore_protocol_prepared(name, q, np, types);
      continue;
    }
    exec_sql(q);
  }
}

int session_restore(const char *name) {
  char path[MAXPGPATH];
  char *gucs = NULL;
  char *prep = NULL;
  int count = 0;

  session_path(name, path);
  ReadFile = AllocateFile(path, PG_BINARY_R);
  if (!ReadFile)
    ereport(ERROR, (errcode_for_file_access(),
                    errmsg("pgr: cannot open \"%s\": %m", path)));

  if (SPI_connect() != SPI_OK_CONNECT)
    elog(ERROR, "pgr: SPI_connect failed");

  for (;;) {
    uint8 type;
    if (fread(&type, 1, 1, ReadFile) != 1)
      break;
    uint64 len = rd_u64();
    off_t next = ftello(ReadFile) + (off_t)len;

    switch (type) {
    case SessGucs:
      gucs = palloc(len);
      rd(gucs, len);
      break;
    case SessPrepared:
      prep = palloc(len);
      rd(prep, len);
      break;
    case SessTable:
      restore_table(len);
      break;
    case SessDropAll:
      drop_all_temp();
      break;
    }
    fseeko(ReadFile, next, SEEK_SET);
    count++;
  }

  if (gucs)
    apply_gucs(gucs);
  if (prep)
    apply_prepared(prep);

  SPI_finish();
  FreeFile(ReadFile);
  ReadFile = NULL;
  return count;
}

Datum sql_session_dump(PG_FUNCTION_ARGS) {
  char *name = text_to_cstring(PG_GETARG_TEXT_PP(0));
  if (SessionFile != NULL)
    ereport(ERROR, (errmsg("pgr: session capture is active")));
  bool ok = session_start(name);
  session_stop();
  PG_RETURN_INT32(ok ? 1 : 0);
}

Datum sql_session_restore(PG_FUNCTION_ARGS) {
  char *name = text_to_cstring(PG_GETARG_TEXT_PP(0));
  PG_RETURN_INT32(session_restore(name));
}
