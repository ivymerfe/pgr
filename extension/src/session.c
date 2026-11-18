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
#include "parser/analyze.h"
#include "parser/parse_node.h"
#include "parser/parse_relation.h"
#include "storage/fd.h"
#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/guc_tables.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/plancache.h"
#include "utils/snapmgr.h"

#include <zstd.h>

#define SQL_ALL                                                       \
  "SELECT t.relid, t.table_name, t.columns_ddl, t.post_ddl, "         \
  "c.relfilenode FROM pgr.ttdescribe() t JOIN pg_class c ON c.oid = " \
  "t.relid"

#define KeyLen 128
#define ChunkSize (1024 * 1024)

enum {
  SessGucSet = 1,
  SessGucReset,
  SessPrepPut,
  SessPrepDrop,
  SessTableBegin,
  SessTableChunk,
  SessTableEnd,
  SessTableDrop,
};

typedef struct {
  char key[KeyLen];
  char* data;
  uint32 len;
  bool seen;
} Kv;

static FILE* SessionFile = NULL;
static char SessionPath[MAXPGPATH];
static ZSTD_CCtx* Zctx = NULL;
static char ZOut[128 * 1024];
static bool FrameOpen = false;

static MemoryContext StateCxt = NULL;
static HTAB* Gucs = NULL;
static HTAB* Preps = NULL;
static HTAB* Tables = NULL;
static HTAB* Dirty = NULL;
static HTAB* Pending = NULL;
static StringInfoData ChunkBuf;

static FILE* ReadFile = NULL;
static ZSTD_DCtx* Dctx = NULL;
static char ZIn[128 * 1024];
static ZSTD_inBuffer In = {ZIn, 0, 0};
static uint32 ChunkLeft = 0;
static bool ChunkDone = false;

static void session_path(const char* name, char* path) {
  const char* slash = strchr(name, '/');
  bool ok = slash && slash != name && slash[1] != '\0' && strlen(name) <= 40;
  for (const char* p = name; ok && *p; p++) {
    if (p != slash && !isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
      ok = false;
    }
  }
  if (!ok) {
    ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                    errmsg("pgr: invalid session name")));
  }
  snprintf(path, MAXPGPATH, "sessions/%s.pgs", name);
}

static const char* nz(const char* s) {
  return s ? s : "";
}

static void z_check(size_t r) {
  if (ZSTD_isError(r)) {
    ereport(ERROR, (errmsg("pgr: zstd error: %s", ZSTD_getErrorName(r))));
  }
}

static void z_emit(const ZSTD_outBuffer* out) {
  if (out->pos > 0 && fwrite(ZOut, 1, out->pos, SessionFile) != out->pos) {
    ereport(ERROR,
            (errcode_for_file_access(), errmsg("pgr: write failed: %m")));
  }
}

static void z_write(const void* data, size_t len) {
  FrameOpen = true;
  ZSTD_inBuffer in = {data, len, 0};
  while (in.pos < in.size) {
    ZSTD_outBuffer out = {ZOut, sizeof(ZOut), 0};
    z_check(ZSTD_compressStream(Zctx, &out, &in));
    z_emit(&out);
  }
}

static void z_finish(void) {
  if (!FrameOpen) {
    return;
  }
  size_t rem;
  do {
    ZSTD_outBuffer out = {ZOut, sizeof(ZOut), 0};
    rem = ZSTD_endStream(Zctx, &out);
    z_check(rem);
    z_emit(&out);
  } while (rem != 0);
  FrameOpen = false;
  fflush(SessionFile);
}

static void put_rec(uint8 type, StringInfo b) {
  uint32 len = b ? (uint32)b->len : 0;
  z_write(&type, sizeof(type));
  z_write(&len, sizeof(len));
  if (len) {
    z_write(b->data, len);
  }
}

static void sb_raw(StringInfo b, const void* p, size_t n) {
  appendBinaryStringInfo(b, p, n);
}

static void sb_u8(StringInfo b, uint8 v) {
  sb_raw(b, &v, sizeof(v));
}

static void sb_u16(StringInfo b, uint16 v) {
  sb_raw(b, &v, sizeof(v));
}

static void sb_u32(StringInfo b, uint32 v) {
  sb_raw(b, &v, sizeof(v));
}

static void sb_bytes(StringInfo b, const char* s, uint32 n) {
  sb_u32(b, n);
  sb_raw(b, s, n);
}

static void sb_str(StringInfo b, const char* s) {
  sb_bytes(b, s, (uint32)strlen(s));
}

static HTAB* kv_new(const char* name, MemoryContext cx) {
  HASHCTL ctl;
  memset(&ctl, 0, sizeof(ctl));
  ctl.keysize = KeyLen;
  ctl.entrysize = sizeof(Kv);
  ctl.hcxt = cx;
  return hash_create(name, 64, &ctl, HASH_ELEM | HASH_STRINGS | HASH_CONTEXT);
}

static bool kv_put(HTAB* h,
                   MemoryContext cx,
                   const char* key,
                   const char* data,
                   uint32 len) {
  bool found;
  Kv* e = hash_search(h, key, HASH_ENTER, &found);
  if (!found) {
    e->data = NULL;
    e->len = 0;
  }
  e->seen = true;
  if (e->data != NULL && e->len == len && memcmp(e->data, data, len) == 0) {
    return false;
  }
  if (e->data != NULL) {
    pfree(e->data);
  }
  e->data = MemoryContextAlloc(cx, len + 1);
  memcpy(e->data, data, len);
  e->len = len;
  return true;
}

static void kv_sweep(HTAB* h, uint8 type) {
  HASH_SEQ_STATUS s;
  Kv* e;
  StringInfoData b;
  initStringInfo(&b);
  hash_seq_init(&s, h);
  while ((e = hash_seq_search(&s)) != NULL) {
    if (e->seen) {
      e->seen = false;
      continue;
    }
    resetStringInfo(&b);
    sb_str(&b, e->key);
    put_rec(type, &b);
    pfree(e->data);
    hash_search(h, e->key, HASH_REMOVE, NULL);
  }
  pfree(b.data);
}

static HTAB* oid_set_new(void) {
  HASHCTL ctl;
  memset(&ctl, 0, sizeof(ctl));
  ctl.keysize = sizeof(Oid);
  ctl.entrysize = sizeof(Oid);
  ctl.hcxt = StateCxt;
  return hash_create("pgr oids", 64, &ctl,
                     HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
}

static void oid_set_clear(HTAB* h) {
  HASH_SEQ_STATUS s;
  Oid* e;
  hash_seq_init(&s, h);
  while ((e = hash_seq_search(&s)) != NULL) {
    hash_search(h, e, HASH_REMOVE, NULL);
  }
}

void session_mark_dirty(Oid relid) {
  if (Pending != NULL) {
    hash_search(Pending, &relid, HASH_ENTER, NULL);
  }
}

void session_xact_end(bool committed) {
  if (Pending == NULL) {
    return;
  }
  HASH_SEQ_STATUS s;
  Oid* e;
  hash_seq_init(&s, Pending);
  while ((e = hash_seq_search(&s)) != NULL) {
    if (committed) {
      hash_search(Dirty, e, HASH_ENTER, NULL);
    }
    hash_search(Pending, e, HASH_REMOVE, NULL);
  }
}

static bool guc_is_session_state(struct config_generic* guc) {
  if (guc->context == PGC_INTERNAL || guc->context == PGC_POSTMASTER) {
    return false;
  }
  return guc->source >= PGC_S_DATABASE && guc->source != PGC_S_OVERRIDE;
}

static void delta_gucs(void) {
  int num_vars;
  struct config_generic** gucs = get_guc_variables(&num_vars);
  StringInfoData b;
  initStringInfo(&b);
  for (int i = 0; i < num_vars; i++) {
    if (!guc_is_session_state(gucs[i])) {
      continue;
    }
    const char* val = nz(ShowGUCOption(gucs[i], false));
    if (kv_put(Gucs, StateCxt, gucs[i]->name, val, strlen(val) + 1)) {
      resetStringInfo(&b);
      sb_str(&b, gucs[i]->name);
      sb_str(&b, val);
      put_rec(SessGucSet, &b);
    }
  }
  kv_sweep(Gucs, SessGucReset);
  pfree(b.data);
}

static void sb_plansource(StringInfo b,
                          const char* name,
                          bool from_sql,
                          CachedPlanSource* src) {
  const char* q = src->query_string;
  size_t len = strlen(q);
  RawStmt* raw = src->raw_parse_tree;
  if (raw && raw->stmt_location >= 0 && (size_t)raw->stmt_location <= len) {
    q += raw->stmt_location;
    len -= raw->stmt_location;
    if (raw->stmt_len > 0 && (size_t)raw->stmt_len < len) {
      len = raw->stmt_len;
    }
  }
  sb_str(b, name);
  sb_u8(b, from_sql);
  sb_bytes(b, q, (uint32)len);
  sb_u16(b, src->num_params);
  for (int i = 0; i < src->num_params; i++) {
    sb_u32(b, src->param_types[i]);
  }
}

static void each_prepared(PreparedStatement* ps, void* arg) {
  StringInfo b = arg;
  resetStringInfo(b);
  sb_plansource(b, ps->stmt_name, ps->from_sql, ps->plansource);
  if (kv_put(Preps, StateCxt, ps->stmt_name, b->data, b->len)) {
    put_rec(SessPrepPut, b);
  }
}

static void delta_prepared(void) {
  StringInfoData b;
  initStringInfo(&b);
  ForEachPreparedStatement(each_prepared, &b);
  kv_sweep(Preps, SessPrepDrop);
  pfree(b.data);
}

static void flush_chunk(void) {
  if (ChunkBuf.len > 0) {
    put_rec(SessTableChunk, &ChunkBuf);
    resetStringInfo(&ChunkBuf);
  }
}

static void dump_cb(void* data, int len) {
  appendBinaryStringInfo(&ChunkBuf, data, len);
  if (ChunkBuf.len >= ChunkSize) {
    flush_chunk();
  }
}

static void dump_table(Oid relid,
                       const char* tname,
                       const char* cols,
                       const char* post) {
  StringInfoData b;
  initStringInfo(&b);
  sb_str(&b, tname);
  sb_str(&b, cols);
  sb_str(&b, post);
  put_rec(SessTableBegin, &b);
  pfree(b.data);

  initStringInfo(&ChunkBuf);
  Relation rel = table_open(relid, AccessShareLock);
  ParseState* pstate = make_parsestate(NULL);
  List* opts =
      list_make1(makeDefElem("format", (Node*)makeString("binary"), -1));
  CopyToState cs =
      BeginCopyTo(pstate, rel, NULL, relid, NULL, false, dump_cb, NIL, opts);
  DoCopyTo(cs);
  EndCopyTo(cs);
  free_parsestate(pstate);
  table_close(rel, AccessShareLock);
  flush_chunk();
  pfree(ChunkBuf.data);
  put_rec(SessTableEnd, NULL);
}

static void delta_tables(void) {
  if (SPI_connect() != SPI_OK_CONNECT) {
    elog(ERROR, "pgr: SPI_connect failed");
  }
  if (SPI_execute(SQL_ALL, true, 0) != SPI_OK_SELECT) {
    elog(ERROR, "pgr: ttdescribe failed");
  }

  uint64 n = SPI_processed;
  SPITupleTable* tt = SPI_tuptable;
  StringInfoData sig;
  initStringInfo(&sig);

  for (uint64 i = 0; i < n; i++) {
    HeapTuple t = tt->vals[i];
    bool isnull;
    Oid relid = DatumGetObjectId(SPI_getbinval(t, tt->tupdesc, 1, &isnull));
    const char* tname = nz(SPI_getvalue(t, tt->tupdesc, 2));
    const char* cols = nz(SPI_getvalue(t, tt->tupdesc, 3));
    const char* post = nz(SPI_getvalue(t, tt->tupdesc, 4));
    const char* fnode = nz(SPI_getvalue(t, tt->tupdesc, 5));

    resetStringInfo(&sig);
    appendStringInfo(&sig, "%u/%s/%s/%s", relid, fnode, cols, post);
    bool changed = kv_put(Tables, StateCxt, tname, sig.data, sig.len);
    bool dirty = hash_search(Dirty, &relid, HASH_FIND, NULL) != NULL;
    if (changed || dirty) {
      dump_table(relid, tname, cols, post);
    }
  }
  kv_sweep(Tables, SessTableDrop);
  oid_set_clear(Dirty);
  pfree(sig.data);
  SPI_finish();
}

static void start_body(void) {
  delta_gucs();
  delta_prepared();
  delta_tables();
  z_finish();
}

static bool guarded(void (*fn)(void)) {
  bool ok = true;
  MemoryContext oldcxt = CurrentMemoryContext;
  ResourceOwner oldowner = CurrentResourceOwner;

  if (IsTransactionState()) {
    CommandCounterIncrement();
    BeginInternalSubTransaction(NULL);
    PG_TRY();
    {
      PushActiveSnapshot(GetTransactionSnapshot());
      fn();
      PopActiveSnapshot();
      ReleaseCurrentSubTransaction();
    }
    PG_CATCH();
    {
      MemoryContextSwitchTo(oldcxt);
      ErrorData* edata = CopyErrorData();
      FlushErrorState();
      RollbackAndReleaseCurrentSubTransaction();
      ereport(WARNING,
              (errmsg("pgr: session capture failed: %s", edata->message)));
      FreeErrorData(edata);
      ok = false;
    }
    PG_END_TRY();
  } else {
    StartTransactionCommand();
    PG_TRY();
    {
      PushActiveSnapshot(GetTransactionSnapshot());
      fn();
      PopActiveSnapshot();
      CommitTransactionCommand();
    }
    PG_CATCH();
    {
      MemoryContextSwitchTo(oldcxt);
      ErrorData* edata = CopyErrorData();
      FlushErrorState();
      AbortCurrentTransaction();
      ereport(WARNING,
              (errmsg("pgr: session capture failed: %s", edata->message)));
      FreeErrorData(edata);
      ok = false;
    }
    PG_END_TRY();
  }

  MemoryContextSwitchTo(oldcxt);
  CurrentResourceOwner = oldowner;
  return ok;
}

bool session_active(void) {
  return SessionFile != NULL;
}

void session_stop(void) {
  if (SessionFile == NULL) {
    return;
  }
  if (Zctx != NULL) {
    ZSTD_freeCCtx(Zctx);
    Zctx = NULL;
  }
  fclose(SessionFile);
  SessionFile = NULL;
  FrameOpen = false;
  if (StateCxt != NULL) {
    MemoryContextDelete(StateCxt);
    StateCxt = NULL;
  }
  Gucs = NULL;
  Preps = NULL;
  Tables = NULL;
  Dirty = NULL;
  Pending = NULL;
}

static void session_abandon(void) {
  session_stop();
  unlink(SessionPath);
}

static bool session_open(const char* path) {
  char dir[MAXPGPATH];
  snprintf(dir, sizeof(dir), "%s", path);
  *strrchr(dir, '/') = '\0';
  MakePGDirectory("sessions");
  MakePGDirectory(dir);

  FILE* f = fopen(path, "wb");
  if (f == NULL) {
    ereport(WARNING, (errmsg("pgr: cannot create %s", path)));
    return false;
  }
  ZSTD_CCtx* z = ZSTD_createCCtx();
  if (z == NULL) {
    fclose(f);
    unlink(path);
    ereport(WARNING, (errmsg("pgr: could not create zstd context")));
    return false;
  }
  ZSTD_CCtx_setParameter(z, ZSTD_c_compressionLevel, 3);

  strlcpy(SessionPath, path, MAXPGPATH);
  SessionFile = f;
  Zctx = z;
  FrameOpen = false;
  StateCxt = AllocSetContextCreate(TopMemoryContext, "pgr session state",
                                   ALLOCSET_DEFAULT_SIZES);
  Gucs = kv_new("pgr gucs", StateCxt);
  Preps = kv_new("pgr preps", StateCxt);
  Tables = kv_new("pgr tables", StateCxt);
  Dirty = oid_set_new();
  Pending = oid_set_new();

  return true;
}

bool session_start(const char* name) {
  char path[MAXPGPATH];
  session_path(name, path);
  if (SessionFile != NULL && strcmp(path, SessionPath) != 0) {
    session_stop();
  }
  if (SessionFile == NULL && !session_open(path)) {
    return false;
  }
  if (!guarded(start_body)) {
    session_abandon();
    return false;
  }
  return true;
}

typedef struct {
  const char* p;
} Cur;

static uint8 c_u8(Cur* c) {
  uint8 v = *(const uint8*)c->p;
  c->p += 1;
  return v;
}

static uint16 c_u16(Cur* c) {
  uint16 v;
  memcpy(&v, c->p, sizeof(v));
  c->p += sizeof(v);
  return v;
}

static uint32 c_u32(Cur* c) {
  uint32 v;
  memcpy(&v, c->p, sizeof(v));
  c->p += sizeof(v);
  return v;
}

static char* c_str(Cur* c) {
  uint32 n = c_u32(c);
  char* s = pnstrdup(c->p, n);
  c->p += n;
  return s;
}

static size_t z_read(void* p, size_t n) {
  ZSTD_outBuffer out = {p, n, 0};
  while (out.pos < n) {
    if (In.pos == In.size) {
      In.size = fread(ZIn, 1, sizeof(ZIn), ReadFile);
      In.pos = 0;
      if (In.size == 0) {
        break;
      }
    }
    size_t r = ZSTD_decompressStream(Dctx, &out, &In);
    if (ZSTD_isError(r)) {
      ereport(ERROR, (errcode(ERRCODE_DATA_CORRUPTED),
                      errmsg("pgr: zstd error: %s", ZSTD_getErrorName(r))));
    }
  }
  return out.pos;
}

static void rd(void* p, size_t n) {
  if (z_read(p, n) != n) {
    ereport(ERROR, (errcode(ERRCODE_DATA_CORRUPTED),
                    errmsg("pgr: session file is truncated")));
  }
}

static bool rd_hdr(uint8* type, uint32* len) {
  if (z_read(type, 1) != 1) {
    return false;
  }
  rd(len, sizeof(*len));
  return true;
}

static int load_cb(void* buf, int minread, int maxread) {
  while (ChunkLeft == 0) {
    if (ChunkDone) {
      return 0;
    }
    uint8 type;
    uint32 len;
    if (!rd_hdr(&type, &len)) {
      ereport(ERROR, (errcode(ERRCODE_DATA_CORRUPTED),
                      errmsg("pgr: session file is truncated")));
    }
    if (type == SessTableEnd) {
      ChunkDone = true;
      return 0;
    }
    if (type != SessTableChunk) {
      ereport(ERROR, (errcode(ERRCODE_DATA_CORRUPTED),
                      errmsg("pgr: unexpected record in table data")));
    }
    ChunkLeft = len;
  }
  size_t want = (size_t)maxread;
  if (want > ChunkLeft) {
    want = ChunkLeft;
  }
  rd(buf, want);
  ChunkLeft -= (uint32)want;
  return (int)want;
}

static void drain_chunks(void) {
  char tmp[8192];
  while (load_cb(tmp, 1, sizeof(tmp)) > 0) {
  }
}

static void exec_sql(const char* sql) {
  if (SPI_execute(sql, false, 0) < 0) {
    elog(ERROR, "pgr: restore failed: %s", sql);
  }
}

static void drop_table(const char* tname) {
  StringInfoData sql;
  initStringInfo(&sql);
  appendStringInfo(&sql, "DROP TABLE IF EXISTS pg_temp.%s",
                   quote_identifier(tname));
  exec_sql(sql.data);
  pfree(sql.data);
}

static void restore_table(Cur* c) {
  char* tname = c_str(c);
  char* cols = c_str(c);
  char* post = c_str(c);
  ChunkLeft = 0;
  ChunkDone = false;

  drop_table(tname);
  StringInfoData sql;
  initStringInfo(&sql);
  appendStringInfo(&sql, "CREATE TEMP TABLE %s (%s)", quote_identifier(tname),
                   cols);
  exec_sql(sql.data);
  pfree(sql.data);

  Relation rel =
      table_openrv(makeRangeVar("pg_temp", tname, -1), RowExclusiveLock);
  ParseState* pstate = make_parsestate(NULL);
  ParseNamespaceItem* nsitem = addRangeTableEntryForRelation(
      pstate, rel, RowExclusiveLock, NULL, false, false);
  nsitem->p_perminfo->requiredPerms = ACL_INSERT;
  List* opts =
      list_make1(makeDefElem("format", (Node*)makeString("binary"), -1));
  CopyFromState cs =
      BeginCopyFrom(pstate, rel, NULL, NULL, false, load_cb, NIL, opts);
  CopyFrom(cs);
  EndCopyFrom(cs);
  drain_chunks();
  free_parsestate(pstate);
  table_close(rel, RowExclusiveLock);

  if (post[0]) {
    exec_sql(post);
  }
}

static void restore_protocol_prepared(const char* name,
                                      const char* q,
                                      int np,
                                      const Oid* types) {
  List* trees = pg_parse_query(q);
  if (list_length(trees) > 1) {
    ereport(ERROR, (errmsg("pgr: cannot restore prepared statement \"%s\": %s",
                           name, q)));
  }

  Oid* pt = palloc((np + 1) * sizeof(Oid));
  memcpy(pt, types, np * sizeof(Oid));
  int n = np;
  List* qtrees = NIL;
  bool lazy = false;
  CachedPlanSource* psrc;

  if (trees == NIL) {
    psrc = CreateCachedPlan(NULL, q, CMDTAG_UNKNOWN);
  } else {
    RawStmt* raw = linitial_node(RawStmt, trees);
    psrc = CreateCachedPlan(raw, q, CreateCommandTag(raw->stmt));
    lazy = analyze_requires_snapshot(raw);
    if (!lazy) {
      qtrees = pg_analyze_and_rewrite_varparams(raw, q, &pt, &n, NULL);
    }
  }
  CompleteCachedPlan(psrc, qtrees, NULL, pt, n, NULL, NULL,
                     CURSOR_OPT_PARALLEL_OK, !lazy);
  if (lazy) {
    psrc->is_valid = false;
  }
  StorePreparedStatement(name, psrc, false);
}

static void apply_one_prepared(const char* name,
                               bool from_sql,
                               const char* q,
                               int np,
                               const Oid* types) {
  MemoryContext oldcxt = CurrentMemoryContext;
  ResourceOwner oldowner = CurrentResourceOwner;

  BeginInternalSubTransaction(NULL);
  PG_TRY();
  {
    if (from_sql) {
      exec_sql(q);
    } else {
      restore_protocol_prepared(name, q, np, types);
    }
    ReleaseCurrentSubTransaction();
  }
  PG_CATCH();
  {
    MemoryContextSwitchTo(oldcxt);
    ErrorData* edata = CopyErrorData();
    FlushErrorState();
    RollbackAndReleaseCurrentSubTransaction();
    ereport(WARNING, (errmsg("pgr: cannot restore prepared \"%s\": %s", name,
                             edata->message)));
    FreeErrorData(edata);
  }
  PG_END_TRY();

  MemoryContextSwitchTo(oldcxt);
  CurrentResourceOwner = oldowner;
}

static void apply_prepared(const char* buf) {
  Cur c = {buf};
  char* name = c_str(&c);
  bool from_sql = c_u8(&c);
  char* q = c_str(&c);
  uint16 np = c_u16(&c);
  Oid* types = palloc((np + 1) * sizeof(Oid));
  for (int j = 0; j < np; j++) {
    types[j] = c_u32(&c);
  }
  apply_one_prepared(name, from_sql, q, np, types);
}

static bool restore_guarded(void (*fn)(void)) {
  bool ok = true;
  MemoryContext oldcxt = CurrentMemoryContext;
  ResourceOwner oldowner = CurrentResourceOwner;

  CommandCounterIncrement();
  BeginInternalSubTransaction(NULL);
  PG_TRY();
  {
    PushActiveSnapshot(GetTransactionSnapshot());
    fn();
    PopActiveSnapshot();
    ReleaseCurrentSubTransaction();
  }
  PG_CATCH();
  {
    MemoryContextSwitchTo(oldcxt);
    ErrorData* edata = CopyErrorData();
    FlushErrorState();
    RollbackAndReleaseCurrentSubTransaction();
    ereport(WARNING,
            (errmsg("pgr: session restore failed: %s", edata->message)));
    FreeErrorData(edata);
    ok = false;
  }
  PG_END_TRY();

  MemoryContextSwitchTo(oldcxt);
  CurrentResourceOwner = oldowner;
  return ok;
}

static void restore_body(void) {
  if (SPI_connect() != SPI_OK_CONNECT) {
    elog(ERROR, "pgr: SPI_connect failed");
  }

  MemoryContext cx = CurrentMemoryContext;
  HTAB* rgucs = kv_new("pgr restore gucs", cx);
  HTAB* rpreps = kv_new("pgr restore preps", cx);

  for (;;) {
    uint8 type;
    uint32 len;
    if (!rd_hdr(&type, &len)) {
      break;
    }
    char* buf = palloc(len + 1);
    rd(buf, len);
    Cur c = {buf};

    switch (type) {
      case SessGucSet: {
        char* name = c_str(&c);
        char* val = c_str(&c);
        kv_put(rgucs, cx, name, val, strlen(val) + 1);
        break;
      }
      case SessGucReset:
        hash_search(rgucs, c_str(&c), HASH_REMOVE, NULL);
        break;
      case SessPrepPut: {
        Cur k = {buf};
        kv_put(rpreps, cx, c_str(&k), buf, len);
        break;
      }
      case SessPrepDrop:
        hash_search(rpreps, c_str(&c), HASH_REMOVE, NULL);
        break;
      case SessTableBegin:
        restore_table(&c);
        break;
      case SessTableDrop:
        drop_table(c_str(&c));
        break;
      default:
        ereport(ERROR, (errcode(ERRCODE_DATA_CORRUPTED),
                        errmsg("pgr: unknown session record %d", type)));
    }
    pfree(buf);
  }

  HASH_SEQ_STATUS s;
  Kv* e;
  hash_seq_init(&s, rgucs);
  while ((e = hash_seq_search(&s)) != NULL) {
    set_config_option(e->key, e->data, superuser() ? PGC_SUSET : PGC_USERSET,
                      PGC_S_SESSION, GUC_ACTION_SET, true, WARNING, false);
  }
  hash_seq_init(&s, rpreps);
  while ((e = hash_seq_search(&s)) != NULL) {
    apply_prepared(e->data);
  }

  SPI_finish();
}

int session_restore(const char* name) {
  char path[MAXPGPATH];

  session_path(name, path);
  ReadFile = AllocateFile(path, PG_BINARY_R);
  if (!ReadFile) {
    ereport(ERROR, (errcode_for_file_access(),
                    errmsg("pgr: cannot open \"%s\": %m", path)));
  }
  Dctx = ZSTD_createDCtx();
  if (Dctx == NULL) {
    FreeFile(ReadFile);
    ReadFile = NULL;
    ereport(ERROR, (errmsg("pgr: could not create zstd context")));
  }
  In.pos = 0;
  In.size = 0;
  bool ok = restore_guarded(restore_body);

  ZSTD_freeDCtx(Dctx);
  Dctx = NULL;
  FreeFile(ReadFile);
  ReadFile = NULL;
  return ok ? 1 : 0;
}
