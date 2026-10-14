#include "pgr.h"

#include "access/table.h"
#include "access/xact.h"
#include "commands/copy.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "nodes/makefuncs.h"
#include "parser/parse_node.h"
#include "parser/parse_relation.h"
#include "storage/fd.h"
#include "utils/builtins.h"
#include "utils/resowner.h"

static FILE *TmpFile = NULL;
static uint64 TmpLeft = 0;

static void temp_path(const char *name, char *path) {
  size_t n = strlen(name);
  if (n == 0 || n > 200)
    ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                    errmsg("pgr: invalid dump name")));
  for (const char *p = name; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-')
      ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                      errmsg("pgr: invalid dump name")));
  }
  snprintf(path, MAXPGPATH, "temptables/%s.bin", name);
}

static void wr(const void *p, size_t n) {
  if (fwrite(p, 1, n, TmpFile) != n)
    ereport(ERROR,
            (errcode_for_file_access(), errmsg("pgr: write failed: %m")));
}

static void rd(void *p, size_t n) {
  if (fread(p, 1, n, TmpFile) != n)
    ereport(ERROR, (errcode(ERRCODE_DATA_CORRUPTED),
                    errmsg("pgr: temp dump is truncated")));
}

static void wr_u32(uint32 v) { wr(&v, sizeof(v)); }
static void wr_u64(uint64 v) { wr(&v, sizeof(v)); }

static void wr_str(const char *s) {
  uint32 n = s ? (uint32)strlen(s) : 0;
  wr_u32(n);
  if (n)
    wr(s, n);
}

static uint32 rd_u32() {
  uint32 v;
  rd(&v, sizeof(v));
  return v;
}

static uint64 rd_u64() {
  uint64 v;
  rd(&v, sizeof(v));
  return v;
}

static char *rd_str() {
  uint32 n = rd_u32();
  char *s = palloc(n + 1);
  rd(s, n);
  s[n] = '\0';
  return s;
}

static void dump_cb(void *data, int len) { wr(data, len); }

static int load_cb(void *buf, int minread, int maxread) {
  size_t want = (size_t)maxread;
  if (want > TmpLeft)
    want = TmpLeft;
  size_t got = fread(buf, 1, want, TmpFile);
  TmpLeft -= got;
  return (int)got;
}

int temp_dump(const char *name) {
  char path[MAXPGPATH];
  temp_path(name, path);

  if (SPI_connect() != SPI_OK_CONNECT)
    elog(ERROR, "pgr: SPI_connect failed");

  if (SPI_execute("SELECT relid, table_name, columns_ddl, post_ddl "
                  "FROM pgr.tdescribe()",
                  true, 0) != SPI_OK_SELECT)
    elog(ERROR, "pgr: tdescribe failed");

  uint64 n = SPI_processed;
  SPITupleTable *tt = SPI_tuptable;

  if (n == 0) {
    SPI_finish();
    return 0;
  }

  MakePGDirectory("temptables");
  TmpFile = AllocateFile(path, PG_BINARY_W);
  if (!TmpFile)
    ereport(ERROR, (errcode_for_file_access(),
                    errmsg("pgr: cannot create \"%s\": %m", path)));

  wr_u32((uint32)n);
  for (uint64 i = 0; i < n; i++) {
    HeapTuple t = tt->vals[i];
    bool isnull;
    Oid relid = DatumGetObjectId(SPI_getbinval(t, tt->tupdesc, 1, &isnull));

    wr_str(SPI_getvalue(t, tt->tupdesc, 2));
    wr_str(SPI_getvalue(t, tt->tupdesc, 3));
    wr_str(SPI_getvalue(t, tt->tupdesc, 4));

    wr_u64(0);
    off_t start = ftello(TmpFile);

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

    off_t end = ftello(TmpFile);
    fseeko(TmpFile, start - (off_t)sizeof(uint64), SEEK_SET);
    wr_u64((uint64)(end - start));
    fseeko(TmpFile, end, SEEK_SET);
  }

  FreeFile(TmpFile);
  TmpFile = NULL;
  SPI_finish();
  return (int)n;
}

int temp_restore(const char *name) {
  char path[MAXPGPATH];
  temp_path(name, path);

  TmpFile = AllocateFile(path, PG_BINARY_R);
  if (!TmpFile)
    ereport(ERROR, (errcode_for_file_access(),
                    errmsg("pgr: cannot open \"%s\": %m", path)));

  if (SPI_connect() != SPI_OK_CONNECT)
    elog(ERROR, "pgr: SPI_connect failed");

  uint32 n = rd_u32();
  for (uint32 i = 0; i < n; i++) {
    char *tname = rd_str();
    char *cols = rd_str();
    char *post = rd_str();
    uint64 len = rd_u64();
    off_t next = ftello(TmpFile) + (off_t)len;

    StringInfoData sql;
    initStringInfo(&sql);
    appendStringInfo(&sql, "CREATE TEMP TABLE %s (%s)", quote_identifier(tname),
                     cols);
    if (SPI_execute(sql.data, false, 0) < 0)
      elog(ERROR, "pgr: cannot create temp table");

    Relation rel =
        table_openrv(makeRangeVar("pg_temp", tname, -1), RowExclusiveLock);
    ParseState *pstate = make_parsestate(NULL);
    ParseNamespaceItem *nsitem = addRangeTableEntryForRelation(
        pstate, rel, RowExclusiveLock, NULL, false, false);
    nsitem->p_perminfo->requiredPerms = ACL_INSERT;
    List *opts =
        list_make1(makeDefElem("format", (Node *)makeString("binary"), -1));

    TmpLeft = len;
    CopyFromState cs =
        BeginCopyFrom(pstate, rel, NULL, NULL, false, load_cb, NIL, opts);
    CopyFrom(cs);
    EndCopyFrom(cs);
    free_parsestate(pstate);
    table_close(rel, RowExclusiveLock);

    fseeko(TmpFile, next, SEEK_SET);

    if (post[0] && SPI_execute(post, false, 0) < 0)
      elog(ERROR, "pgr: cannot restore constraints and indexes");
  }

  SPI_finish();
  FreeFile(TmpFile);
  TmpFile = NULL;
  return (int)n;
}

bool temp_dump_safe(const char *name) {
  bool ok = false;
  char path[MAXPGPATH];
  MemoryContext oldcxt = CurrentMemoryContext;
  ResourceOwner oldowner = CurrentResourceOwner;

  snprintf(path, sizeof(path), "temptables/%s.bin", name);

  BeginInternalSubTransaction(NULL);
  PG_TRY();
  {
    bool pushed = false;
    if (!ActiveSnapshotSet()) {
      PushActiveSnapshot(GetTransactionSnapshot());
      pushed = true;
    }
    ok = temp_dump(name) > 0;
    if (pushed)
      PopActiveSnapshot();
    ReleaseCurrentSubTransaction();
  }
  PG_CATCH();
  {
    MemoryContextSwitchTo(oldcxt);
    ErrorData *edata = CopyErrorData();
    FlushErrorState();
    RollbackAndReleaseCurrentSubTransaction();
    TmpFile = NULL;
    unlink(path);
    ereport(WARNING,
            (errmsg("pgr: temp tables dump failed: %s", edata->message)));
    FreeErrorData(edata);
    ok = false;
  }
  PG_END_TRY();

  MemoryContextSwitchTo(oldcxt);
  CurrentResourceOwner = oldowner;
  return ok;
}
