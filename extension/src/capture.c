#include "pgr.h"

#include "commands/prepare.h"
#include "fmgr.h"
#include "nodes/params.h"
#include "tcop/tcopprot.h"
#include "utils/guc_tables.h"
#include "utils/lsyscache.h"
#include "utils/timestamp.h"

static char CaptureBuffer[1024 * 1024];
static size_t CaptureBufferPos = 0;

static void cap_u8(uint8_t value) {
  if (CaptureBufferPos + sizeof(value) > sizeof(CaptureBuffer)) {
    return;
  }
  CaptureBuffer[CaptureBufferPos++] = value;
}

static void cap_u16(uint16_t value) {
  if (CaptureBufferPos + sizeof(value) > sizeof(CaptureBuffer)) {
    return;
  }
  memcpy(&CaptureBuffer[CaptureBufferPos], &value, sizeof(value));
  CaptureBufferPos += sizeof(value);
}

static void cap_u32(uint32_t value) {
  if (CaptureBufferPos + sizeof(value) > sizeof(CaptureBuffer)) {
    return;
  }
  memcpy(&CaptureBuffer[CaptureBufferPos], &value, sizeof(value));
  CaptureBufferPos += sizeof(value);
}

static void cap_u64(uint64_t value) {
  if (CaptureBufferPos + sizeof(value) > sizeof(CaptureBuffer)) {
    return;
  }
  memcpy(&CaptureBuffer[CaptureBufferPos], &value, sizeof(value));
  CaptureBufferPos += sizeof(value);
}

static void cap_str(const char *str) {
  size_t len = strlen(str);
  if (CaptureBufferPos + len + 4 > sizeof(CaptureBuffer)) {
    return;
  }
  cap_u32(len);
  memcpy(&CaptureBuffer[CaptureBufferPos], str, len);
  CaptureBufferPos += len;
}

static void cap_begin(uint8_t type) {
  CaptureBufferPos = 0;
  cap_u8(type);
  cap_u32(MyClientId);
  cap_u64(GetCurrentTimestamp());
}

static void cap_end() {
  if (CaptureBufferPos > 0) {
    ereport(LOG, (errmsg("pgr: sending capture message of size %zu",
                         CaptureBufferPos)));
    ring_push(&Shmem->capture_ring, CaptureBuffer, CaptureBufferPos);
    CaptureBufferPos = 0;
    if (Shmem->worker_latch) {
      SetLatch(Shmem->worker_latch);
    }
  }
}
static void cap_patch_u32(size_t pos, uint32_t value) {
  memcpy(&CaptureBuffer[pos], &value, sizeof(value));
}

static bool guc_is_session_state(struct config_generic *guc) {
  if (guc->context == PGC_INTERNAL || guc->context == PGC_POSTMASTER)
    return false;
  return guc->source >= PGC_S_DATABASE && guc->source != PGC_S_OVERRIDE;
}

static void cap_plansource(const char *name, bool from_sql,
                           CachedPlanSource *src) {
  cap_str(name);
  cap_u8(from_sql);
  cap_str(src->query_string);
  cap_u16(src->num_params);
  for (int i = 0; i < src->num_params; i++)
    cap_u32(src->param_types[i]);
}

static void cap_prepared(PreparedStatement *ps, void *arg) {
  cap_plansource(ps->stmt_name, ps->from_sql, ps->plansource);
  (*(uint32_t *)arg)++;
}

void capture_session_info() {
  cap_begin(MsgTypeSessionInfo);

  int num_vars;
  struct config_generic **gucs = get_guc_variables(&num_vars);

  size_t guc_count_pos = CaptureBufferPos;
  uint32_t guc_count = 0;
  cap_u32(0);

  for (int i = 0; i < num_vars; i++) {
    struct config_generic *guc = gucs[i];
    if (!guc_is_session_state(guc))
      continue;

    char *val = ShowGUCOption(guc, false);
    cap_str(guc->name);
    cap_str(val ? val : "");
    cap_u8(guc->source);
    guc_count++;
  }
  cap_patch_u32(guc_count_pos, guc_count);

  size_t prep_count_pos = CaptureBufferPos;
  uint32_t prep_count = 0;
  cap_u32(0);

  CachedPlanSource *unnamed = GetUnnamedStatementSource();
  if (unnamed) {
    cap_plansource("", false, unnamed);
    prep_count++;
  }

  ForEachPreparedStatement(cap_prepared, &prep_count);
  cap_patch_u32(prep_count_pos, prep_count);

  cap_end();
}

void capture_parse(const char *stmt_name, const char *query, Oid *types,
                   int n) {
  cap_begin(MsgTypeParse);
  cap_str(stmt_name ? stmt_name : "");
  cap_str(query);
  cap_u16(n);
  for (int i = 0; i < n; i++)
    cap_u32(types ? types[i] : 0);
  cap_end();
}

void capture_simple_query(const char *query) {
  cap_begin(MsgTypeSimpleQuery);
  cap_str(query);
  cap_end();
}

void capture_bind(const char *portal, const char *stmt, int nrf, int16 *rf,
                  int np, ParamListInfo params) {
  cap_begin(MsgTypeBind);
  cap_str(portal ? portal : "");
  cap_str(stmt ? stmt : "");
  cap_u16(nrf);
  for (int i = 0; i < nrf; i++)
    cap_u16((uint16_t)rf[i]);
  if (!params)
    np = 0;
  cap_u16(np);
  for (int i = 0; i < np; i++) {
    ParamExternData *p = &params->params[i];
    cap_u32(p->ptype);
    cap_u8(p->isnull);
    if (!p->isnull) {
      Oid outfunc;
      bool isvarlena;
      getTypeOutputInfo(p->ptype, &outfunc, &isvarlena);
      char *s = OidOutputFunctionCall(outfunc, p->value);
      cap_str(s);
      pfree(s);
    }
  }
  cap_end();
}

void capture_execute(const char *portal, long max_rows) {
  cap_begin(MsgTypeExecute);
  cap_str(portal ? portal : "");
  cap_u64((uint64_t)(int64_t)max_rows);
  cap_end();
}

void capture_sync() {
  cap_begin(MsgTypeSync);
  cap_end();
}
