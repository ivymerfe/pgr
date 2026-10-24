#include "pgr.h"

#include "access/xact.h"
#include "access/xlog.h"
#include "lib/stringinfo.h"
#include "nodes/params.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"

#define TX_BUF_LIMIT (64 * 1024 * 1024)

bool CaptureLive = false;

static char CaptureBuffer[1024 * 1024];
static size_t CaptureBufferPos = 0;
static bool CaptureOverflow = false;

static StringInfoData TxBuf;
static bool TxBufInit = false;
static bool TxBufOverflow = false;

static void cap_raw(const void *data, size_t len) {
  if (CaptureOverflow || CaptureBufferPos + len > sizeof(CaptureBuffer)) {
    CaptureOverflow = true;
    return;
  }
  memcpy(&CaptureBuffer[CaptureBufferPos], data, len);
  CaptureBufferPos += len;
}

static void cap_u8(uint8_t v) { cap_raw(&v, sizeof(v)); }
static void cap_u16(uint16_t v) { cap_raw(&v, sizeof(v)); }
static void cap_u32(uint32_t v) { cap_raw(&v, sizeof(v)); }
static void cap_u64(uint64_t v) { cap_raw(&v, sizeof(v)); }

static void cap_bytes(const char *data, uint32_t len) {
  cap_u32(len);
  cap_raw(data, len);
}

static void cap_str(const char *str) { cap_bytes(str, strlen(str)); }

static void cap_begin(uint8_t type) {
  CaptureBufferPos = 0;
  CaptureOverflow = false;
  cap_u8(type);
  cap_u32(MyClientId);
  cap_u64(GetCurrentTimestamp());
}

static void ring_send(const char *data, size_t len) {
  ring_push(&Shmem->capture_ring, data, len);
  wakeup_capture_worker();
}

static void txbuf_add(const char *data, size_t len) {
  if (!TxBufInit) {
    MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);
    initStringInfo(&TxBuf);
    MemoryContextSwitchTo(old);
    TxBufInit = true;
  }
  if (TxBufOverflow)
    return;
  if (TxBuf.len + len + sizeof(uint32_t) > TX_BUF_LIMIT) {
    TxBufOverflow = true;
    return;
  }
  uint32_t l = (uint32_t)len;
  appendBinaryStringInfo(&TxBuf, (char *)&l, sizeof(l));
  appendBinaryStringInfo(&TxBuf, data, len);
}

static void cap_end() {
  if (CaptureOverflow) {
    ereport(WARNING, (errmsg("pgr: capture message dropped, too large")));
  } else if (CaptureBufferPos > 0) {
    if (CaptureLive)
      ring_send(CaptureBuffer, CaptureBufferPos);
    else
      txbuf_add(CaptureBuffer, CaptureBufferPos);
  }
  CaptureBufferPos = 0;
  CaptureOverflow = false;
}

void capture_txbuf_reset() {
  TxBufOverflow = false;
  if (!TxBufInit)
    return;
  if (TxBuf.maxlen > 16 * 1024 * 1024) {
    pfree(TxBuf.data);
    TxBufInit = false;
  } else {
    resetStringInfo(&TxBuf);
  }
}

void capture_go_live(const char *session) {
  CaptureLive = true;
  cap_begin(MsgTypeConnect);
  cap_str(session);
  cap_end();

  if (TxBufInit && TxBufOverflow) {
    ereport(WARNING, (errmsg("pgr: pending transaction too large, dropped")));
  } else if (TxBufInit) {
    size_t pos = 0;
    while (pos < (size_t)TxBuf.len) {
      uint32_t l;
      memcpy(&l, TxBuf.data + pos, sizeof(l));
      pos += sizeof(l);
      ring_send(TxBuf.data + pos, l);
      pos += l;
    }
  }
  capture_txbuf_reset();
}

void capture_sync_lsn() {
  cap_begin(MsgTypeLsn);
  cap_u64(GetXLogInsertRecPtr());
  if (!CaptureOverflow)
    ring_send(CaptureBuffer, CaptureBufferPos);
  CaptureBufferPos = 0;
  pg_atomic_write_u32(&Shmem->wal_ready, 1);
}

void capture_disconnect() {
  cap_begin(MsgTypeDisconnect);
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
    if (p->isnull) {
      cap_u32(UINT32_MAX);
      continue;
    }
    Oid outfunc;
    bool isvarlena;
    getTypeOutputInfo(p->ptype, &outfunc, &isvarlena);
    char *s = OidOutputFunctionCall(outfunc, p->value);
    cap_bytes(s, strlen(s));
    pfree(s);
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

void capture_tx_end(bool committed) {
  cap_begin(MsgTypeTxEnd);
  cap_u8(committed);
  cap_u32(GetTopTransactionIdIfAny());
  cap_u64(GetXLogInsertRecPtr());
  cap_end();
}
