#include "pgr.h"

#include "lib/stringinfo.h"
#include "nodes/params.h"
#include "portability/instr_time.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"

#define TX_BUF_LIMIT (64 * 1024 * 1024)
#define DURATION_OFFSET (sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t))

typedef struct {
  char* data;
  size_t cap;
  size_t pos;
  bool overflow;
} CapBuf;

bool CaptureLive = false;

static char CmdData[1024 * 1024];
static char MsgData[4096];
static CapBuf CmdBuf = {CmdData, sizeof(CmdData), 0, false};
static CapBuf MsgBuf = {MsgData, sizeof(MsgData), 0, false};

static bool CmdPending = false;
static instr_time CmdStart;
static uint32 CmdGen = 0;

static StringInfoData TxBuf;
static bool TxBufInit = false;
static bool TxBufOverflow = false;

static void cap_raw(CapBuf* b, const void* data, size_t len) {
  if (b->overflow || b->pos + len > b->cap) {
    b->overflow = true;
    return;
  }
  memcpy(b->data + b->pos, data, len);
  b->pos += len;
}

static void cap_u8(CapBuf* b, uint8_t v) {
  cap_raw(b, &v, sizeof(v));
}

static void cap_u16(CapBuf* b, uint16_t v) {
  cap_raw(b, &v, sizeof(v));
}

static void cap_u32(CapBuf* b, uint32_t v) {
  cap_raw(b, &v, sizeof(v));
}

static void cap_u64(CapBuf* b, uint64_t v) {
  cap_raw(b, &v, sizeof(v));
}

static void cap_bytes(CapBuf* b, const char* data, uint32_t len) {
  cap_u32(b, len);
  cap_raw(b, data, len);
}

static void cap_str(CapBuf* b, const char* str) {
  cap_bytes(b, str, strlen(str));
}

static void cap_begin(CapBuf* b, uint8_t type) {
  b->pos = 0;
  b->overflow = false;
  cap_u8(b, type);
  cap_u32(b, MyClientId);
  cap_u64(b, GetCurrentTimestamp());
  cap_u32(b, 0);
}

static void cmd_begin(uint8_t type) {
  cap_begin(&CmdBuf, type);
  INSTR_TIME_SET_CURRENT(CmdStart);
  CmdGen = MyCaptureGen;
  CmdPending = true;
}

static void txbuf_add(const char* data, size_t len) {
  if (!TxBufInit) {
    MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);
    initStringInfo(&TxBuf);
    MemoryContextSwitchTo(old);
    TxBufInit = true;
  }
  if (TxBufOverflow) {
    return;
  }
  if (TxBuf.len + len + sizeof(uint32_t) > TX_BUF_LIMIT) {
    TxBufOverflow = true;
    return;
  }
  uint32_t l = (uint32_t)len;
  appendBinaryStringInfo(&TxBuf, (char*)&l, sizeof(l));
  appendBinaryStringInfo(&TxBuf, data, len);
}

static void deliver(CapBuf* b) {
  if (b->overflow) {
    ereport(WARNING, (errmsg("pgr: capture message dropped, too large")));
  } else if (b->pos > 0) {
    if (CaptureLive) {
      if (!channel_push(ChanCapture, b->data, b->pos)) {
        ereport(WARNING,
                (errmsg("pgr: capture channel full, message dropped")));
      }
    } else {
      txbuf_add(b->data, b->pos);
    }
  }
  b->pos = 0;
  b->overflow = false;
}

void capture_cmd_end(bool tx_open) {
  if (!CmdPending) {
    return;
  }
  CmdPending = false;
  if (!channel_running(ChanCapture) ||
      CmdGen != channel_generation(ChanCapture)) {
    return;
  }
  if (!CaptureLive && !tx_open) {
    return;
  }
  instr_time d;
  INSTR_TIME_SET_CURRENT(d);
  INSTR_TIME_SUBTRACT(d, CmdStart);
  uint64 us = INSTR_TIME_GET_MICROSEC(d);
  uint32_t v = us > UINT32_MAX ? UINT32_MAX : (uint32_t)us;
  memcpy(CmdBuf.data + DURATION_OFFSET, &v, sizeof(v));
  deliver(&CmdBuf);
}

void capture_txbuf_reset() {
  TxBufOverflow = false;
  if (!TxBufInit) {
    return;
  }
  if (TxBuf.maxlen > 16 * 1024 * 1024) {
    pfree(TxBuf.data);
    TxBufInit = false;
  } else {
    resetStringInfo(&TxBuf);
  }
}

void capture_go_live(const char* session) {
  CaptureLive = true;
  cap_begin(&MsgBuf, MsgTypeConnect);
  cap_str(&MsgBuf, session);
  deliver(&MsgBuf);

  if (TxBufInit && TxBufOverflow) {
    ereport(WARNING, (errmsg("pgr: pending transaction too large, dropped")));
  } else if (TxBufInit) {
    size_t pos = 0;
    while (pos < (size_t)TxBuf.len) {
      uint32_t l;
      memcpy(&l, TxBuf.data + pos, sizeof(l));
      pos += sizeof(l);
      if (!channel_push(ChanCapture, TxBuf.data + pos, l)) {
        ereport(WARNING,
                (errmsg("pgr: capture channel full while writing pending tx")));
      }
      pos += l;
    }
  }
  capture_txbuf_reset();
}

void capture_lsn(uint64_t lsn) {
  cap_begin(&MsgBuf, MsgTypeLsn);
  cap_u64(&MsgBuf, lsn);
  if (!channel_push(ChanCapture, MsgBuf.data, MsgBuf.pos)) {
    ereport(WARNING, (errmsg("pgr: capture channel full, failed to send lsn")));
  }
  MsgBuf.pos = 0;
  MsgBuf.overflow = false;
}

void capture_disconnect() {
  cap_begin(&MsgBuf, MsgTypeDisconnect);
  deliver(&MsgBuf);
}

void capture_simple_query(const char* query) {
  cmd_begin(MsgTypeSimpleQuery);
  cap_str(&CmdBuf, query);
}

void capture_parse(const char* stmt_name,
                   const char* query,
                   Oid* types,
                   int n) {
  cmd_begin(MsgTypeParse);
  cap_str(&CmdBuf, stmt_name ? stmt_name : "");
  cap_str(&CmdBuf, query);
  cap_u16(&CmdBuf, n);
  for (int i = 0; i < n; i++) {
    cap_u32(&CmdBuf, types ? types[i] : 0);
  }
}

void capture_bind(const char* portal,
                  const char* stmt,
                  int nrf,
                  int16* rf,
                  int np,
                  ParamListInfo params) {
  cmd_begin(MsgTypeBind);
  cap_str(&CmdBuf, portal ? portal : "");
  cap_str(&CmdBuf, stmt ? stmt : "");
  cap_u16(&CmdBuf, nrf);
  for (int i = 0; i < nrf; i++) {
    cap_u16(&CmdBuf, (uint16_t)rf[i]);
  }
  if (!params) {
    np = 0;
  }
  cap_u16(&CmdBuf, np);
  for (int i = 0; i < np; i++) {
    ParamExternData* p = &params->params[i];
    cap_u32(&CmdBuf, p->ptype);
    if (p->isnull) {
      cap_u32(&CmdBuf, UINT32_MAX);
      continue;
    }
    Oid outfunc;
    bool isvarlena;
    getTypeOutputInfo(p->ptype, &outfunc, &isvarlena);
    char* s = OidOutputFunctionCall(outfunc, p->value);
    cap_bytes(&CmdBuf, s, strlen(s));
    pfree(s);
  }
}

void capture_execute(const char* portal, long max_rows) {
  cmd_begin(MsgTypeExecute);
  cap_str(&CmdBuf, portal ? portal : "");
  cap_u64(&CmdBuf, (uint64_t)(int64_t)max_rows);
}

void capture_close(int close_type, const char* target) {
  cmd_begin(MsgTypeClose);
  cap_u8(&CmdBuf, (uint8_t)close_type);
  cap_str(&CmdBuf, target ? target : "");
}

void capture_sync() {
  cmd_begin(MsgTypeSync);
}
