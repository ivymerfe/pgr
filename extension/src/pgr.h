#pragma once

#include "postgres.h"

#include "access/xlogdefs.h"
#include "nodes/params.h"
#include "port/atomics.h"
#include "postgres.h"
#include "storage/latch.h"
#include "storage/spin.h"

#include "ring.h"

typedef struct {
  pg_atomic_uint32 capture_running;
  pg_atomic_uint32 capture_id;
  pg_atomic_uint32 next_client_id;
  pg_atomic_uint32 start_gen;
  pg_atomic_uint32 wal_ready;
  slock_t lock;
  uint32 open_xacts;
  uint32 pending_xacts;
  Latch *worker_latch;

  MpscRing capture_ring;
} SharedMemory;

extern SharedMemory *Shmem;

extern uint32 MyCaptureId;
extern uint32 MyClientId;

enum MessageType {
  MsgTypeSessionInfo = 1,
  MsgTypeParse = 2,
  MsgTypeSimpleQuery = 3,
  MsgTypeBind = 4,
  MsgTypeExecute = 5,
  MsgTypeSync = 6,
  MsgTypeTxStart = 7,
  MsgTypeLsn = 8,
  MsgTypeTxEnd = 9,
};

void setup_hooks();
void shmem_init();
void register_capture_worker();

void capture_reset();
void capture_start();
void capture_stop();
bool is_capture_running();

uint32 get_capture_id();
uint32 acquire_client_id();

void capture_session_info();
void capture_parse(const char *stmt_name, const char *query, Oid *types, int n);
void capture_simple_query(const char *query);
void capture_bind(const char *portal, const char *stmt, int nrf, int16 *rf,
                  int np, ParamListInfo params);
void capture_execute(const char *portal, long max_rows);
void capture_sync();

void capture_tx_start();
void capture_tx_end(bool committed);
void capture_lsn(XLogRecPtr lsn);

uint32 xact_enter_shared();
bool xact_leave_shared(uint32 gen);
bool xact_is_pre(uint32 gen);
