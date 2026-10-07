#pragma once

#include "postgres.h"

#include "access/xlogdefs.h"
#include "datatype/timestamp.h"
#include "executor/tuptable.h"
#include "nodes/params.h"
#include "port/atomics.h"
#include "postgres.h"
#include "storage/latch.h"

#include "ring.h"
#include "utils/relcache.h"

typedef struct {
  pg_atomic_uint32 capture_running;
  pg_atomic_uint32 capture_id;
  pg_atomic_uint32 next_client_id;
  Latch *worker_latch;

  MpscRing capture_ring;
  pg_atomic_uint64 start_lsn;
  pg_atomic_uint64 start_ts;
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
  MsgTypeCaptureStart = 7,
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

TimestampTz get_capture_start_ts();
XLogRecPtr get_capture_start_lsn();
