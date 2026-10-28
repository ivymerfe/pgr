#pragma once

#include "postgres.h"

#include "libpq/libpq-be.h"
#include "nodes/params.h"
#include "port/atomics.h"
#include "postgres.h"
#include "storage/latch.h"
#include "storage/spin.h"

#include "ring.h"

typedef struct {
  pg_atomic_uint32 capture_id;
  pg_atomic_uint32 capture_running;
  pg_atomic_uint32 capture_generation;
  pg_atomic_uint32 next_client_id;
  pg_atomic_uint32 wal_ready;

  pg_atomic_uint32 session_debug_enabled;

  slock_t lock;
  uint32 open_xacts;
  uint32 pending_xacts;

  Latch* capture_worker_latch;
  MpscRing capture_ring;

  pg_atomic_uint32 trace_id;
  pg_atomic_uint32 trace_running;
  pg_atomic_uint32 trace_generation;

  Latch* trace_worker_latch;
  MpscRing trace_ring;

  pg_atomic_uint64 commits;
  pg_atomic_uint64 aborts;
  pg_atomic_uint64 rollbacks;
} SharedMemory;

extern SharedMemory* Shmem;

extern uint32 MyCaptureGen;
extern uint32 MyClientId;
extern bool CaptureLive;

extern int32 MyReplayId;
extern uint64 StatementIndex;

enum {
  MsgTypeLsn = 1,
  MsgTypeConnect,
  MsgTypeDisconnect,
  MsgTypeSimpleQuery,
  MsgTypeParse,
  MsgTypeBind,
  MsgTypeExecute,
  MsgTypeSync,
  MsgTypeTxEnd,
};

void setup_hooks();
void shmem_init();

void register_capture_worker();
void wakeup_capture_worker();

uint32 reserve_id(const char* subdir, const char* ext);

// session

bool session_start(const char* name);
void session_stop(void);
bool session_active(void);
int session_restore(const char* name);

// capture

uint32 capture_start();
void capture_stop();
bool is_capture_running();
uint32 get_capture_generation();
uint32 acquire_client_id();

void capture_txbuf_reset(void);
void capture_go_live(const char* session);
void capture_sync_lsn(void);
void capture_disconnect(void);
void capture_parse(const char* stmt_name, const char* query, Oid* types, int n);
void capture_simple_query(const char* query);
void capture_bind(const char* portal,
                  const char* stmt,
                  int nrf,
                  int16* rf,
                  int np,
                  ParamListInfo params);
void capture_execute(const char* portal, long max_rows);
void capture_sync(void);
void capture_tx_end(bool committed);

uint32 xact_enter_shared();
bool xact_leave_shared(uint32 gen);
bool xact_is_pre(uint32 gen);

// trace

void read_replay_client_id(Port* port);
bool is_replay_client();

void register_trace_worker();
void wakeup_trace_worker();

uint32 trace_start();
void trace_stop();
bool is_trace_running();
uint32 get_trace_generation();

void send_trace_event(char event_type, uint32 duration_us);
void trace_begin();
void trace_end(char event_type);
