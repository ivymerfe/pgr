#include "pgr.h"

#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/shmem.h"
#include "tcop/tcopprot.h"
#include "access/xact.h"
#include "access/xlog.h"

static shmem_startup_hook_type prev_shmem_startup = NULL;
static shmem_startup_hook_type prev_shmem_request = NULL;

static exec_parse_message_hook_type prev_exec_parse_message_hook = NULL;
static exec_simple_query_hook_type prev_exec_simple_query_hook = NULL;
static exec_bind_message_hook_type prev_exec_bind_message_hook = NULL;
static exec_execute_message_hook_type prev_exec_execute_message_hook = NULL;
static pq_msg_sync_hook_type prev_pq_msg_sync_hook = NULL;

uint32 MyCaptureId = 0;
uint32 MyClientId = 0;

static bool TxOpen = false;
static uint32 TxGen = 0;
static uint32 TxStartSentId = 0;

static void check_for_capture() {
  uint32 current_capture_id = get_capture_id();
  if (MyCaptureId == current_capture_id) {
    return;
  }
  MyCaptureId = current_capture_id;
  MyClientId = acquire_client_id();
  capture_session_info();
}


static void tx_track() {
  if (TxOpen || !IsTransactionState()) {
    return;
  }
  TxGen = xact_enter_shared();
  TxOpen = true;
  TxStartSentId = 0;
}

static bool capture_gate() {
  if (MyBackendType != B_BACKEND) {
    return false;
  }
  tx_track();
  if (!is_capture_running()) {
    return false;
  }
  if (TxOpen && xact_is_pre(TxGen)) {
    return false;
  }
  check_for_capture();
  if (TxOpen && !pg_atomic_read_u32(&Shmem->wal_ready) &&
      TxStartSentId != MyCaptureId) {
    capture_tx_start();
    TxStartSentId = MyCaptureId;
  }
  return true;
}

static void tx_finish(bool committed) {
  if (!TxOpen) {
    return;
  }
  TxOpen = false;
  bool sent = TxStartSentId != 0 && is_capture_running() &&
              TxStartSentId == get_capture_id();
  bool last = xact_leave_shared(TxGen);
  TxStartSentId = 0;
  if (sent) {
    capture_tx_end(committed);
  }
  if (last) {
    XLogRecPtr lsn = GetXLogInsertRecPtr();
    pg_atomic_write_u32(&Shmem->wal_ready, 1);
    capture_lsn(lsn);
  }
}

static void pgr_xact_callback(XactEvent event, void *arg) {
  if (MyBackendType != B_BACKEND) {
    return;
  }
  switch (event) {
  case XACT_EVENT_COMMIT:
  case XACT_EVENT_PREPARE:
    tx_finish(true);
    break;
  case XACT_EVENT_ABORT:
    tx_finish(false);
    break;
  default:
    break;
  }
}

static void pgr_exec_parse_message_hook(const char *query_string,
                                        const char *stmt_name, Oid *paramTypes,
                                        int numParams) {
  if (prev_exec_parse_message_hook) {
    prev_exec_parse_message_hook(query_string, stmt_name, paramTypes,
                                 numParams);
  }
  if (capture_gate()) {
    capture_parse(stmt_name, query_string, paramTypes, numParams);
  }
}

static void pgr_exec_simple_query_hook(const char *query_string) {
  if (prev_exec_simple_query_hook) {
    prev_exec_simple_query_hook(query_string);
  }
  if (capture_gate()) {
    capture_simple_query(query_string);
  }
}

static void pgr_exec_bind_message_hook(const char *portal_name,
                                       const char *stmt_name, int numPFormats,
                                       int16 *pformats, int numRFormats,
                                       int16 *rformats, int numParams,
                                       ParamListInfo params) {
  if (prev_exec_bind_message_hook) {
    prev_exec_bind_message_hook(portal_name, stmt_name, numPFormats, pformats,
                                numRFormats, rformats, numParams, params);
  }
  if (capture_gate()) {
    capture_bind(portal_name, stmt_name, numRFormats, rformats, numParams,
                 params);
  }
}

static void pgr_exec_execute_message_hook(const char *portal_name,
                                          long max_rows) {
  if (prev_exec_execute_message_hook) {
    prev_exec_execute_message_hook(portal_name, max_rows);
  }
  if (capture_gate()) {
    capture_execute(portal_name, max_rows);
  }
}

static void pgr_pq_msg_sync_hook() {
  if (prev_pq_msg_sync_hook) {
    prev_pq_msg_sync_hook();
  }
  if (capture_gate()) {
    capture_sync();
  }
}

static void pgr_shmem_request_hook() {
  if (prev_shmem_request) {
    prev_shmem_request();
  }

  RequestAddinShmemSpace(MAXALIGN(sizeof(SharedMemory)));
}

static void pgr_shmem_startup_hook() {
  if (prev_shmem_startup) {
    prev_shmem_startup();
  }

  bool found_mem;
  Shmem =
      (SharedMemory *)ShmemInitStruct("pgr", sizeof(SharedMemory), &found_mem);
  if (!found_mem) {
    shmem_init();
  }
}

void setup_hooks() {
  prev_shmem_request = shmem_request_hook;
  shmem_request_hook = pgr_shmem_request_hook;

  prev_shmem_startup = shmem_startup_hook;
  shmem_startup_hook = pgr_shmem_startup_hook;

  prev_exec_parse_message_hook = exec_parse_message_hook;
  exec_parse_message_hook = pgr_exec_parse_message_hook;

  prev_exec_simple_query_hook = exec_simple_query_hook;
  exec_simple_query_hook = pgr_exec_simple_query_hook;

  prev_exec_bind_message_hook = exec_bind_message_hook;
  exec_bind_message_hook = pgr_exec_bind_message_hook;

  prev_exec_execute_message_hook = exec_execute_message_hook;
  exec_execute_message_hook = pgr_exec_execute_message_hook;

  prev_pq_msg_sync_hook = pq_msg_sync_hook;
  pq_msg_sync_hook = pgr_pq_msg_sync_hook;

  RegisterXactCallback(pgr_xact_callback, NULL);
}
