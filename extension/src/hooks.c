#include "pgr.h"

#include "access/xact.h"
#include "catalog/namespace.h"
#include "executor/executor.h"
#include "libpq/auth.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"
#include "nodes/plannodes.h"
#include "optimizer/planner.h"
#include "parser/analyze.h"
#include "storage/ipc.h"
#include "storage/shmem.h"
#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/elog.h"
#include "utils/timestamp.h"

static shmem_startup_hook_type prev_shmem_startup = NULL;
static shmem_startup_hook_type prev_shmem_request = NULL;

static exec_parse_message_hook_type prev_exec_parse_message_hook = NULL;
static exec_simple_query_hook_type prev_exec_simple_query_hook = NULL;
static exec_bind_message_hook_type prev_exec_bind_message_hook = NULL;
static exec_execute_message_hook_type prev_exec_execute_message_hook = NULL;
static pq_msg_sync_hook_type prev_pq_msg_sync_hook = NULL;
static pq_msg_close_hook_type prev_pq_msg_close_hook = NULL;

static ClientAuthentication_hook_type prev_ClientAuthentication = NULL;
static post_parse_analyze_hook_type prev_post_parse_analyze = NULL;
static planner_hook_type prev_planner = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

uint32 MyCaptureGen = 0;
uint32 MyClientId = 0;
uint64 StatementIndex = 0;

static bool TxOpen = false;
static uint32 TxGen = 0;
static bool TxCaptured = false;
static char SessionName[64];
static bool SkipSnap = false;

static bool IsUserTransaction = false;

static bool ExitRegistered = false;
static bool ExitLateRegistered = false;
static bool TempCommitted = false;
static bool ExitDone = false;

static void pgr_exit(int code, Datum arg) {
  if (!Shmem || ExitDone) {
    return;
  }
  ExitDone = true;
  AbortOutOfAnyTransaction();
  if (CaptureLive && is_capture_running() &&
      MyCaptureGen == get_capture_generation()) {
    capture_disconnect();
    if (pg_atomic_read_u32(&Shmem->session_debug_enabled)) {
      char session_name[64];
      snprintf(session_name, sizeof(session_name), "d/%d", MyClientId);
      session_start(session_name);
      session_stop();
    }
  }
  if (MyReplayId != -1 && pg_atomic_read_u32(&Shmem->session_debug_enabled)) {
    char session_name[64];
    snprintf(session_name, sizeof(session_name), "r/%d", MyReplayId);
    session_start(session_name);
    session_stop();
  }
}

static void ensure_exit_registered(void) {
  if (!is_replay_client() && !is_capture_running()) {
    return;
  }
  if (!ExitRegistered) {
    before_shmem_exit(pgr_exit, 0);
    ExitRegistered = true;
  }
  if (TempCommitted && !ExitLateRegistered) {
    before_shmem_exit(pgr_exit, 1);
    ExitLateRegistered = true;
  }
}

static void go_live() {
  bool ok = session_active();
  session_stop();
  capture_go_live(ok ? SessionName : "");
}

static bool capture_gate() {
  if (MyBackendType != B_BACKEND) {
    return false;
  }
  if (!TxOpen && IsTransactionState()) {
    TxGen = xact_enter_shared();
    TxOpen = true;
    TxCaptured = false;
    if (!CaptureLive) {
      capture_txbuf_reset();
    }
  }
  if (!is_capture_running()) {
    return false;
  }
  if (TxOpen && xact_is_pre(TxGen)) {
    return false;
  }
  uint32 gen = get_capture_generation();
  if (MyCaptureGen != gen) {
    session_stop();
    capture_txbuf_reset();
    CaptureLive = false;
    MyCaptureGen = gen;
    MyClientId = acquire_client_id();
    snprintf(SessionName, sizeof(SessionName), "%u/%u",
             pg_atomic_read_u32(&Shmem->capture_id), MyClientId);
    SkipSnap = StatementIndex <= 1 && pg_atomic_read_u32(&Shmem->wal_ready);
  }
  if (!CaptureLive && !TxOpen) {
    return false;
  }
  if (!CaptureLive && !TxCaptured) {
    if (SkipSnap) {
      SkipSnap = false;
      session_stop();
    } else {
      session_start(SessionName);
    }
  }
  if (!CaptureLive && pg_atomic_read_u32(&Shmem->wal_ready)) {
    go_live();
  }
  if (TxOpen) {
    TxCaptured = true;
  }
  return true;
}

static void tx_finish(bool committed) {
  if (!TxOpen) {
    return;
  }
  TxOpen = false;
  bool last = xact_leave_shared(TxGen);
  if (TxCaptured && is_capture_running() &&
      MyCaptureGen == get_capture_generation()) {
    if (!CaptureLive && pg_atomic_read_u32(&Shmem->wal_ready)) {
      go_live();
    }
    if (CaptureLive) {
      capture_tx_end(committed);
    }
  }
  if (!CaptureLive) {
    capture_txbuf_reset();
  }
  TxCaptured = false;
  if (last) {
    capture_sync_lsn();
  }
}

static void pgr_xact_callback(XactEvent event, void* arg) {
  if (MyBackendType != B_BACKEND || !Shmem) {
    return;
  }
  ensure_exit_registered();
  if ((event == XACT_EVENT_COMMIT || event == XACT_EVENT_PREPARE) &&
      OidIsValid(GetTempToastNamespace())) {
    TempCommitted = true;
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
  if (!is_replay_client()) {
    return;
  }
  if (event == XACT_EVENT_PRE_COMMIT && IsUserTransaction) {
    trace_begin();
  }
  if (event == XACT_EVENT_COMMIT && IsUserTransaction) {
    trace_end('C');
    pg_atomic_fetch_add_u64(&Shmem->commits, 1);
    IsUserTransaction = false;
  }
  if (event == XACT_EVENT_ABORT && IsUserTransaction) {
    trace_end('A');
    pg_atomic_fetch_add_u64(&Shmem->aborts, 1);
    IsUserTransaction = false;
  }
}

static void pgr_exec_parse_message_hook(const char* query_string,
                                        const char* stmt_name,
                                        Oid* paramTypes,
                                        int numParams) {
  if (prev_exec_parse_message_hook) {
    prev_exec_parse_message_hook(query_string, stmt_name, paramTypes,
                                 numParams);
  }
  StatementIndex++;
  if (capture_gate()) {
    capture_parse(stmt_name, query_string, paramTypes, numParams);
  }
}

static void pgr_exec_simple_query_hook(const char* query_string) {
  if (prev_exec_simple_query_hook) {
    prev_exec_simple_query_hook(query_string);
  }
  StatementIndex++;
  if (capture_gate()) {
    capture_simple_query(query_string);
  }
}

static void pgr_exec_bind_message_hook(const char* portal_name,
                                       const char* stmt_name,
                                       int numPFormats,
                                       int16* pformats,
                                       int numRFormats,
                                       int16* rformats,
                                       int numParams,
                                       ParamListInfo params) {
  if (prev_exec_bind_message_hook) {
    prev_exec_bind_message_hook(portal_name, stmt_name, numPFormats, pformats,
                                numRFormats, rformats, numParams, params);
  }
  StatementIndex++;
  if (capture_gate()) {
    capture_bind(portal_name, stmt_name, numRFormats, rformats, numParams,
                 params);
  }
}

static void pgr_exec_execute_message_hook(const char* portal_name,
                                          long max_rows) {
  if (prev_exec_execute_message_hook) {
    prev_exec_execute_message_hook(portal_name, max_rows);
  }
  StatementIndex++;
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

static void pgr_pq_msg_close_hook(int close_type, const char* close_target) {
  if (prev_pq_msg_close_hook) {
    prev_pq_msg_close_hook(close_type, close_target);
  }
  if (capture_gate()) {
    capture_close(close_type, close_target);
  }
}

static void pgr_ClientAuthentication_hook(struct Port* port, int status) {
  if (prev_ClientAuthentication) {
    prev_ClientAuthentication(port, status);
  }
  read_replay_client_id(port);
}

static void pgr_post_parse_analyze_hook(ParseState* pstate,
                                        Query* query,
                                        const JumbleState* jstate) {
  if (is_replay_client()) {
    long secs;
    int usecs;
    TimestampDifference(GetCurrentStatementStartTimestamp(),
                        GetCurrentTimestamp(), &secs, &usecs);
    uint32 parse_duration = (uint32)(secs * 1000000L + usecs);
    send_trace_event('p', parse_duration);
  }
  if (prev_post_parse_analyze) {
    prev_post_parse_analyze(pstate, query, jstate);
  }
}

static PlannedStmt* pgr_planner_hook(Query* parse,
                                     const char* query_string,
                                     int cursorOptions,
                                     ParamListInfo boundParams,
                                     ExplainState* es) {
  PlannedStmt* result;

  trace_begin();
  if (prev_planner) {
    result = prev_planner(parse, query_string, cursorOptions, boundParams, es);
  } else {
    result =
        standard_planner(parse, query_string, cursorOptions, boundParams, es);
  }
  trace_end('P');
  return result;
}

static void pgr_ExecutorStart_hook(QueryDesc* queryDesc, int eflags) {
  IsUserTransaction = true;
  trace_begin();
  if (prev_ExecutorStart) {
    prev_ExecutorStart(queryDesc, eflags);
  } else {
    standard_ExecutorStart(queryDesc, eflags);
  }
  trace_end('S');
}

static void pgr_ExecutorRun_hook(QueryDesc* queryDesc,
                                 ScanDirection direction,
                                 uint64 count) {
  trace_begin();
  if (prev_ExecutorRun) {
    prev_ExecutorRun(queryDesc, direction, count);
  } else {
    standard_ExecutorRun(queryDesc, direction, count);
  }
  trace_end('E');
}

static void pgr_ProcessUtility_hook(PlannedStmt* pstmt,
                                    const char* queryString,
                                    bool readOnlyTree,
                                    ProcessUtilityContext context,
                                    ParamListInfo params,
                                    QueryEnvironment* queryEnv,
                                    DestReceiver* dest,
                                    QueryCompletion* qc) {
  IsUserTransaction = true;
  if (is_replay_client() && IsTransactionBlock()) {
    Node* parsetree = pstmt->utilityStmt;
    if (IsA(parsetree, TransactionStmt)) {
      TransactionStmt* stmt = (TransactionStmt*)parsetree;
      if (stmt->kind == TRANS_STMT_ROLLBACK) {
        pg_atomic_fetch_add_u64(&Shmem->rollbacks, 1);
      }
    }
  }
  trace_begin();
  if (prev_ProcessUtility) {
    prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params,
                        queryEnv, dest, qc);
  } else {
    standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params,
                            queryEnv, dest, qc);
  }
  trace_end('U');
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
      (SharedMemory*)ShmemInitStruct("pgr", sizeof(SharedMemory), &found_mem);
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

  prev_pq_msg_close_hook = pq_msg_close_hook;
  pq_msg_close_hook = pgr_pq_msg_close_hook;

  prev_ClientAuthentication = ClientAuthentication_hook;
  ClientAuthentication_hook = pgr_ClientAuthentication_hook;

  prev_post_parse_analyze = post_parse_analyze_hook;
  post_parse_analyze_hook = pgr_post_parse_analyze_hook;

  prev_planner = planner_hook;
  planner_hook = pgr_planner_hook;

  prev_ExecutorStart = ExecutorStart_hook;
  ExecutorStart_hook = pgr_ExecutorStart_hook;

  prev_ExecutorRun = ExecutorRun_hook;
  ExecutorRun_hook = pgr_ExecutorRun_hook;

  prev_ProcessUtility = ProcessUtility_hook;
  ProcessUtility_hook = pgr_ProcessUtility_hook;

  RegisterXactCallback(pgr_xact_callback, NULL);
}
