#include "pgr.h"

#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/shmem.h"
#include "tcop/tcopprot.h"

static shmem_startup_hook_type prev_shmem_startup = NULL;
static shmem_startup_hook_type prev_shmem_request = NULL;

static exec_parse_message_hook_type prev_exec_parse_message_hook = NULL;
static exec_simple_query_hook_type prev_exec_simple_query_hook = NULL;
static exec_bind_message_hook_type prev_exec_bind_message_hook = NULL;
static exec_execute_message_hook_type prev_exec_execute_message_hook = NULL;
static pq_msg_sync_hook_type prev_pq_msg_sync_hook = NULL;

uint32 MyCaptureId = 0;
uint32 MyClientId = 0;

static void check_for_capture() {
  if (!is_capture_running()) {
    return;
  }
  uint32 current_capture_id = get_capture_id();
  if (MyCaptureId == current_capture_id) {
    return;
  }
  MyCaptureId = current_capture_id;
  MyClientId = acquire_client_id();
  capture_session_info();
}

static void pgr_exec_parse_message_hook(const char *query_string,
                                        const char *stmt_name, Oid *paramTypes,
                                        int numParams) {
  if (prev_exec_parse_message_hook) {
    prev_exec_parse_message_hook(query_string, stmt_name, paramTypes,
                                 numParams);
  }
  if (MyBackendType != B_BACKEND) {
    return;
  }
  check_for_capture();
  if (is_capture_running()) {
    capture_parse(stmt_name, query_string, paramTypes, numParams);
  }
}

static void pgr_exec_simple_query_hook(const char *query_string) {
  if (prev_exec_simple_query_hook) {
    prev_exec_simple_query_hook(query_string);
  }
  if (MyBackendType != B_BACKEND) {
    return;
  }
  check_for_capture();
  if (is_capture_running()) {
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
  if (MyBackendType != B_BACKEND) {
    return;
  }
  check_for_capture();
  if (is_capture_running()) {
    capture_bind(portal_name, stmt_name, numRFormats, rformats, numParams,
                 params);
  }
}

static void pgr_exec_execute_message_hook(const char *portal_name,
                                          long max_rows) {
  if (prev_exec_execute_message_hook) {
    prev_exec_execute_message_hook(portal_name, max_rows);
  }
  if (MyBackendType != B_BACKEND) {
    return;
  }
  check_for_capture();
  if (is_capture_running()) {
    capture_execute(portal_name, max_rows);
  }
}

static void pgr_pq_msg_sync_hook() {
  if (prev_pq_msg_sync_hook) {
    prev_pq_msg_sync_hook();
  }
  if (MyBackendType != B_BACKEND) {
    return;
  }
  check_for_capture();
  if (is_capture_running()) {
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
}
