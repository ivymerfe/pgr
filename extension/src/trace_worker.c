#include "postgres.h"

#include "pgr.h"

#include "miscadmin.h"
#include "port.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "utils/elog.h"
#include "utils/wait_classes.h"

#include <stdio.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024 * 1024

static FILE* TraceFile = NULL;
static char TraceBuffer[BUFFER_SIZE];
static uint32 WorkerGeneration = 0;

static void close_trace() {
  if (TraceFile != NULL) {
    fclose(TraceFile);
    TraceFile = NULL;
  }
}

static bool open_trace() {
  close_trace();

  char path[MAXPGPATH];
  snprintf(path, sizeof(path), "%s/traces/%u.ptr", DataDir,
           pg_atomic_read_u32(&Shmem->trace_id));

  FILE* f = fopen(path, "w");
  if (f == NULL) {
    ereport(ERROR, (errmsg("pgr: could not open trace file %s", path)));
    return false;
  }
  setvbuf(f, NULL, _IOFBF, 64 * 1024);
  TraceFile = f;
  return true;
}

static int write_events() {
  int count = 0;
  uint32 len;
  while (ring_pop(&Shmem->trace_ring, TraceBuffer, BUFFER_SIZE, &len) ==
         RingOk) {
    if (TraceFile != NULL) {
      fwrite(TraceBuffer, len, 1, TraceFile);
    }
    count += 1;
  }
  if (TraceFile != NULL) {
    fflush(TraceFile);
  }
  return count;
}

PGDLLEXPORT void trace_worker_main(Datum main_arg) {
  pqsignal(SIGTERM, SignalHandlerForShutdownRequest);
  pqsignal(SIGHUP, SignalHandlerForConfigReload);
  BackgroundWorkerUnblockSignals();

  Shmem->trace_worker_latch = &MyProc->procLatch;

  while (!ShutdownRequestPending) {
    uint32 gen = get_trace_generation();
    if (WorkerGeneration != gen || !is_trace_running()) {
      WorkerGeneration = gen;
      close_trace();
    }
    if (is_trace_running() && TraceFile == NULL) {
      if (!open_trace()) {
        break;
      }
    }
    if (write_events() > 0) {
      pg_usleep(1000);
      continue;
    }
    ResetLatch(MyLatch);
    if (write_events() > 0) {
      pg_usleep(1000);
      continue;
    }
    int rc = WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
                       1000L, PG_WAIT_EXTENSION);

    if (rc & WL_POSTMASTER_DEATH) {
      break;
    }
    CHECK_FOR_INTERRUPTS();
  }
  write_events();
  close_trace();
  Shmem->trace_worker_latch = NULL;
}

void register_trace_worker() {
  BackgroundWorker worker;

  memset(&worker, 0, sizeof(worker));
  worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
  worker.bgw_start_time = BgWorkerStart_ConsistentState;
  worker.bgw_restart_time = BGW_NEVER_RESTART;
  snprintf(worker.bgw_library_name, BGW_MAXLEN, "pgr");
  snprintf(worker.bgw_function_name, BGW_MAXLEN, "trace_worker_main");
  snprintf(worker.bgw_name, BGW_MAXLEN, "pgr trace");
  snprintf(worker.bgw_type, BGW_MAXLEN, "pgr");
  RegisterBackgroundWorker(&worker);
}
