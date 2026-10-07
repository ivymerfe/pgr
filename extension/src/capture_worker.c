#include "postgres.h"

#include "pgr.h"

#include "miscadmin.h"
#include "port.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "utils/elog.h"
#include "utils/timestamp.h"
#include "utils/wait_classes.h"

#include <stdio.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024 * 1024

static FILE *CaptureFile = NULL;
static char CaptureBuffer[BUFFER_SIZE];
static uint32 WorkerCaptureId = 0;

static void close_capture() {
  if (CaptureFile != NULL) {
    fclose(CaptureFile);
    CaptureFile = NULL;
  }
}

static bool start_capture() {
  close_capture();

  char dir[MAXPGPATH];
  snprintf(dir, sizeof(dir), "%s/captures", DataDir);
  mkdir(dir, 0700);

  char path[MAXPGPATH];
  snprintf(path, sizeof(path), "%s/%ld.pr", dir, (long)GetCurrentTimestamp());

  FILE *f = fopen(path, "w");
  if (f == NULL) {
    ereport(ERROR, (errmsg("pgr: could not open capture file %s", path)));
    return false;
  }
  setvbuf(f, NULL, _IOFBF, 64 * 1024);
  CaptureFile = f;
  return true;
}

static int write_events() {
  int count = 0;
  uint32 len;
  while (ring_pop(&Shmem->capture_ring, CaptureBuffer, BUFFER_SIZE, &len) ==
         RingOk) {
    if (CaptureFile != NULL) {
      fwrite(CaptureBuffer, len, 1, CaptureFile);
    }
    count += 1;
  }
  if (CaptureFile != NULL) {
    fflush(CaptureFile);
  }
  return count;
}

PGDLLEXPORT void capture_worker_main(Datum main_arg) {
  pqsignal(SIGTERM, SignalHandlerForShutdownRequest);
  pqsignal(SIGHUP, SignalHandlerForConfigReload);
  BackgroundWorkerUnblockSignals();

  Shmem->worker_latch = &MyProc->procLatch;

  while (!ShutdownRequestPending) {
    uint32 current_capture_id = get_capture_id();
    if (WorkerCaptureId != current_capture_id) {
      WorkerCaptureId = current_capture_id;
      close_capture();
    }
    if (is_capture_running() && CaptureFile == NULL) {
      if (!start_capture()) {
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
  close_capture();
  Shmem->worker_latch = NULL;
}

void register_capture_worker() {
  BackgroundWorker worker;

  memset(&worker, 0, sizeof(worker));
  worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
  worker.bgw_start_time = BgWorkerStart_ConsistentState;
  worker.bgw_restart_time = BGW_NEVER_RESTART;
  snprintf(worker.bgw_library_name, BGW_MAXLEN, "pgr");
  snprintf(worker.bgw_function_name, BGW_MAXLEN, "capture_worker_main");
  snprintf(worker.bgw_name, BGW_MAXLEN, "pgr capture");
  snprintf(worker.bgw_type, BGW_MAXLEN, "pgr");
  RegisterBackgroundWorker(&worker);
}
