#include "pgr.h"

#include "miscadmin.h"
#include "port.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "utils/elog.h"
#include "utils/wait_classes.h"

#include <stdio.h>

#include <zstd.h>

typedef struct {
  const char* name;
  const char* subdir;
  const char* ext;
  int open_on;
} ChannelDesc;

static const ChannelDesc Descs[ChanCount] = {
    [ChanCapture] = {"capture", "captures", "pr", MsgTypeLsn},
    [ChanTrace] = {"trace", "traces", "ptr", 0},
    [ChanTiming] = {"timing", "timings", "ptm", 0},
};

static FILE* File = NULL;
static char ChannelBuffer[1024 * 1024];
static ZSTD_CCtx* Zctx = NULL;
static char ZOut[256 * 1024];

static uint32 WorkerGeneration = 0;

static void z_check(size_t r) {
  if (ZSTD_isError(r)) {
    ereport(ERROR, (errmsg("pgr: zstd error: %s", ZSTD_getErrorName(r))));
  }
}

static void z_emit(const ZSTD_outBuffer* out) {
  if (out->pos > 0 && fwrite(ZOut, 1, out->pos, File) != out->pos) {
    ereport(ERROR, (errmsg("pgr: write failed")));
  }
}

static void z_write(const char* data, size_t len) {
  ZSTD_inBuffer in = {data, len, 0};
  while (in.pos < in.size) {
    ZSTD_outBuffer out = {ZOut, sizeof(ZOut), 0};
    z_check(ZSTD_compressStream(Zctx, &out, &in));
    z_emit(&out);
  }
}

static void z_finish(void) {
  size_t rem;
  do {
    ZSTD_outBuffer out = {ZOut, sizeof(ZOut), 0};
    rem = ZSTD_endStream(Zctx, &out);
    z_check(rem);
    z_emit(&out);
  } while (rem != 0);
}

static void close_file() {
  if (File != NULL) {
    z_finish();
    ZSTD_freeCCtx(Zctx);
    Zctx = NULL;
    fclose(File);
    File = NULL;
  }
}

static void open_file(ChannelKind k) {
  close_file();
  char path[MAXPGPATH];
  snprintf(path, sizeof(path), "%s/%s/%u.%s", DataDir, Descs[k].subdir,
           channel_id(k), Descs[k].ext);
  FILE* f = fopen(path, "w");
  if (f == NULL) {
    ereport(ERROR, (errmsg("pgr: could not open file %s", path)));
  }
  ZSTD_CCtx* z = ZSTD_createCCtx();
  if (z == NULL) {
    fclose(f);
    ereport(ERROR, (errmsg("pgr: could not create zstd context")));
  }
  ZSTD_CCtx_setParameter(z, ZSTD_c_compressionLevel, 3);
  Zctx = z;
  File = f;
}

static int write_events(ChannelKind k) {
  Channel* ch = &Shmem->channels[k];
  int count = 0;
  uint32 len;
  while (ring_pop(&ch->ring, ChannelBuffer, sizeof(ChannelBuffer), &len) == RingOk) {
    count++;
    if (File == NULL) {
      if (Descs[k].open_on == 0 || ChannelBuffer[0] != Descs[k].open_on ||
          !channel_running(k)) {
        continue;
      }
      open_file(k);
    }
    z_write(ChannelBuffer, len);
  }
  return count;
}

static void worker_cleanup(int code, Datum arg) {
  Channel* ch = &Shmem->channels[DatumGetInt32(arg)];
  SpinLockAcquire(&ch->lock);
  if (ch->worker_pid == MyProcPid) {
    ch->worker_pid = 0;
    ch->latch = NULL;
  }
  SpinLockRelease(&ch->lock);
}

static bool worker_try_exit(Channel* ch) {
  bool stop;
  SpinLockAcquire(&ch->lock);
  stop = pg_atomic_read_u32(&ch->running) == 0;
  if (stop) {
    ch->worker_pid = 0;
    ch->latch = NULL;
  }
  SpinLockRelease(&ch->lock);
  return stop;
}

PGDLLEXPORT void channel_worker_main(Datum main_arg) {
  ChannelKind k = (ChannelKind)DatumGetInt32(main_arg);
  Channel* ch = &Shmem->channels[k];

  pqsignal(SIGTERM, SignalHandlerForShutdownRequest);
  pqsignal(SIGHUP, SignalHandlerForConfigReload);
  BackgroundWorkerUnblockSignals();

  on_shmem_exit(worker_cleanup, Int32GetDatum(k));

  SpinLockAcquire(&ch->lock);
  ch->worker_pid = MyProcPid;
  ch->latch = &MyProc->procLatch;
  SpinLockRelease(&ch->lock);

  while (!ShutdownRequestPending) {
    uint32 gen = channel_generation(k);
    if (WorkerGeneration != gen) {
      close_file();
      WorkerGeneration = gen;
    } else if (!channel_running(k) && File != NULL) {
      write_events(k);
      close_file();
    }
    if (Descs[k].open_on == 0 && channel_running(k) && File == NULL) {
      open_file(k);
    }
    if (write_events(k) > 0) {
      pg_usleep(1000);
      continue;
    }
    if (!channel_running(k) && worker_try_exit(ch)) {
      close_file();
      return;
    }
    ResetLatch(MyLatch);
    if (write_events(k) > 0) {
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
  write_events(k);
  close_file();
}

void channel_ensure_worker(ChannelKind k) {
  Channel* ch = &Shmem->channels[k];
  bool spawn = false;

  SpinLockAcquire(&ch->lock);
  if (ch->worker_pid == 0) {
    ch->worker_pid = -1;
    spawn = true;
  }
  SpinLockRelease(&ch->lock);
  if (!spawn) {
    return;
  }

  BackgroundWorker w;
  memset(&w, 0, sizeof(w));
  w.bgw_flags = BGWORKER_SHMEM_ACCESS;
  w.bgw_start_time = BgWorkerStart_ConsistentState;
  w.bgw_restart_time = BGW_NEVER_RESTART;
  w.bgw_main_arg = Int32GetDatum(k);
  w.bgw_notify_pid = 0;
  snprintf(w.bgw_library_name, BGW_MAXLEN, "pgr");
  snprintf(w.bgw_function_name, BGW_MAXLEN, "channel_worker_main");
  snprintf(w.bgw_name, BGW_MAXLEN, "pgr %s", Descs[k].name);
  snprintf(w.bgw_type, BGW_MAXLEN, "pgr %s", Descs[k].name);

  if (!RegisterDynamicBackgroundWorker(&w, NULL)) {
    pg_atomic_write_u32(&ch->running, 0);
    SpinLockAcquire(&ch->lock);
    ch->worker_pid = 0;
    SpinLockRelease(&ch->lock);
    ereport(ERROR, (errmsg("pgr: could not start %s worker", Descs[k].name),
                    errhint("Increase max_worker_processes.")));
  }
}

static void channel_init(Channel* ch) {
  pg_atomic_init_u32(&ch->id, 0);
  pg_atomic_init_u32(&ch->running, 0);
  pg_atomic_init_u32(&ch->generation, 0);
  SpinLockInit(&ch->lock);
  ch->worker_pid = 0;
  ch->latch = NULL;
  ring_init(&ch->ring);
}

uint32 channel_start(ChannelKind k) {
  uint32 id = reserve_id(Descs[k].subdir, Descs[k].ext);
  channel_publish(k, id);
  channel_ensure_worker(k);
  channel_wakeup(k);
  return id;
}

void channels_init() {
  for (int i = 0; i < ChanCount; i++) {
    channel_init(&Shmem->channels[i]);
  }
}

void channel_wakeup(ChannelKind k) {
  Latch* l = Shmem->channels[k].latch;
  if (l) {
    SetLatch(l);
  }
}

void channel_publish(ChannelKind k, uint32 id) {
  Channel* ch = &Shmem->channels[k];
  pg_atomic_write_u32(&ch->id, id);
  pg_atomic_fetch_add_u32(&ch->generation, 1);
  pg_atomic_write_u32(&ch->running, 1);
}

void channel_stop(ChannelKind k) {
  Channel* ch = &Shmem->channels[k];
  if (pg_atomic_read_u32(&ch->running) == 0) {
    return;
  }
  pg_atomic_write_u32(&ch->running, 0);
  channel_wakeup(k);
}

bool channel_running(ChannelKind k) {
  return pg_atomic_read_u32(&Shmem->channels[k].running) != 0;
}

uint32 channel_generation(ChannelKind k) {
  return pg_atomic_read_u32(&Shmem->channels[k].generation);
}

uint32 channel_id(ChannelKind k) {
  return pg_atomic_read_u32(&Shmem->channels[k].id);
}

bool channel_push(ChannelKind k, const char* data, size_t len) {
  bool ok = ring_push(&Shmem->channels[k].ring, data, len);
  channel_wakeup(k);
  return ok;
}
