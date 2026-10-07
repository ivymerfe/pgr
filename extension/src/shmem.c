#include "pgr.h"
#include "ring.h"

#include "access/xlog.h"
#include "utils/timestamp.h"

SharedMemory *Shmem = NULL;

void shmem_init() {
  pg_atomic_init_u32(&Shmem->capture_running, 0);
  pg_atomic_init_u32(&Shmem->capture_id, 0);
  pg_atomic_init_u32(&Shmem->next_client_id, 0);
  pg_atomic_init_u64(&Shmem->start_lsn, 0);
  pg_atomic_init_u64(&Shmem->start_ts, 0);
  ring_init(&Shmem->capture_ring);
}

static void pgr_wakeup_worker() {
  if (Shmem->worker_latch) {
    SetLatch(Shmem->worker_latch);
  }
}

void capture_reset() {
  pg_atomic_fetch_add_u32(&Shmem->capture_id, 1);
  pg_atomic_write_u32(&Shmem->next_client_id, 0);
  pgr_wakeup_worker();
}

void capture_start() {
  XLogRecPtr lsn = GetXLogInsertRecPtr();
  TimestampTz ts = GetCurrentTimestamp();
  pg_atomic_write_u64(&Shmem->start_lsn, lsn);
  pg_atomic_write_u64(&Shmem->start_ts, (uint64)ts);
  pg_write_barrier();
  pg_atomic_write_u32(&Shmem->capture_running, 1);
  capture_reset();
}

void capture_stop() {
  if (pg_atomic_read_u32(&Shmem->capture_running) == 0) {
    return;
  }
  pg_atomic_write_u32(&Shmem->capture_running, 0);
  capture_reset();
}

bool is_capture_running() {
  return pg_atomic_read_u32(&Shmem->capture_running) != 0;
}

uint32 get_capture_id() {
  return pg_atomic_read_u32(&Shmem->capture_id);
}

uint32 acquire_client_id() {
  return pg_atomic_fetch_add_u32(&Shmem->next_client_id, 1);
}

TimestampTz get_capture_start_ts() {
  pg_read_barrier();
  return (TimestampTz)pg_atomic_read_u64(&Shmem->start_ts);
}

XLogRecPtr get_capture_start_lsn() {
  pg_read_barrier();
  return (XLogRecPtr)pg_atomic_read_u64(&Shmem->start_lsn);
}
