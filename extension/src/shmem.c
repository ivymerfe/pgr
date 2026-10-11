#include "pgr.h"
#include "ring.h"

SharedMemory *Shmem = NULL;

void shmem_init() {
  pg_atomic_init_u32(&Shmem->capture_running, 0);
  pg_atomic_init_u32(&Shmem->capture_id, 0);
  pg_atomic_init_u32(&Shmem->next_client_id, 0);
  pg_atomic_init_u32(&Shmem->start_gen, 0);
  pg_atomic_init_u32(&Shmem->wal_ready, 0);

  SpinLockInit(&Shmem->lock);
  Shmem->open_xacts = 0;
  Shmem->pending_xacts = 0;

  Shmem->capture_worker_latch = NULL;
  ring_init(&Shmem->capture_ring);

  pg_atomic_init_u32(&Shmem->trace_running, 0);
  pg_atomic_init_u32(&Shmem->trace_id, 0);

  Shmem->trace_worker_latch = NULL;
  ring_init(&Shmem->trace_ring);

  pg_atomic_init_u64(&Shmem->commits, 0);
  pg_atomic_init_u64(&Shmem->aborts, 0);
  pg_atomic_init_u64(&Shmem->rollbacks, 0);
}

// capture

void wakeup_capture_worker() {
  if (Shmem->capture_worker_latch) {
    SetLatch(Shmem->capture_worker_latch);
  }
}

void capture_reset() {
  pg_atomic_fetch_add_u32(&Shmem->capture_id, 1);
  pg_atomic_write_u32(&Shmem->next_client_id, 0);
  wakeup_capture_worker();
}

void capture_start() {
  SpinLockAcquire(&Shmem->lock);
  pg_atomic_write_u32(&Shmem->wal_ready, 0);
  pg_atomic_fetch_add_u32(&Shmem->start_gen, 1);
  Shmem->pending_xacts = Shmem->open_xacts;
  pg_atomic_write_u32(&Shmem->capture_running, 1);
  SpinLockRelease(&Shmem->lock);
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

uint32 get_capture_id() { return pg_atomic_read_u32(&Shmem->capture_id); }

uint32 acquire_client_id() {
  return pg_atomic_fetch_add_u32(&Shmem->next_client_id, 1);
}

uint32 xact_enter_shared() {
  uint32 gen;
  SpinLockAcquire(&Shmem->lock);
  Shmem->open_xacts++;
  gen = is_capture_running() ? pg_atomic_read_u32(&Shmem->start_gen) : 0;
  SpinLockRelease(&Shmem->lock);
  return gen;
}

bool xact_leave_shared(uint32 gen) {
  bool last = false;
  SpinLockAcquire(&Shmem->lock);
  Shmem->open_xacts--;
  if (is_capture_running() && gen != pg_atomic_read_u32(&Shmem->start_gen) &&
      Shmem->pending_xacts > 0) {
    last = --Shmem->pending_xacts == 0;
  }
  SpinLockRelease(&Shmem->lock);
  return last;
}

bool xact_is_pre(uint32 gen) {
  return is_capture_running() && gen != pg_atomic_read_u32(&Shmem->start_gen);
}

// trace

void wakeup_trace_worker() {
  if (Shmem->trace_worker_latch) {
    SetLatch(Shmem->trace_worker_latch);
  }
}

void trace_reset() {
  pg_atomic_fetch_add_u32(&Shmem->trace_id, 1);
  wakeup_trace_worker();
}

void trace_start() {
  pg_atomic_write_u32(&Shmem->trace_running, 1);
  trace_reset();
}

void trace_stop() {
  if (pg_atomic_read_u32(&Shmem->trace_running) == 0) {
    return;
  }
  pg_atomic_write_u32(&Shmem->trace_running, 0);
  trace_reset();
}

bool is_trace_running() {
  return pg_atomic_read_u32(&Shmem->trace_running) != 0;
}

uint32 get_trace_id() { return pg_atomic_read_u32(&Shmem->trace_id); }
