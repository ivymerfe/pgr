#include "pgr.h"
#include "ring.h"

SharedMemory *Shmem = NULL;

void shmem_init() {
  pg_atomic_init_u32(&Shmem->capture_id, 0);
  pg_atomic_init_u32(&Shmem->capture_running, 0);
  pg_atomic_init_u32(&Shmem->capture_generation, 0);
  pg_atomic_init_u32(&Shmem->next_client_id, 0);
  pg_atomic_init_u32(&Shmem->wal_ready, 0);

  SpinLockInit(&Shmem->lock);
  Shmem->open_xacts = 0;
  Shmem->pending_xacts = 0;

  Shmem->delta_xacts = 0;
  Shmem->pre_done = false;
  Shmem->sync_claimed = false;

  Shmem->capture_worker_latch = NULL;
  ring_init(&Shmem->capture_ring);

  pg_atomic_init_u32(&Shmem->trace_id, 0);
  pg_atomic_init_u32(&Shmem->trace_running, 0);
  pg_atomic_init_u32(&Shmem->trace_generation, 0);

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

uint32 capture_start() {
  uint32 id = reserve_id("captures", "pr");

  SpinLockAcquire(&Shmem->lock);

  pg_atomic_write_u32(&Shmem->wal_ready, 0);
  pg_atomic_write_u32(&Shmem->next_client_id, 0);
  pg_atomic_write_u32(&Shmem->capture_id, id);
  
  Shmem->pending_xacts = Shmem->open_xacts;
  Shmem->delta_xacts = 0;
  Shmem->pre_done = false;
  Shmem->sync_claimed = false;

  pg_atomic_fetch_add_u32(&Shmem->capture_generation, 1);
  pg_atomic_write_u32(&Shmem->capture_running, 1);

  SpinLockRelease(&Shmem->lock);

  wakeup_capture_worker();
  return id;
}

void capture_stop() {
  if (pg_atomic_read_u32(&Shmem->capture_running) == 0) {
    return;
  }
  pg_atomic_write_u32(&Shmem->capture_running, 0);
  wakeup_capture_worker();
}

bool is_capture_running() {
  return pg_atomic_read_u32(&Shmem->capture_running) != 0;
}

uint32 get_capture_generation() {
  return pg_atomic_read_u32(&Shmem->capture_generation);
}

uint32 acquire_client_id() {
  return pg_atomic_fetch_add_u32(&Shmem->next_client_id, 1);
}

uint32 xact_enter_shared() {
  uint32 gen;
  SpinLockAcquire(&Shmem->lock);
  Shmem->open_xacts++;
  gen =
      is_capture_running() ? pg_atomic_read_u32(&Shmem->capture_generation) : 0;
  SpinLockRelease(&Shmem->lock);
  return gen;
}

bool xact_is_pre(uint32 gen) {
  return is_capture_running() &&
         gen != pg_atomic_read_u32(&Shmem->capture_generation);
}

static bool sync_try_claim() {
  if (Shmem->pre_done && Shmem->delta_xacts == 0 && !Shmem->sync_claimed) {
    Shmem->sync_claimed = true;
    return true;
  }
  return false;
}

bool xact_leave_shared(uint32 gen) {
  bool last = false;
  SpinLockAcquire(&Shmem->lock);
  Shmem->open_xacts--;
  if (is_capture_running() &&
      gen != pg_atomic_read_u32(&Shmem->capture_generation) &&
      Shmem->pending_xacts > 0 && --Shmem->pending_xacts == 0) {
    Shmem->pre_done = true;
    last = sync_try_claim();
  }
  SpinLockRelease(&Shmem->lock);
  return last;
}

bool xact_delta_enter() {
  bool ok;
  SpinLockAcquire(&Shmem->lock);
  ok = !Shmem->sync_claimed;
  if (ok)
    Shmem->delta_xacts++;
  SpinLockRelease(&Shmem->lock);
  return ok;
}

bool xact_delta_leave() {
  bool last;
  SpinLockAcquire(&Shmem->lock);
  Shmem->delta_xacts--;
  last = sync_try_claim();
  SpinLockRelease(&Shmem->lock);
  return last;
}

bool xact_sync_claimed() {
  bool v;
  SpinLockAcquire(&Shmem->lock);
  v = Shmem->sync_claimed;
  SpinLockRelease(&Shmem->lock);
  return v;
}

// trace

void wakeup_trace_worker() {
  if (Shmem->trace_worker_latch) {
    SetLatch(Shmem->trace_worker_latch);
  }
}

uint32 trace_start() {
  uint32 id = reserve_id("traces", "ptr");

  pg_atomic_write_u32(&Shmem->trace_id, id);
  pg_atomic_write_u32(&Shmem->trace_running, 1);
  pg_atomic_fetch_add_u32(&Shmem->trace_generation, 1);
  wakeup_trace_worker();

  return id;
}

void trace_stop() {
  if (pg_atomic_read_u32(&Shmem->trace_running) == 0) {
    return;
  }
  pg_atomic_write_u32(&Shmem->trace_running, 0);
  wakeup_trace_worker();
}

bool is_trace_running() {
  return pg_atomic_read_u32(&Shmem->trace_running) != 0;
}

uint32 get_trace_generation() {
  return pg_atomic_read_u32(&Shmem->trace_generation);
}
