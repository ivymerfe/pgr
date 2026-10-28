#include "pgr.h"

SharedMemory* Shmem = NULL;

void shmem_init() {
  channels_init();

  CaptureState* c = &Shmem->capture;
  pg_atomic_init_u32(&c->next_client_id, 0);
  pg_atomic_init_u32(&c->wal_ready, 0);
  SpinLockInit(&c->lock);
  c->open_xacts = 0;
  c->pending_xacts = 0;

  pg_atomic_init_u32(&Shmem->session_debug_enabled, 0);

  pg_atomic_init_u64(&Shmem->stats.commits, 0);
  pg_atomic_init_u64(&Shmem->stats.aborts, 0);
  pg_atomic_init_u64(&Shmem->stats.rollbacks, 0);
}

uint32 capture_start() {
  uint32 id = reserve_id("captures", "pr");
  CaptureState* c = &Shmem->capture;

  SpinLockAcquire(&c->lock);
  pg_atomic_write_u32(&c->wal_ready, 0);
  pg_atomic_write_u32(&c->next_client_id, 0);
  c->pending_xacts = c->open_xacts;
  channel_publish(ChanCapture, id);
  SpinLockRelease(&c->lock);

  channel_ensure_worker(ChanCapture);
  channel_wakeup(ChanCapture);
  return id;
}

uint32 acquire_client_id() {
  return pg_atomic_fetch_add_u32(&Shmem->capture.next_client_id, 1);
}

uint32 xact_enter_shared() {
  CaptureState* c = &Shmem->capture;
  uint32 gen;
  SpinLockAcquire(&c->lock);
  c->open_xacts++;
  gen = channel_running(ChanCapture) ? channel_generation(ChanCapture) : 0;
  SpinLockRelease(&c->lock);
  return gen;
}

bool xact_leave_shared(uint32 gen) {
  CaptureState* c = &Shmem->capture;
  bool last = false;
  SpinLockAcquire(&c->lock);
  c->open_xacts--;
  if (channel_running(ChanCapture) && gen != channel_generation(ChanCapture) &&
      c->pending_xacts > 0) {
    last = --c->pending_xacts == 0;
  }
  SpinLockRelease(&c->lock);
  return last;
}

bool xact_is_pre(uint32 gen) {
  return channel_running(ChanCapture) && gen != channel_generation(ChanCapture);
}
