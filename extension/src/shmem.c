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

  init_stats();
}

uint32 capture_start() {
  uint32 id = reserve_id("captures", "pr");
  CaptureState* c = &Shmem->capture;
  bool nothing_pending;

  SpinLockAcquire(&c->lock);
  pg_atomic_write_u32(&c->wal_ready, 0);
  pg_atomic_write_u32(&c->next_client_id, 0);
  c->pending_xacts = c->open_xacts;
  nothing_pending = c->pending_xacts == 0;
  channel_publish(ChanCapture, id);
  SpinLockRelease(&c->lock);

  channel_ensure_worker(ChanCapture);
  channel_wakeup(ChanCapture);
  if (nothing_pending) {
    capture_sync_lsn();
  }
  return id;
}

uint32 acquire_client_id() {
  return pg_atomic_fetch_add_u32(&Shmem->capture.next_client_id, 1);
}

uint32 xact_enter_shared() {
  CaptureState* c = &Shmem->capture;
  uint32 gen;
  SpinLockAcquire(&c->lock);
  c->open_xacts += 1;
  gen = channel_running(ChanCapture) ? channel_generation(ChanCapture) : 0;
  SpinLockRelease(&c->lock);
  return gen;
}

bool xact_leave_shared(uint32 gen) {
  CaptureState* c = &Shmem->capture;
  bool last = false;
  
  SpinLockAcquire(&c->lock);
  c->open_xacts -= 1;
  if (channel_running(ChanCapture) && gen != channel_generation(ChanCapture) &&
      c->pending_xacts > 0) {
    c->pending_xacts -= 1;
    last = c->pending_xacts == 0;
  }
  SpinLockRelease(&c->lock);
  return last;
}

void init_stats() {
  pg_atomic_init_u64(&Shmem->stats.statements, 0);
  pg_atomic_init_u64(&Shmem->stats.commits, 0);
  pg_atomic_init_u64(&Shmem->stats.aborts, 0);
  pg_atomic_init_u64(&Shmem->stats.rollbacks, 0);
}

static bool should_record_stats() {
  return (is_replay_client() || CaptureLive) && !ClientIsPsql;
}

uint64_t stats_statements() {
  return pg_atomic_read_u64(&Shmem->stats.statements);
}

void stats_add_statement() {
  if (should_record_stats()) {
    pg_atomic_fetch_add_u64(&Shmem->stats.statements, 1);
  }
}

void stats_add_statements(uint64_t count) {
  pg_atomic_fetch_add_u64(&Shmem->stats.statements, count);
}

uint64_t stats_commits() {
  return pg_atomic_read_u64(&Shmem->stats.commits);
}

void stats_add_commit() {
  if (should_record_stats()) {
    pg_atomic_fetch_add_u64(&Shmem->stats.commits, 1);
  }
}

uint64_t stats_rollbacks() {
  return pg_atomic_read_u64(&Shmem->stats.rollbacks);
}

void stats_add_rollback() {
  if (should_record_stats()) {
    pg_atomic_fetch_add_u64(&Shmem->stats.rollbacks, 1);
  }
}

uint64_t stats_aborts() {
  return pg_atomic_read_u64(&Shmem->stats.aborts);
}

void stats_add_abort() {
  if (should_record_stats()) {
    pg_atomic_fetch_add_u64(&Shmem->stats.aborts, 1);
  }
}

void reset_stats() {
  pg_atomic_write_u64(&Shmem->stats.statements, 0);
  pg_atomic_write_u64(&Shmem->stats.commits, 0);
  pg_atomic_write_u64(&Shmem->stats.aborts, 0);
  pg_atomic_write_u64(&Shmem->stats.rollbacks, 0);
}
