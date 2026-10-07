#include "ring.h"

void ring_init(MpscRing *r) {
  SpinLockInit(&r->lock);
  r->hhead = 0;
  r->dhead = 0;
  pg_atomic_init_u64(&r->htail, 0);
  pg_atomic_init_u64(&r->dtail, 0);
  for (int i = 0; i < RING_HEADER_SIZE; i++) {
    pg_atomic_init_u32(&r->hdrs[i].ready, 0);
    r->hdrs[i].len = 0;
    r->hdrs[i].off = 0;
  }
}

bool ring_push(MpscRing *r, const void *msg, uint32 len) {
  MsgHdr *h;
  uint64 off, pos, first;

  SpinLockAcquire(&r->lock);

  if (r->hhead - pg_atomic_read_u64(&r->htail) >= RING_HEADER_SIZE ||
      len > RING_BUFFER_SIZE - (r->dhead - pg_atomic_read_u64(&r->dtail))) {
    SpinLockRelease(&r->lock);
    return false;
  }

  h = &r->hdrs[r->hhead % RING_HEADER_SIZE];
  off = r->dhead;
  h->off = off;
  h->len = len;
  r->hhead++;
  r->dhead += len;

  SpinLockRelease(&r->lock);

  pos = off % RING_BUFFER_SIZE;
  first = Min((uint64)len, RING_BUFFER_SIZE - pos);
  memcpy(r->data + pos, msg, first);
  if (first < len)
    memcpy(r->data, (const char *)msg + first, len - first);

  pg_write_barrier();
  pg_atomic_write_u32(&h->ready, 1);
  return true;
}

enum RingResult ring_pop(MpscRing *r, void *buf, uint32 buf_size, uint32 *len) {
  uint64 t = pg_atomic_read_u64(&r->htail);
  MsgHdr *h = &r->hdrs[t % RING_HEADER_SIZE];
  uint64 pos, first;
  uint32 n;

  if (pg_atomic_read_u32(&h->ready) != 1) {
    return RingNotReady;
  }

  pg_read_barrier();
  n = h->len;

  if (n > buf_size) {
    return RingOverflow;
  }

  pos = h->off % RING_BUFFER_SIZE;
  first = Min((uint64)n, RING_BUFFER_SIZE - pos);
  memcpy(buf, r->data + pos, first);
  if (first < n)
    memcpy((char *)buf + first, r->data, n - first);

  pg_atomic_write_u32(&h->ready, 0);
  pg_write_barrier();
  pg_atomic_write_u64(&r->dtail, h->off + n);
  pg_atomic_write_u64(&r->htail, t + 1);

  *len = n;
  return RingOk;
}
