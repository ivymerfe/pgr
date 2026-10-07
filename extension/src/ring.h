#pragma once

#include "postgres.h"

#include "port/atomics.h"
#include "storage/spin.h"

#define RING_HEADER_SIZE 1024
#define RING_BUFFER_SIZE (1024 * 1024)

typedef struct MessageHeader {
  pg_atomic_uint32 ready;
  uint32 len;
  uint64 off;
} MsgHdr;

typedef struct MpscRing {
  slock_t lock;
  uint64 hhead;
  uint64 dhead;
  pg_atomic_uint64 htail;
  pg_atomic_uint64 dtail;
  MsgHdr hdrs[RING_HEADER_SIZE];
  char data[RING_BUFFER_SIZE];
} MpscRing;

enum RingResult {
    RingNotReady,
    RingOverflow,
    RingOk,
};

void ring_init(MpscRing *r);
bool ring_push(MpscRing *r, const void *msg, uint32 len);
enum RingResult ring_pop(MpscRing *r, void *buf, uint32 buf_size, uint32 *len);
