#include "pgr.h"

#include "utils/timestamp.h"

void send_timing_event(uint8 type) {
  if (!Shmem || !is_replay_client() || !channel_running(ChanTiming)) {
    return;
  }
  char buf[13];
  uint32 id = (uint32)MyReplayId;
  uint64 ts = (uint64)GetCurrentTimestamp();
  memcpy(buf, &id, 4);
  buf[4] = (char)type;
  memcpy(buf + 5, &ts, 8);
  channel_push(ChanTiming, buf, sizeof(buf));
}
