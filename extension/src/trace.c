#include "pgr.h"

#include "portability/instr_time.h"

void send_trace_event(char event_type, uint32 duration_us) {
  if (!Shmem || !is_trace_running()) {
    return;
  }
  uint32 index = (uint32)StatementIndex;
  char buf[13];
  memcpy(buf, &MyReplayId, 4);
  memcpy(buf + 4, &index, 4);
  memcpy(buf + 8, &duration_us, 4);
  buf[12] = event_type;
  ring_push(&Shmem->trace_ring, buf, sizeof(buf));
  wakeup_trace_worker();
}

static instr_time pgr_trace_start_it;

static uint32 it_diff_us(instr_time start, instr_time end) {
  INSTR_TIME_SUBTRACT(end, start);
  return (uint32)INSTR_TIME_GET_MICROSEC(end);
}

void trace_begin() {
  if (!is_replay_client() || !is_trace_running()) {
    return;
  }
  INSTR_TIME_SET_CURRENT(pgr_trace_start_it);
}

void trace_end(char event_type) {
  if (!is_replay_client() || !is_trace_running()) {
    return;
  }
  instr_time now;
  INSTR_TIME_SET_CURRENT(now);
  uint32 duration_us = it_diff_us(pgr_trace_start_it, now);
  send_trace_event(event_type, duration_us);
}
