#include "pgr.h"

#include "fmgr.h"
#include "miscadmin.h"

PG_MODULE_MAGIC;

void _PG_init(void) {
  if (!process_shared_preload_libraries_in_progress) {
    ereport(ERROR, (errmsg("pgr must be loaded via shared_preload_libraries")));
  }
  setup_hooks();
  register_capture_worker();
  register_trace_worker();
}
