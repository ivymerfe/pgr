#include "pgr.h"

#include "fmgr.h"
#include "miscadmin.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(sql_capture_start);
PG_FUNCTION_INFO_V1(sql_capture_stop);
PG_FUNCTION_INFO_V1(sql_capture_reset);

void _PG_init(void) {
  if (!process_shared_preload_libraries_in_progress) {
    ereport(ERROR,
            (errmsg("pgr must be loaded via shared_preload_libraries")));
  }
  setup_hooks();
  register_capture_worker();
}

Datum sql_capture_start(PG_FUNCTION_ARGS) { 
  capture_start();
  PG_RETURN_BOOL(true);
}

Datum sql_capture_stop(PG_FUNCTION_ARGS) { 
  capture_stop();
  PG_RETURN_BOOL(true);
}

Datum sql_capture_reset(PG_FUNCTION_ARGS) { 
  capture_reset();
  PG_RETURN_BOOL(true);
}
