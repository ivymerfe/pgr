#include "pgr.h"

#include "fmgr.h"
#include "funcapi.h"
#include "access/htup_details.h"
#include "utils/builtins.h"

PG_FUNCTION_INFO_V1(sql_capture_start);
PG_FUNCTION_INFO_V1(sql_capture_stop);

PG_FUNCTION_INFO_V1(sql_trace_start);
PG_FUNCTION_INFO_V1(sql_trace_stop);

PG_FUNCTION_INFO_V1(sql_get_stats);
PG_FUNCTION_INFO_V1(sql_reset_stats);

PG_FUNCTION_INFO_V1(sql_temp_dump);
PG_FUNCTION_INFO_V1(sql_temp_restore);

Datum sql_capture_start(PG_FUNCTION_ARGS) { 
  uint32 id = capture_start();
  PG_RETURN_INT32(id);
}

Datum sql_capture_stop(PG_FUNCTION_ARGS) { 
  capture_stop();
  PG_RETURN_BOOL(true);
}

Datum sql_trace_start(PG_FUNCTION_ARGS) { 
  uint32 id = trace_start();
  PG_RETURN_INT32(id);
}

Datum sql_trace_stop(PG_FUNCTION_ARGS) { 
  trace_stop();
  PG_RETURN_BOOL(true);
}

Datum sql_get_stats(PG_FUNCTION_ARGS) {
	TupleDesc tupdesc = (TupleDesc)fcinfo->flinfo->fn_extra;
	if (tupdesc == NULL) {
		MemoryContext oldcontext =
			MemoryContextSwitchTo(fcinfo->flinfo->fn_mcxt);

		if (get_call_result_type(fcinfo, NULL, &tupdesc) !=
			TYPEFUNC_COMPOSITE) {
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("function returning record called in context "
							"that cannot accept type record")));
		}
		fcinfo->flinfo->fn_extra = (void *)tupdesc;

		MemoryContextSwitchTo(oldcontext);
	}
	uint64_t commits = pg_atomic_read_u64(&Shmem->commits);
	uint64_t rollbacks = pg_atomic_read_u64(&Shmem->rollbacks);
	uint64_t aborts = pg_atomic_read_u64(&Shmem->aborts);
    uint64_t failed_commits = aborts - rollbacks;

	bool nulls[3] = {false, false, false};
	Datum values[4];
	values[0] = Int64GetDatum(commits);
	values[1] = Int64GetDatum(rollbacks);
	values[2] = Int64GetDatum(failed_commits);

	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

Datum sql_reset_stats(PG_FUNCTION_ARGS) {
	pg_atomic_write_u64(&Shmem->commits, 0);
    pg_atomic_write_u64(&Shmem->aborts, 0);
    pg_atomic_write_u64(&Shmem->rollbacks, 0);
	PG_RETURN_VOID();
}

Datum sql_temp_dump(PG_FUNCTION_ARGS) {
  char *name = text_to_cstring(PG_GETARG_TEXT_PP(0));
  PG_RETURN_INT32(temp_dump(name));
}

Datum sql_temp_restore(PG_FUNCTION_ARGS) {
  char *name = text_to_cstring(PG_GETARG_TEXT_PP(0));
  PG_RETURN_INT32(temp_restore(name));
}
