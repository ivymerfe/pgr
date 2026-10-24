project('pgr', 'c',
  version: '0.1',
  default_options: ['warning_level=2', 'c_std=c11']
)

fs = import('fs')

sources = files(
  'src/capture_worker.c',
  'src/capture.c',
  'src/funcs.c',
  'src/helpers.c',
  'src/hooks.c',
  'src/init.c',
  'src/replay_id.c',
  'src/ring.c',
  'src/session.c',
  'src/shmem.c',
  'src/trace_worker.c',
  'src/trace.c',
)

pg_config = find_program('pg_config', required: true)

r_inc = run_command(pg_config, '--includedir-server', check: true)
r_lib = run_command(pg_config, '--pkglibdir', check: true)
r_share = run_command(pg_config, '--sharedir', check: true)

pg_inc = include_directories(r_inc.stdout().strip())
pg_libdir = r_lib.stdout().strip()
pg_sharedir = r_share.stdout().strip()

shared_module('pgr',
  sources,
  include_directories: pg_inc,
  name_prefix: '',
  install: true,
  install_dir: pg_libdir
)

install_data('pgr--0.1.sql', install_dir: pg_sharedir / 'extension')
if fs.exists('pgr.control')
  install_data('pgr.control', install_dir: pg_sharedir / 'extension')
endif
