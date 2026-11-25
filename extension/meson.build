project('pgr', 'c',
  version: '0.1',
  default_options: ['warning_level=2', 'c_std=gnu11']
)

fs = import('fs')

sources = files(
  'src/capture.c',
  'src/channel.c',
  'src/client_info.c',
  'src/funcs.c',
  'src/helpers.c',
  'src/hooks.c',
  'src/init.c',
  'src/ring.c',
  'src/session.c',
  'src/shmem.c',
  'src/timing.c',
  'src/trace.c',
)

pg_config = find_program('pg_config', required: true)

r_inc = run_command(pg_config, '--includedir-server', check: true)
r_lib = run_command(pg_config, '--pkglibdir', check: true)
r_share = run_command(pg_config, '--sharedir', check: true)
r_bin = run_command(pg_config, '--bindir', check: true)

pg_inc = include_directories(r_inc.stdout().strip())
pg_libdir = r_lib.stdout().strip()
pg_sharedir = r_share.stdout().strip()
pg_bindir = r_bin.stdout().strip()

zstd_dep = dependency('libzstd')
openssl_dep = dependency('openssl', required: false)
deps = [zstd_dep]

if openssl_dep.found()
  deps += openssl_dep
endif

link_args = []
if host_machine.system() == 'darwin'
  link_args += ['-bundle_loader', pg_bindir / 'postgres']
endif

cc = meson.get_compiler('c')

shared_module('pgr',
  sources,
  include_directories: pg_inc,
  dependencies: deps,
  c_args: cc.get_supported_arguments('-Wno-unused-parameter'),
  link_args: link_args,
  name_prefix: '',
  install: true,
  install_dir: pg_libdir
)

install_data('pgr--0.1.sql', install_dir: pg_sharedir / 'extension')
if fs.exists('pgr.control')
  install_data('pgr.control', install_dir: pg_sharedir / 'extension')
endif
