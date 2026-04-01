upf_sources = files(
  'upf.c',
  'upf_context.c',
  'upf_sess_buf.c'
)

# Include directories
upf_includes = include_directories(
  '.',
  '..',
  '../logger',
  '../utlt',
  '../pfcp',
  '../updk',
  '../list'
)

# Dependencies (must be declared elsewhere)
upf_deps = [
  libpfcp_dep,
  libutlt_dep,
  liblist_dep,
  libupdk_dep,
  liblogger_dep,
  cc.find_library('m')
]

libupf = static_library(
  'libupf',
  upf_sources,
  include_directories: upf_includes,
  dependencies: upf_deps,
  pic: true,
  install: true,
  install_tag: 'onvm'
)

libupf_dep = declare_dependency(
  link_with: libupf,
  dependencies: upf_deps,
  include_directories: upf_includes
)

onvm_l25gc_dep += libupf_dep
