pfcp_sources = files(
  'pfcp_convert.c',
  'pfcp_message.c',
  'pfcp_node.c',
  'pfcp_path.c',
  'pfcp_types.c',
  'pfcp_xact.c'
)

# Include directories
pfcp_includes = include_directories(
  '.',
  '../logger',
  '../onvm_nflib',
  '../lib',
  '../utlt'
)

# Dependencies assumed to be declared elsewhere in your Meson project
pfcp_deps = [
  libonvm_dep,
  libonvmhelper_dep,
  liblogger_dep,
  libutlt_dep,
  cc.find_library('m')  # Link with -lm
]

libpfcp = static_library(
  'libpfcp',
  pfcp_sources,
  include_directories: pfcp_includes,
  dependencies: pfcp_deps,
  pic: true,
  install: true,
  install_tag: 'onvm'
)

libpfcp_dep = declare_dependency(
  link_with: libpfcp,
  dependencies: pfcp_deps,
  include_directories: pfcp_includes
)

onvm_l25gc_dep += libpfcp_dep