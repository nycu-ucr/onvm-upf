# Source files
updk_sources = files('env.c')

# Include paths
updk_includes = include_directories('.', '../logger', '../utlt')

# Dependencies
libm_dep = cc.find_library('m')

updk_deps = [
  liblogger_dep,
  libutlt_dep,
  libm_dep
]

# Static library build
libupdk = static_library(
  'libupdk',
  updk_sources,
  include_directories: updk_includes,
  dependencies: updk_deps,
  pic: true,
  install: true,
  install_tag: 'onvm'
)

# Dependency object for use in other targets
libupdk_dep = declare_dependency(
  link_with: libupdk,
  dependencies: updk_deps,
  include_directories: updk_includes
)

onvm_l25gc_dep += libupdk_dep