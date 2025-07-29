utlt_sources = files(
  'utlt_3gppTypes.c',
  'utlt_debug.c',
  'utlt_event.c',
  'utlt_lib.c',
  'utlt_sockAddr.c',
  'utlt_test.c',
  'utlt_time.c',
  'utlt_udp.c',
  'utlt_yaml.c',
  'utlt_buff.c',
  'utlt_epoll.c',
  'utlt_hash.c',
  'utlt_mq.c',
  'utlt_socket.c',
  'utlt_thread.c',
  'utlt_timer.c',
  'utlt_unix_sock.c'
)

utlt_includes = include_directories('.', '../logger')

libm_dep = cc.find_library('m')

libutlt_deps = [
  liblogger_dep,
  libm_dep
]

libutlt = static_library(
  'libutlt',
  utlt_sources,
  include_directories: utlt_includes,
  dependencies: libutlt_deps,
  pic: true,
  install: true,
  install_tag: 'onvm'
)

libutlt_dep = declare_dependency(
  link_with: libutlt,
  dependencies: libutlt_deps,
  include_directories: utlt_includes
)

onvm_l25gc_dep += libutlt_dep