list_sources = files(
  'list.c',
  'list_iterator.c',
  'list_node.c'
)

list_includes = include_directories('.')

liblist = static_library(
  'list',
  list_sources,
  include_directories: list_includes,
  c_args: ['-DONVM_ENV'],
  pic: true,
  install: true,
  install_tag: 'onvm'
)

liblist_dep = declare_dependency(
  link_with: liblist,
  include_directories: list_includes
)
