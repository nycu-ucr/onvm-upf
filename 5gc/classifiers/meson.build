fs = import('fs')


classifier_inc = include_directories(
  '.',                  
  'PartitionSort',
  'TupleSpaceSearch',
  'Utilities',             
  '../../onvm/updk/updk'
)

ps_srcs = files(
  # Core adapter & wrapper
  'upf_cls_adapter.cpp',
  'classifier_wrapper.cpp',
  'Simulation.cpp',

  # PartitionSort backend
  'PartitionSort/misc.cpp',
  'PartitionSort/OptimizedMITree.cpp',
  'PartitionSort/PartitionSort.cpp',
  'PartitionSort/red_black_tree.cpp',
  'PartitionSort/SortableRulesetPartitioner.cpp',
  'PartitionSort/stack.cpp',

  # TupleSpaceSearch backend
  'TupleSpaceSearch/cmap.cpp',
  'TupleSpaceSearch/TupleSpaceSearch.cpp',

  # Common utilities
  'Utilities/IntervalUtilities.cpp',
  'Utilities/MapExtensions.cpp',
  'Utilities/Tcam.cpp',
)



# 5) Build the static library, passing in the chosen backend macro
libclassifier = static_library(
  'classifier',
  ps_srcs,
  include_directories: classifier_inc,
)

# 6) Export a Meson dependency that carries both the headers and the .a
classifier_dep = declare_dependency(
  include_directories: classifier_inc,
  link_with: libclassifier
)
