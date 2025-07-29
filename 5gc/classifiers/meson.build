cls_be = get_option('cls_backend')

if cls_be == 'PS'
  be_flag = '-DCLS_BACKEND_PS'
elif cls_be == 'TSS'
  be_flag = '-DCLS_BACKEND_TSS'
else
  be_flag = '-DCLS_BACKEND_PTSS'
endif

classifier_inc = include_directories(
  '.',
  'PartitionSort',
  'TupleSpaceSearch',
  '../../onvm/updk/updk'   # UPDK headers live here
)

libclassifier = static_library(
  'classifier',
  ps_srcs,
  include_directories: classifier_inc,
  cpp_std: 'c++17',
  cpp_args: [ be_flag ],
)

classifier_dep = declare_dependency(
  include_directories: classifier_inc,
  link_with: libclassifier
)
