project('openNetVM', 'c', default_options: ['default_library=both'])

add_global_arguments('-msse4', language : 'c')

cc = meson.get_compiler('c')
onvm_source = meson.current_source_dir()

# Output directory that executables are installed into
onvm_output_dir = meson.current_source_dir() + '/bin'

# ONVM configurations
onvm_mgr_app_name = 'onvm_mgr'

# DPDK dependencies
onvm_dpdk_dep = dependency('libdpdk')

# ONVM dependencies
onvm_nflib_dep = []
onvm_math_dep = cc.find_library('m')
onvm_thread_dep = dependency('threads')
onvm_systemd_dep = cc.find_library('systemd')

# L25GC+ dependencies
yaml_dep = cc.find_library('yaml', required: true)
onvm_l25gc_dep = [yaml_dep]

# Include directories to be used when building components and examples
onvm_includes = include_directories('onvm/', 
                                    'onvm/onvm_nflib',
                                    'onvm/onvm_mgr')

# Build the ONVM components (onvm_mgr, nflib, lib)
subdir('onvm')

# Build the ONVM example apps
subdir('examples')

# Build the L25GC+ NFs
subdir('5gc')