upf_c_sources = files(
    'upf.c',
    'upf_init.c',
    'upf_config.c',
    'n4_onvm_pfcp_path.c',
    'n4_onvm_pfcp_handler.c',
    'n4_onvm_pfcp_build.c',
    'n4_dispatcher.c',
    '../classifiers/cls_heap_dpdk_shim.cpp',
)

upf_c_includes = [ include_directories('.'), onvm_includes ]
upf_c_deps = [ onvm_dpdk_dep, onvm_nflib_dep, onvm_l25gc_dep, rt_dep, classifier_dep ]

executable(
    'l25gc_upf_c',
    upf_c_sources,
    include_directories: upf_c_includes,
    dependencies: upf_c_deps,
    install: true,
    install_tag: 'onvm',
    install_dir: onvm_output_dir + '/nf/upf_c'
)

