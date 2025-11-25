rt_dep = cc.find_library('rt', required: false)

# Classifier dependency (defines classifier_dep)
subdir('classifiers')

# Shared deps/includes
upf_u_link_deps = [ dependency('yaml-0.1', version: '>=0.2.2', required: true) ]

# ------------------------
# UPF-U ingress / egress
# ------------------------
upf_u_includes = [ include_directories('upf_u'), onvm_includes ]
upf_u_deps = [ onvm_dpdk_dep, onvm_nflib_dep, onvm_l25gc_dep, rt_dep, classifier_dep ] + upf_u_link_deps

upf_u_common_sources = files(
  'upf_u/upf_u.c',
  'upf_u/upf_u_config.c'
)

ingress_sources = upf_u_common_sources + files('upf_u/upf_ingress.c')
egress_sources  = upf_u_common_sources + files('upf_u/upf_egress.c')

executable(
    'l25gc_upf_ingress',
    ingress_sources,
    include_directories: upf_u_includes,
    dependencies: upf_u_deps,
    install: true,
    install_tag: 'onvm',
    install_dir: onvm_output_dir + '/nf/upf_u'
)

executable(
    'l25gc_upf_egress',
    egress_sources,
    include_directories: upf_u_includes,
    dependencies: upf_u_deps,
    install: true,
    install_tag: 'onvm',
    install_dir: onvm_output_dir + '/nf/upf_u'
)

# ------------------------
# UPF-C
# ------------------------
upf_c_sources = files(
    'upf_c/upf.c',
    'upf_c/upf_init.c',
    'upf_c/upf_config.c',
    'upf_c/n4_onvm_pfcp_path.c',
    'upf_c/n4_onvm_pfcp_handler.c',
    'upf_c/n4_onvm_pfcp_build.c',
    'upf_c/n4_dispatcher.c',
    'classifiers/cls_heap_dpdk_shim.cpp',
)

upf_c_includes = [ include_directories('upf_c'), onvm_includes ]
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

# ------------------------
# dn_app
# ------------------------
dn_app_sources = files('dn_app/dn_app.c')
dn_app_includes = [ include_directories('dn_app'), onvm_includes ]
dn_app_deps = [ onvm_dpdk_dep, onvm_nflib_dep, onvm_l25gc_dep, rt_dep, classifier_dep ]

executable(
    'l25gc_dn_app',
    dn_app_sources,
    include_directories: dn_app_includes,
    dependencies: dn_app_deps,
    install: true,
    install_tag: 'onvm',
    install_dir: onvm_output_dir + '/nf/dn_app'
)
