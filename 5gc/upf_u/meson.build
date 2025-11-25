sources_common = files(
    'upf_u.c',
    'upf_u_config.c',
)

ingress_sources = sources_common + files('upf_ingress.c')
egress_sources  = sources_common + files('upf_egress.c')

upf_u_link_deps = [
  dependency('yaml-0.1', version: '>=0.2.2', required: true),
]

upf_u_includes = [ include_directories('.'), onvm_includes ]
upf_u_deps = [ onvm_dpdk_dep, onvm_nflib_dep, onvm_l25gc_dep, rt_dep, classifier_dep ] + upf_u_link_deps

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

