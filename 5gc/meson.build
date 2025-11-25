rt_dep = cc.find_library('rt', required: false)

subdir('classifiers')
subdir('upf_u')
subdir('upf_c')
subdir('dn_app')

# Explicit dn_app executable (keeps dn_app/meson.build minimal)
dn_app_includes = [ include_directories('dn_app'), onvm_includes ]
dn_app_deps = [ onvm_dpdk_dep, onvm_nflib_dep, onvm_l25gc_dep, rt_dep, classifier_dep ]

executable(
    'l25gc_dn_app',
    sources,
    include_directories: dn_app_includes,
    dependencies: dn_app_deps,
    install: true,
    install_tag: 'onvm',
    install_dir: onvm_output_dir + '/nf/dn_app'
)
