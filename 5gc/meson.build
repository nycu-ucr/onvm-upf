l25gc_nfs = [
    'upf_u_complete',
    'upf_c_complete'
]

foreach nf : l25gc_nfs
    name = 'l25gc_' + nf
    sources = []
    includes = [include_directories(nf), onvm_includes]

    subdir(nf)

    executable(
        name,
        sources,
        include_directories: includes,
        dependencies: [onvm_dpdk_dep, onvm_nflib_dep, onvm_l25gc_dep],
        install: true,
        install_tag: 'onvm',
        install_dir: onvm_output_dir + '/nf/' + nf
    )
endforeach
