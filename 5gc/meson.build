subdir('classifiers')


l25gc_nfs = [
    'upf_u_complete',
    'upf_c_complete'
]

rt_dep = cc.find_library('rt', required: false)

foreach nf : l25gc_nfs
    name = 'l25gc_' + nf
    sources = []
    includes = [include_directories(nf), onvm_includes]

    subdir(nf)

    # base deps for every NF
    deps = [ onvm_dpdk_dep, onvm_nflib_dep, onvm_l25gc_dep, rt_dep, classifier_dep ]

    if nf == 'upf_u_complete'
        deps += upf_u_link_deps
    endif

    executable(
        name,
        sources,
        include_directories: includes,
        dependencies: deps,
        install: true,
        install_tag: 'onvm',
        install_dir: onvm_output_dir + '/nf/' + nf
    )
endforeach
