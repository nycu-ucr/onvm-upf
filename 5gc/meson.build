subdir('classifiers')


l25gc_nfs = [
    'upf_u',
    'upf_c',
    'dn_app',
    'host_agent'
]

rt_dep = cc.find_library('rt', required: false)

# Optional: DOCA dependency for Host Agent (Comch client)
doca_dep = dependency('doca', required: false)

foreach nf : l25gc_nfs
    name = 'l25gc_' + nf
    sources = []
    includes = [include_directories(nf), onvm_includes]

    subdir(nf)

    # base deps for every NF
    deps = [ onvm_dpdk_dep, onvm_nflib_dep, onvm_l25gc_dep, rt_dep, classifier_dep ]

    if nf == 'upf_u'
        deps += upf_u_link_deps
    endif

    if nf == 'host_agent' and doca_dep.found()
        deps += host_agent_link_deps
    elif nf == 'host_agent' and not doca_dep.found()
        # Skip host_agent if DOCA SDK is not available on this host
        warning('DOCA SDK not found — skipping host_agent build')
        continue
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
