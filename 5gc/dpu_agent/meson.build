# DPU Agent — standalone DOCA application (runs on BF3 ARM cores)
# NOT an ONVM NF — does not link against onvm_nflib.
# Uses DPDK (rte_eal, rte_ethdev, rte_ring, rte_hash, etc.) via the
# DOCA SDK transitive dependency.  Built on the DPU with DOCA installed.
#
# DOCA 3.x dropped the monolithic 'doca' pkg-config name and replaced it with
# per-library packages.  List only the ones this binary actually uses:
#   doca-common — doca_dev, doca_devinfo, doca_pe, doca_ctx, doca_task
#   doca-flow   — doca_flow_* (eSwitch pipeline, pipe/entry management)
#   doca-comch  — doca_comch_server_* (host<->DPU channel)
#   doca-argp   — DOCA Arg Parser

project('dpu_agent', 'c',
    version: '0.1.0',
    default_options: ['c_std=c11', 'warning_level=2'],
)

# Required by DOCA SDK: experimental API symbols are only exported when this
# define is present at compile time.  In DOCA 3.3 most Flow APIs graduated to
# stable, but some helpers and new features may still be experimental.
add_project_arguments('-D', 'DOCA_ALLOW_EXPERIMENTAL_API', language: 'c')

dpdk_dep        = dependency('libdpdk',     required: true)
doca_common_dep = dependency('doca-common', required: true)
doca_flow_dep   = dependency('doca-flow',   required: true)
doca_comch_dep  = dependency('doca-comch',  required: true)
doca_argp_dep   = dependency('doca-argp',   required: true)
doca_dpdk_bridge_dep = dependency('doca-dpdk-bridge', required: true)

executable('dpu_agent',
    sources: files(
        'dpu_agent.c',
        'dpu_agent_config.c',
        'dpu_pipeline.c',
        'dpu_buffer.c',
        'dpu_shaper.c',
        'dpu_l2l3_responder.c',
        'dpu_gtp_codec.c',
    ),
    dependencies: [
        dpdk_dep,
        doca_common_dep,
        doca_flow_dep,
        doca_comch_dep,
        doca_argp_dep,
        doca_dpdk_bridge_dep,
    ],
    install: true,
)