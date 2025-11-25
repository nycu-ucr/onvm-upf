#!/bin/bash

function usage {
        echo "Run the example NF in one of the following ways:"
        echo "$0 NF-NAME SERVICE-ID [remaining NF args]"
        echo "$0 NF-NAME DPDK_ARGS -- ONVM_ARGS -- NF_ARGS"
        echo "$0 NF-NAME -F config.json [other args]"
        echo ""
        echo "$0 upf_u_ingress 1   --> UPF-U ingress"
        echo "$0 upf_u_egress 14  --> UPF-U egress"
        exit 1
}

# 2 args: NF_NAME + (service_id or -F config_name)
if [ "$#" -lt 2 ]; then
  echo "ERROR: Missing required arguments"
  usage
  exit 1
fi

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
NF_NAME=$1
NF_PATH=$SCRIPTPATH/$NF_NAME

# Support split UPF-U roles using a shared source directory
case "$NF_NAME" in
  upf_u_ingress)
    NF_PATH=$SCRIPTPATH/upf_u
    BIN_NAME=l25gc_upf_ingress
    ;;
  upf_u_egress)
    NF_PATH=$SCRIPTPATH/upf_u
    BIN_NAME=l25gc_upf_egress
    ;;
  *)
    BIN_NAME=${NF_PATH##*/}
    ;;
esac

# Locate binary: L25GC NFs are built under build/5gc/, others under build/app/
if [[ "$BIN_NAME" == l25gc_* ]]; then
  BINARY=$SCRIPTPATH/build/5gc/$BIN_NAME
else
  BINARY=$NF_PATH/build/app/$BIN_NAME
fi
DPDK_BASE_ARGS="-n 3 --proc-type=secondary"
# For simple mode, only used for initial dpdk startup
DEFAULT_CORE_ID=0

if [ ! -f "$BINARY" ]; then
  echo "ERROR: NF executable not found, $BINARY doesn't exist"
  echo "Please verify NF binary name and run script from the NF folder"
  exit 1
fi

shift 1

# Config launch, when using the config we don't really parse any other args
if [ "$1" = "-F" ]
then
  config=$2
  shift 2
  exec sudo "$BINARY" -F "$config" "$@"
fi

# Check if -- is present, if so parse dpdk/onvm specific args
dash_dash_cnt=0
non_nf_arg_cnt=0
for i in "$@" ; do
  if [[ dash_dash_cnt -lt 2 ]] ; then
        non_nf_arg_cnt=$((non_nf_arg_cnt+1))
  fi
  if [[ $i == "--" ]] ; then
    dash_dash_cnt=$((dash_dash_cnt+1))
  fi
done

# Spaces before $@ are required otherwise it swallows the first arg for some reason
if [[ $dash_dash_cnt -ge 2 ]]; then
  DPDK_ARGS="$DPDK_BASE_ARGS $(echo " ""$*" | awk -F "--" '{print $1;}')"
  ONVM_ARGS="$(echo " ""$*" | awk -F "--" '{print $2;}')"
  # Move to NF arguments
  shift ${non_nf_arg_cnt}
  if [[ $DPDK_ARGS =~ "-l" && ! $ONVM_ARGS =~ "-m" ]]; then
    echo "Warning: Include -m flag in order to bind core specified in -l"
  fi
elif [[ $dash_dash_cnt -eq 0 ]]; then
  # Dealing with required args shared by all NFs
  service=$1
  shift 1

  DPDK_ARGS="-l $DEFAULT_CORE_ID $DPDK_BASE_ARGS"
  ONVM_ARGS="-r $service"
elif [[ $dash_dash_cnt -eq 1 ]]; then
  # Don't allow only one `--`
  echo "This script expects 0 or at least 2 '--' argument separators"
  usage
  exit 1
fi

# don't mess with variable expansion
# shellcheck disable=SC2086
exec sudo "$BINARY" $DPDK_ARGS -- $ONVM_ARGS -- "$@"
