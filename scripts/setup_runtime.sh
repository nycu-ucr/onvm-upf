#! /bin/bash

# Copyright 2025 University of California, Riverside and National Yang Ming Chiao Tung University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

arg_hugepages=true

# Basic check to make sure this script is running in the correct working
# directory.
if [ "$(basename "$(pwd)")" != "openNetVM" ]; then
    echo "Please run the installation script from the parent openNetVM directory"
fi

# Parse the passed arguments, and set the appropriate flags if a
# particular argument is detected
for arg in "$@"
do
    if [[ $arg == "--nohugepages" ]]; then
        arg_hugepages=false
        break
    fi
done

# Check sudo privileges
sudo -v 


# (1)
# Disable address space layout randomization (ASLR)
echo "- Disabling ASLR"
sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"


# (2)
# Disable hyperthreading
# echo "- Disabling hyperthreading"

# CPUS_TO_SKIP=" $(cat /sys/devices/system/cpu/cpu*/topology/thread_siblings_list | sed 's/[^0-9].*//' | sort | uniq | tr "\r\n" "  ") "
# for CPU_PATH in /sys/devices/system/cpu/cpu[0-9]*; do
#         CPU="$(echo "$CPU_PATH" | tr -cd "0-9")"
#         echo "$CPUS_TO_SKIP" | grep " $CPU " > /dev/null
#         if [ $? -ne 0 ]; then
#             sudo sh -c "echo 0 > "$CPU_PATH"/online"
#         fi
# done

# lscpu | grep -i -E  "^CPU\(s\):|core|socket" 


# (3)
# Load the uio kernel module from dpdk-kmods
grep -m 1 "igb_uio" /proc/modules | cat
if [ "${PIPESTATUS[0]}" != 0 ]; then
    echo "- Loading uio kernel module"
    sudo modprobe uio
    sudo insmod ./subprojects/dpdk-kmods/linux/igb_uio/igb_uio.ko
else
    echo "- uio kernel module already loaded"
fi


# (4)
# Setup hugepages.
# This will be skipped if --nohugepages is passed in.
if [ "$arg_hugepages" = true ]; then
    echo "- Configuring hugepages"
    . ./scripts/dpdk_helper_scripts.sh
    set_numa_pages "$hp_count"
else
    echo "- Skipping hugepages"
fi