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

packages=("build-essential" \
          "python3" \
          "python3-pip" \
          "python3-setuptools" \
          "python3-wheel" \
          "python3-venv" \
          "ninja-build" \
          "pkg-config" \
          "libnuma-dev" \
          "libpcap-dev" \
          "libyaml-dev" \
          "libsystemd-dev" \
          "libbsd-dev")
install_packages=true

pypackages=("meson" \
            "pyelftools")
pyenv="env"

# Check the passed arguments, and set the appropriate flags if a
# particular argument is detected
for arg in "$@"
do
    if [[ $arg == "--noinstall" ]]; then
        install_packages=false
        break
    fi
done

# Check to make sure this script is running in the correct working
# directory.
# Ensure we're working relative to the onvm root directory
if [ "$(basename "$(pwd)")" != "openNetVM" ]; then
    echo "Please run the installation script from the parent openNetVM directory"
fi


# (1)
# Install required packages for development
required=$(IFS=' '; echo "${packages[*]}")

echo "- Installing required packages"
if [ "$install_packages" = true ]; then
    echo "  - installing: $required"
    sudo apt-get update
    sudo NEEDRESTART_MODE=a apt-get install $required -y
else
    echo "  - skipping due to --noinstall flag"
fi


# (2)
# Initialize the Git submodules (dpdk & pkt_gen)
echo "- Initializing Git submodules"

git submodule update --init


# (3)
# Create the Python environment (this will be used for compiling onvm)
pyrequired=$(IFS=' '; echo "${pypackages[*]}")

echo "- Setup Python environment"
echo "  - installing $pyrequired"

python3 -m venv $pyenv
source env/bin/activate
pip3 install $pyrequired


# (4)
# Build the dpdk-kmods uio kernel module
echo "- Building the dpdk-kmods uio kernel module"
cd subprojects/dpdk-kmods/linux/igb_uio
make
cd -

# (5)
# Install dpdk
echo "- Installing dpdk"
cd subprojects/dpdk
meson setup build
ninja -C build
sudo ninja -C build install
sudo ldconfig

# (6)
# Install Golang 1.21 (the following assume that your shell is bash)
sudo rm -rf /usr/local/go
sudo rm -rf ~/go

mkdir -p ~/go/{bin,pkg,src}

wget https://dl.google.com/go/go1.21.8.linux-amd64.tar.gz
sudo tar -C /usr/local -zxf go1.21.8.linux-amd64.tar.gz

echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin:$GOROOT/bin' >> ~/.bashrc
echo 'export GO111MODULE=auto' >> ~/.bashrc
source ~/.bashrc

rm go1.21.8.linux-amd64.tar.gz
