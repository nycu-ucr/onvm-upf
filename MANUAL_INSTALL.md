## 1. Install Dependencies

### For DPDK
```bash
sudo apt update
sudo apt install libnuma-dev meson python3-pip -y
```

### For Pktgen-DPDK
```bash
sudo apt install pkg-config cmake libpcap-dev libbsd-dev python3-pyelftools -y
```

### For onvm-upf
```bash
sudo apt install libyaml-dev libsystemd-dev -y
```

#### Install Golang 1.21
```bash
sudo rm -rf /usr/local/go
sudo rm -rf ~/go

mkdir -p ~/go/{bin,pkg,src}

wget https://dl.google.com/go/go1.21.8.linux-amd64.tar.gz
sudo tar -C /usr/local -zxf go1.21.8.linux-amd64.tar.gz

# The following assume that your shell is bash
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin:$GOROOT/bin' >> ~/.bashrc
echo 'export GO111MODULE=auto' >> ~/.bashrc
source ~/.bashrc

rm go1.21.8.linux-amd64.tar.gz
```

### Additional setups on Ubuntu 20.04

#### Missing `numa.pc`
Ubuntu 20.04 does not ship `numa.pc` by default with libnuma-dev. You may encounter this error because even though libnuma-dev is installed, Meson (via pkg-config) is failing to find it. This typically happens when the `numa.pc` file is missing from the pkg-config path.

```bash
# Create a pkg-config file for libnuma on Ubuntu 20.04
sudo tee /usr/lib/pkgconfig/numa.pc > /dev/null <<EOF
prefix=/usr
exec_prefix=\${prefix}
libdir=/usr/lib/x86_64-linux-gnu
includedir=\${prefix}/include

Name: libnuma
Description: NUMA policy library
Version: 2.0.12
Libs: -L\${libdir} -lnuma
Cflags: -I\${includedir}
EOF

# Export PKG_CONFIG_PATH
export PKG_CONFIG_PATH=/usr/lib/pkgconfig:$PKG_CONFIG_PATH

# Verify
pkg-config --modversion numa
```

#### Install Meson 0.58.0 on Ubuntu 20.04
Ubuntu 20.04 ships `meson` by default with `0.53.0`, which is fully compatible with the `meson.build` in `onvm-upf`. We can solve it by upgrading `meson` to `0.58.0`
```bash
pip3 install meson==0.58.0
```

```bash
# Check meson version
meson --version

# If meson is not found in your PATH, try (default installation path of pip3):
~/.local/bin/meson --version

# Or add meson to PATH
echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

## 2. Clone onvm-upf

```bash
git clone https://github.com/nycu-ucr/onvm-upf.git
cd onvm-upf
git checkout <upgraded_dpdk_branch>
```

## 3. Initializing submodules (DPDK, dpdk-kmods, pktgen-DPDK)
From the `onvm-upf` parent folder run the following to clone submodules:
```bash
git submodule sync
git submodule update --init
```

## 4. Build and install DPDK
From the `onvm-upf` parent folder run the following to build and install dpdk:
```bash
cd subprojects/dpdk 
meson setup build
ninja -C build
sudo ninja -C build install
sudo ldconfig  # make sure ld.so is pointing new DPDK libraries
```

## 5. (Optional) Install `igb_uio` driver for Intel NICs
From the `onvm-upf` parent folder run the following to build and install `igb_uio` driver:
```bash
cd subprojects/dpdk-kmods/linux/igb_uio
make

# Load `igb_uio` driver
sudo modprobe uio
sudo insmod ./igb_uio.ko

# Bind NIC to igb_uio (replace <pci_id> with the actual PCI address)
sudo python <dpdk>/usertools/dpdk-devbind.py --bind=igb_uio <pci_id> | <eth_if_id>
```

## 6. Build and install Pktgen-DPDK
From the `onvm-upf` parent folder run the following to build and install Pktgen-DPDK:
```bash
cd tools/Pktgen/pktgen-dpdk/

meson setup build
ninja -C build
sudo ninja -C build install
```

## 7. Configure Hugepages and ASLR (Run as Root)

> _Switch to root user before proceeding. Run `sudo -s`_

### Allocate Hugepages

For single-node systems:

```bash
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

For NUMA systems:

```bash
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
```

### Mount Hugepages

```bash
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
```

### Disable ASLR (for multi-process setups)

```bash
echo 0 > /proc/sys/kernel/randomize_va_space
```

> _Exit root user mode_

## 8. Build `onvm-upf`
From the `onvm-upf` parent folder run the following to build and install `onvm-upf`:

```bash
meson setup build
ninja -C build/ onvm/logger/liblogger.a
ninja -C build/
```