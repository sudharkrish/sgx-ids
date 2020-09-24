#!/usr/bin/env bash

set -x
set -e

apt-get update -y

apt-get install -y --no-install-recommends make gcc build-essential ocaml automake autoconf libtool wget python libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev libnuma-dev  python-protobuf python-crypto flex bison libpcap-dev unzip cmake hwloc libhwloc-dev pkg-config git linux-tools-common linux-tools-`uname -r` linux-headers-generic

if [ ! -d dpdk ] ; then
    wget -qO- https://fast.dpdk.org/rel/dpdk-17.08.tar.gz | tar zxv
    mv dpdk-17.08 dpdk
    pushd dpdk
    #make install T=x86_64-native-linuxapp-gcc DESTDIR=install EXTRA_CFLAGS="-fPIC" -j
    #To enable debug symbols for GDB
    make install T=x86_64-native-linuxapp-gcc DESTDIR=install EXTRA_CFLAGS="-fPIC -g -ggdb" -j
    export RTE_SDK=$(readlink -f .)
    export RTE_TARGET=x86_64-native-linuxapp-gcc
    # cd tools && sudo ./dpdk-setup.sh  # choose "[17] Insert VFIO module"; then "[23] Bind Ethernet/Crypto device to VFIO module" for all required network interfaces; then "[24] Setup VFIO permissions"
    popd
fi
