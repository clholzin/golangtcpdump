#!/bin/bash


cd /go/src/gotcpDump/nDPI

./configure.seed –with-pic

make

cd /go/src/gotcpDump/pfring/PF_RING/kernel

make

sudo insmod ./pf_ring.ko

cd ../userland

make
