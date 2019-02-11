#!/bin/bash


cd /go/src/gotcpDump
mkdir nembuild
cd nembuild 
wget http://www.tcpdump.org/release/libpcap-1.9.0.tar.gz
tar -xf libpcap-1.9.0.tar.gz
cd libpcap-1.9.0
./configure  
#--without-flex --without-lex --without-bison
make && make install
