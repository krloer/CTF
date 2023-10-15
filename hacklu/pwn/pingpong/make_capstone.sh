#!/bin/sh

set -e
set -x 

CAPSTONE_DIR="capstone-5.0"
CAPSTONE_SRC=$CAPSTONE_DIR.tar.gz

tar -xf $CAPSTONE_SRC
cd $CAPSTONE_DIR
./make.sh

cp /capstone-5.0/libcapstone.so.5 /libcapstone.so.5