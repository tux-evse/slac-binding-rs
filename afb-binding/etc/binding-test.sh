#!/bin/bash

# use afbv4 development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
clear

if ! test -f $CARGO_TARGET_DIR/debug/libafb_slac.so; then
    echo "FATAL: missing libafb_slac.so use: cargo build"
    exit 1
fi

# start binder with test config
afb-binder -vvv --config=afb-binding/etc/binding-test.json
