#!/bin/bash

set -ex -o pipefail

# Run the test
rm -f smoke.serial

export QEMU_CMD="qemu-system-riscv64 \
    -M virt \
    -smp 1 \
    -nographic \
    -m 2g \
    -kernel binaries/xen"

export QEMU_LOG="smoke.serial"
export PASSED="All set up"

./automation/scripts/qemu-key.exp | sed 's/\r\+$//'
