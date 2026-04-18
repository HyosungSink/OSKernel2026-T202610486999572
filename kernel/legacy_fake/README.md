# OSKernel2026 Clean-Room Kernel

This directory contains a clean-room kernel scaffold created from scratch for the 2026 OS competition workspace.

Current status:
- Builds `kernel-rv` and `kernel-la` from the top-level `Makefile`
- RISC-V image boots under QEMU and prints a banner
- LoongArch image also boots under the competition-style `-kernel` flow
- Local basic test ext4 development images are available under `dev/images/`

Major work still required to pass competition tests:
- trap/exception handling
- page tables and memory management
- task/process model
- ELF loading and userspace runtime
- ext4 block device support
- syscall layer compatible with the competition tests
- signal, time, poll, and process control support
- network stack support for iperf/netperf
