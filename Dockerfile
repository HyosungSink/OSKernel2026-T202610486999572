FROM zhouzhouyi/os-contest:20260104

WORKDIR /workspace/OSKernel2026
COPY . /workspace/OSKernel2026

ENV PATH=/opt/qemu-bin-10.0.2/bin:/opt/riscv64-linux-musl-cross/bin:/opt/loongarch64-linux-musl-cross/bin:/opt/gcc-13.2.0-loongarch64-linux-gnu/bin:/opt/toolchain-loongarch64-linux-gnu-gcc8-host-x86_64-2022-07-18/bin:/opt/kendryte-toolchain/bin:/root/.cargo/bin:/opt/riscv64-lp64d--musl--bleeding-edge-2024.02-1/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/kendryte-toolchain/bin:${LD_LIBRARY_PATH}

CMD ["/bin/bash"]
