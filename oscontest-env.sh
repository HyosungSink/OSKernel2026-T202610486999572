#!/bin/sh

add_path() {
    if [ -d "$1" ]; then
        case ":$PATH:" in
            *":$1:"*) ;;
            *) PATH="$1:$PATH" ;;
        esac
    fi
}

append_path() {
    if [ -d "$1" ]; then
        case ":$PATH:" in
            *":$1:"*) ;;
            *) PATH="$PATH:$1" ;;
        esac
    fi
}

append_ld_library_path() {
    if [ -d "$1" ]; then
        case ":${LD_LIBRARY_PATH:-}:" in
            *":$1:"*) ;;
            *) LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$1" ;;
        esac
    fi
}

add_path /opt/qemu-bin-10.0.2/bin
add_path /opt/riscv64-linux-musl-cross/bin
add_path /opt/loongarch64-linux-musl-cross/bin
add_path /opt/gcc-13.2.0-loongarch64-linux-gnu/bin
add_path /opt/toolchain-loongarch64-linux-gnu-gcc8-host-x86_64-2022-07-18/bin
append_path /opt/kendryte-toolchain/bin
append_path /root/.cargo/bin
append_path /opt/riscv64-lp64d--musl--bleeding-edge-2024.02-1/bin
append_ld_library_path /opt/kendryte-toolchain/bin

export PATH
export LD_LIBRARY_PATH
