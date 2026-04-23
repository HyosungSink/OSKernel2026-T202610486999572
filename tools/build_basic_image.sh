#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <rv|la> <output-image>" >&2
    exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TESTSUITS_ROOT=${TESTSUITS_ROOT:-$ROOT_DIR/testsuits-for-oskernel-pre-2025}
REFRESH_ROOT=$ROOT_DIR/kernel/starry-next/embedded-runtime-refresh
ARCH=$1
OUT=$2

WORK_DIR=$(mktemp -d /tmp/osk-basic.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

copy_if_exists() {
    src=$1
    dst=$2
    if [ -f "$src" ]; then
        mkdir -p "$(dirname -- "$dst")"
        cp "$src" "$dst"
    fi
}

copy_required_file() {
    src=$1
    dst=$2
    if [ ! -f "$src" ]; then
        echo "missing required file: $src" >&2
        exit 1
    fi
    mkdir -p "$(dirname -- "$dst")"
    cp "$src" "$dst"
}

copy_seed_root() {
    primary_dir=$1
    fallback_dir=$2
    stage_dir=$3

    if [ -d "$primary_dir" ]; then
        cp -R "$primary_dir" "$stage_dir"
        return 0
    fi
    if [ -d "$fallback_dir" ]; then
        cp -R "$fallback_dir" "$stage_dir"
        return 0
    fi

    echo "missing required root seed: $primary_dir (fallback: $fallback_dir)" >&2
    exit 1
}

case "$ARCH" in
    rv|riscv|riscv64)
        SRC_DIR="$ROOT_DIR/dev/basic-rv-root"
        FALLBACK_DIR="$REFRESH_ROOT/rv/glibc"
        STAGE_DIR="$WORK_DIR/basic-rv-root"
        copy_seed_root "$SRC_DIR" "$FALLBACK_DIR" "$STAGE_DIR"
        copy_required_file \
            "$REFRESH_ROOT/rv/glibc/lib/ld-linux-riscv64-lp64d.so.1" \
            "$STAGE_DIR/lib/ld-linux-riscv64-lp64d.so.1"
        copy_required_file \
            "$REFRESH_ROOT/rv/glibc/lib/libc.so.6" \
            "$STAGE_DIR/lib/libc.so.6"
        ;;
    la|loongarch|loongarch64)
        SRC_DIR="$ROOT_DIR/dev/basic-la-root"
        FALLBACK_DIR="$REFRESH_ROOT/la/glibc"
        STAGE_DIR="$WORK_DIR/basic-la-root"
        copy_seed_root "$SRC_DIR" "$FALLBACK_DIR" "$STAGE_DIR"
        copy_if_exists "$TESTSUITS_ROOT/runtime/loongarch/lib64/libc.so" \
            "$STAGE_DIR/musl/lib/libc.so"
        copy_if_exists "$TESTSUITS_ROOT/runtime/loongarch/lib64/ld-linux-loongarch-lp64d.so.1" \
            "$STAGE_DIR/lib64/ld-linux-loongarch-lp64d.so.1"
        copy_if_exists "$TESTSUITS_ROOT/runtime/loongarch/lib64/ld.so" \
            "$STAGE_DIR/lib64/ld-linux-loongarch-lp64d.so.1"
        ;;
    *)
        echo "unsupported arch: $ARCH" >&2
        exit 2
        ;;
esac

mkdir -p "$(dirname -- "$OUT")"
rm -f "$OUT"
truncate -s 128M "$OUT"
mkfs.ext4 -q -F -d "$STAGE_DIR" "$OUT"
