#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <rv|la> <glibc|musl> <output-dir>" >&2
    exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TESTSUITS_ROOT=${TESTSUITS_ROOT:-$ROOT_DIR/testsuits-for-oskernel-pre-2025}
VENDORED_MAKEFILE_SUB=${VENDORED_MAKEFILE_SUB:-$ROOT_DIR/tools/vendor/Makefile.sub}
TOOLCHAIN_CACHE=${TOOLCHAIN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/osk-toolchains}
if [ -n "${BUILD_JOBS:-}" ]; then
    :
else
    BUILD_JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 10)
fi
LTP_RELEASE=${LTP_RELEASE:-20240524}
LTP_SUITE_DIR=ltp-full-${LTP_RELEASE}
ARCH=$1
RUNTIME=$2
OUT_DIR=$3
FULL_SUITE_INCLUDE_UNIXBENCH=${FULL_SUITE_INCLUDE_UNIXBENCH:-0}

prepend_path_if_dir() {
    if [ -d "$1" ]; then
        PATH="$1:$PATH"
    fi
}

prepend_path_if_dir /opt/gcc-13.2.0-loongarch64-linux-gnu/bin
prepend_path_if_dir /opt/toolchain-loongarch64-linux-gnu-gcc8-host-x86_64-2022-07-18/bin
prepend_path_if_dir /opt/riscv64-linux-musl-cross/bin
prepend_path_if_dir /opt/loongarch64-linux-musl-cross/bin
prepend_path_if_dir "${XDG_CACHE_HOME:-$HOME/.cache}/osk-toolchains/riscv64-linux-musl-cross/bin"
prepend_path_if_dir "${XDG_CACHE_HOME:-$HOME/.cache}/osk-toolchains/loongarch64-linux-musl-cross/bin"
export PATH

require_file() {
    if [ ! -f "$1" ]; then
        echo "missing required file: $1" >&2
        exit 1
    fi
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

download_file() {
    url=$1
    out=$2
    if command -v curl >/dev/null 2>&1; then
        curl -L --fail -o "$out" "$url"
        return 0
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -O "$out" "$url"
        return 0
    fi
    echo "missing downloader: curl or wget" >&2
    exit 1
}

copy_if_exists() {
    src=$1
    dst=$2
    if [ -e "$src" ]; then
        mkdir -p "$(dirname -- "$dst")"
        cp -a "$src" "$dst"
    fi
}

target_enabled() {
    target=$1
    for enabled in $TARGETS; do
        if [ "$enabled" = "$target" ]; then
            return 0
        fi
    done
    return 1
}

alias_tool() {
    target=$1
    source_name=$2
    if command -v "$target" >/dev/null 2>&1; then
        return 0
    fi
    if ! command -v "$source_name" >/dev/null 2>&1; then
        return 1
    fi
    ln -sf "$(command -v "$source_name")" "$TOOL_ALIAS_DIR/$target"
}

ensure_rv_musl_toolchain() {
    if ! command -v riscv64-linux-musl-gcc >/dev/null 2>&1; then
        ensure_toolchain_bin \
            riscv64-linux-musl-cross \
            riscv64-linux-musl-gcc \
            riscv64-linux-musl \
            https://raw.githubusercontent.com/zhouzhouyi-hub/os-contest-image/master/riscv64-linux-musl-cross.tgz
    fi
    alias_tool riscv64-buildroot-linux-musl-gcc riscv64-linux-musl-gcc || true
    alias_tool riscv64-buildroot-linux-musl-strip riscv64-linux-musl-strip || true
    alias_tool riscv64-buildroot-linux-musl-ar riscv64-linux-musl-ar || true
    alias_tool riscv64-buildroot-linux-musl-ranlib riscv64-linux-musl-ranlib || true
    alias_tool riscv64-buildroot-linux-musl-nm riscv64-linux-musl-nm || true
    alias_tool riscv64-buildroot-linux-musl-objcopy riscv64-linux-musl-objcopy || true
    alias_tool riscv64-buildroot-linux-musl-objdump riscv64-linux-musl-objdump || true
}

ensure_la_musl_toolchain() {
    if ! command -v loongarch64-linux-musl-gcc >/dev/null 2>&1; then
        ensure_toolchain_bin \
            loongarch64-linux-musl-cross \
            loongarch64-linux-musl-gcc \
            loongarch64-linux-musl \
            https://raw.githubusercontent.com/zhouzhouyi-hub/os-contest-image/master/loongarch64-linux-musl-cross.tgz
    fi
}

ensure_toolchain_bin() {
    dir_name=$1
    compiler=$2
    expected_triplet=$3
    url=$4

    if command -v "$compiler" >/dev/null 2>&1; then
        actual_triplet=$("$compiler" -dumpmachine 2>/dev/null || true)
        if [ "$actual_triplet" = "$expected_triplet" ]; then
            return 0
        fi
    fi

    mkdir -p "$TOOLCHAIN_CACHE"
    archive="$TOOLCHAIN_CACHE/$dir_name.tgz"
    extract_dir="$TOOLCHAIN_CACHE/$dir_name"
    if [ ! -x "$extract_dir/bin/$compiler" ]; then
        if [ ! -f "$archive" ]; then
            echo "downloading toolchain: $url" >&2
            download_file "$url" "$archive"
        fi
        tmp_extract="$TOOLCHAIN_CACHE/.tmp-$dir_name"
        rm -rf "$tmp_extract"
        mkdir -p "$tmp_extract"
        tar xf "$archive" -C "$tmp_extract"
        found_dir=$(find "$tmp_extract" -maxdepth 1 -mindepth 1 -type d | head -n 1)
        if [ -z "$found_dir" ] || [ ! -x "$found_dir/bin/$compiler" ]; then
            echo "invalid toolchain archive: $archive" >&2
            exit 1
        fi
        rm -rf "$extract_dir"
        mv "$found_dir" "$extract_dir"
        rm -rf "$tmp_extract"
    fi

    PATH="$extract_dir/bin:$PATH"
    export PATH
}

seed_sys_queue_header() {
    compiler=$1
    sysroot=$("$compiler" -print-sysroot 2>/dev/null || true)
    if [ -z "$sysroot" ] || [ ! -d "$sysroot" ]; then
        return 0
    fi
    case "$sysroot" in
        /)
            return 0
            ;;
    esac
    if [ -f "$sysroot/include/sys/queue.h" ]; then
        return 0
    fi
    host_queue=$(find /usr/include -path '*/sys/queue.h' 2>/dev/null | head -n 1)
    if [ -z "$host_queue" ] || [ ! -f "$host_queue" ]; then
        return 0
    fi
    if [ ! -d "$sysroot/include" ] && [ ! -w "$sysroot" ]; then
        return 0
    fi
    if [ -d "$sysroot/include" ] && [ ! -w "$sysroot/include" ]; then
        return 0
    fi
    mkdir -p "$sysroot/include/sys"
    cp "$host_queue" "$sysroot/include/sys/queue.h"
}

copy_shared_objects() {
    src_dir=$1
    dst_dir=$2
    if [ ! -d "$src_dir" ]; then
        return 0
    fi
    mkdir -p "$dst_dir"
    find "$src_dir" -maxdepth 1 \( -type f -o -type l \) | while IFS= read -r path; do
        name=$(basename -- "$path")
        case "$name" in
            *.so|*.so.*|ld-linux-*|ld-musl-*)
                cp -a "$path" "$dst_dir/"
                ;;
        esac
    done
}

is_elf_binary() {
    path=$1
    [ -f "$path" ] || return 1
    magic=$(dd if="$path" bs=4 count=1 2>/dev/null || true)
    [ "$magic" = "$(printf '\177ELF')" ]
}

normalize_musl_runtime_dir() {
    sysroot_lib=$1
    root_lib=$2
    loader_name=$3

    mkdir -p "$root_lib"

    if [ -f "$sysroot_lib/libc.so" ] && ! is_elf_binary "$root_lib/libc.so"; then
        cp -f "$sysroot_lib/libc.so" "$root_lib/libc.so"
    fi

    if [ -L "$root_lib/$loader_name" ]; then
        ld_target=$(readlink "$root_lib/$loader_name" 2>/dev/null || true)
        if [ "$ld_target" = "/lib/libc.so" ] || [ "$ld_target" = "/lib64/libc.so" ]; then
            ln -sf libc.so "$root_lib/$loader_name"
        fi
    elif [ ! -e "$root_lib/$loader_name" ] && [ -f "$root_lib/libc.so" ]; then
        ln -sf libc.so "$root_lib/$loader_name"
    fi
}

copy_selected_runtime_libs() {
    src_dir=$1
    dst_dir=$2
    shift 2
    if [ ! -d "$src_dir" ]; then
        return 0
    fi
    mkdir -p "$dst_dir"
    find "$src_dir" -maxdepth 1 \( -type f -o -type l \) | while IFS= read -r path; do
        name=$(basename -- "$path")
        for pattern in "$@"; do
            case "$name" in
                $pattern)
                    cp -a "$path" "$dst_dir/"
                    break
                    ;;
            esac
        done
    done
}

copy_compiler_runtime_dir() {
    compiler=$1
    dst_dir=$2
    runtime_path=$("$compiler" -print-file-name=libgcc_s.so.1 2>/dev/null || true)
    case "$runtime_path" in
        ""|"libgcc_s.so.1")
            return 0
            ;;
    esac
    runtime_dir=$(dirname -- "$runtime_path")
    copy_shared_objects "$runtime_dir" "$dst_dir"
}

copy_glibc_locale_data() {
    root_dir=$1
    if [ -d /usr/lib/locale/C.utf8 ]; then
        copy_if_exists /usr/lib/locale/C.utf8 "$root_dir/usr/lib/locale/C.utf8"
    fi
    if [ -f /usr/lib/locale/locale-archive ]; then
        copy_if_exists /usr/lib/locale/locale-archive "$root_dir/usr/lib/locale/locale-archive"
    fi
}

validate_output_tree() {
    root_dir=$1
    runtime=$2
    require_executable() {
        path=$1
        if [ ! -x "$path" ]; then
            echo "rootfs validation failed: missing executable $path" >&2
            exit 1
        fi
    }

    require_regular_file() {
        path=$1
        if [ ! -f "$path" ]; then
            echo "rootfs validation failed: missing $path" >&2
            exit 1
        fi
    }

    target_enabled() {
        target=$1
        for enabled in $TARGETS; do
            if [ "$enabled" = "$target" ]; then
                return 0
            fi
        done
        return 1
    }

    if target_enabled basic; then
        require_executable "$root_dir/basic_testcode.sh"
    fi
    if target_enabled busybox; then
        require_executable "$root_dir/busybox_testcode.sh"
        require_executable "$root_dir/busybox"
    fi
    if target_enabled lua; then
        require_executable "$root_dir/lua_testcode.sh"
        require_executable "$root_dir/lua"
    fi
    if target_enabled iozone; then
        require_executable "$root_dir/iozone_testcode.sh"
        require_executable "$root_dir/iozone"
    fi
    if target_enabled iperf; then
        require_executable "$root_dir/iperf_testcode.sh"
        require_executable "$root_dir/iperf3"
    fi
    if target_enabled libcbench; then
        require_executable "$root_dir/libcbench_testcode.sh"
    fi
    if target_enabled libc-test; then
        require_executable "$root_dir/libctest_testcode.sh"
        require_executable "$root_dir/run-static.sh"
        require_executable "$root_dir/run-dynamic.sh"
    fi
    if target_enabled lmbench_src; then
        require_executable "$root_dir/lmbench_testcode.sh"
    fi
    if target_enabled cyclictest; then
        require_executable "$root_dir/cyclictest_testcode.sh"
        require_executable "$root_dir/cyclictest"
    fi
    if target_enabled ltp; then
        require_regular_file "$root_dir/ltp/runtest/syscalls"
        require_executable "$root_dir/ltp_testcode.sh"
        require_executable "$root_dir/ltp/testcases/bin/clone08"
    fi
    if target_enabled netperf; then
        require_executable "$root_dir/netperf_testcode.sh"
        require_executable "$root_dir/netperf"
        require_executable "$root_dir/netserver"
    fi

    case "$runtime" in
        glibc)
            if [ ! -e "$root_dir/lib/libgcc_s.so.1" ] && [ ! -e "$root_dir/lib64/libgcc_s.so.1" ]; then
                echo "rootfs validation failed: missing libgcc_s.so.1 in $root_dir" >&2
                exit 1
            fi
            ;;
        musl)
            libc_path=
            for candidate in "$root_dir/lib/libc.so" "$root_dir/lib64/libc.so"; do
                if [ -e "$candidate" ]; then
                    libc_path=$candidate
                    break
                fi
            done
            if [ -z "$libc_path" ] || ! is_elf_binary "$libc_path"; then
                echo "rootfs validation failed: musl libc.so is missing or not an ELF binary in $root_dir" >&2
                exit 1
            fi
            loader_path=
            for candidate in \
                "$root_dir/lib/ld-musl-riscv64.so.1" \
                "$root_dir/lib/ld-musl-loongarch64.so.1" \
                "$root_dir/lib64/ld-musl-loongarch-lp64d.so.1"
            do
                if [ -L "$candidate" ] || [ -e "$candidate" ]; then
                    loader_path=$candidate
                    break
                fi
            done
            if [ -z "$loader_path" ]; then
                echo "rootfs validation failed: missing musl loader symlink in $root_dir" >&2
                exit 1
            fi
            if [ -L "$loader_path" ]; then
                loader_target=$(readlink "$loader_path" 2>/dev/null || true)
                if [ "$loader_target" = "/lib/libc.so" ] || [ "$loader_target" = "/lib64/libc.so" ]; then
                    echo "rootfs validation failed: musl loader symlink still uses absolute libc target in $root_dir" >&2
                    exit 1
                fi
            elif ! is_elf_binary "$loader_path"; then
                echo "rootfs validation failed: musl loader is not an ELF binary in $root_dir" >&2
                exit 1
            fi
            ;;
    esac
}

normalize_runtime_tree() {
    root_dir=$1
    mkdir -p "$root_dir/bin" "$root_dir/tmp" "$root_dir/var/tmp"
    chmod 1777 "$root_dir/tmp" "$root_dir/var/tmp" || true

    for sidecar in dlopen_dso.so tls_get_new-dtv_dso.so; do
        if [ -f "$root_dir/lib/$sidecar" ] && [ ! -e "$root_dir/$sidecar" ]; then
            cp -a "$root_dir/lib/$sidecar" "$root_dir/$sidecar"
        fi
    done

    find "$root_dir" -maxdepth 1 -type f \( -name '*.sh' -o -name '*_testcode.sh' \) -exec chmod +x {} \;
    for path in "$root_dir/run-static.sh" "$root_dir/run-dynamic.sh" "$root_dir/run-all.sh" "$root_dir/test.sh"; do
        if [ -f "$path" ]; then
            chmod +x "$path"
        fi
    done
}

copy_runtime_rv_glibc() {
    root_dir=$1
    mkdir -p "$root_dir/lib"
    copy_shared_objects /usr/riscv64-linux-gnu/lib "$root_dir/lib"
    copy_shared_objects /usr/lib/riscv64-linux-gnu "$root_dir/lib"
    copy_compiler_runtime_dir riscv64-linux-gnu-gcc "$root_dir/lib"
    copy_glibc_locale_data "$root_dir"
}

copy_runtime_rv_musl() {
    root_dir=$1
    sysroot=$(riscv64-linux-musl-gcc -print-sysroot)
    mkdir -p "$root_dir/lib"
    copy_shared_objects "$sysroot/lib" "$root_dir/lib"
    copy_shared_objects "$sysroot/usr/lib" "$root_dir/lib"
    if command -v riscv64-linux-gnu-gcc >/dev/null 2>&1; then
        copy_selected_runtime_libs /usr/riscv64-linux-gnu/lib "$root_dir/lib" \
            'libstdc++.so' 'libstdc++.so.*' \
            'libgcc_s.so' 'libgcc_s.so.*' \
            'libatomic.so' 'libatomic.so.*' \
            'libgomp.so' 'libgomp.so.*' \
            'libgfortran.so' 'libgfortran.so.*' \
            'libasan.so' 'libasan.so.*' \
            'libubsan.so' 'libubsan.so.*' \
            'libitm.so' 'libitm.so.*' \
            'libssp.so' 'libssp.so.*' \
            'libquadmath.so' 'libquadmath.so.*'
        copy_selected_runtime_libs /usr/lib/riscv64-linux-gnu "$root_dir/lib" \
            'libstdc++.so' 'libstdc++.so.*' \
            'libgcc_s.so' 'libgcc_s.so.*' \
            'libatomic.so' 'libatomic.so.*' \
            'libgomp.so' 'libgomp.so.*' \
            'libgfortran.so' 'libgfortran.so.*' \
            'libasan.so' 'libasan.so.*' \
            'libubsan.so' 'libubsan.so.*' \
            'libitm.so' 'libitm.so.*' \
            'libssp.so' 'libssp.so.*' \
            'libquadmath.so' 'libquadmath.so.*'
        runtime_dir=$(dirname -- "$(riscv64-linux-gnu-gcc -print-file-name=libgcc_s.so.1 2>/dev/null || printf '%s' libgcc_s.so.1)")
        copy_selected_runtime_libs "$runtime_dir" "$root_dir/lib" \
            'libstdc++.so' 'libstdc++.so.*' \
            'libgcc_s.so' 'libgcc_s.so.*' \
            'libatomic.so' 'libatomic.so.*' \
            'libgomp.so' 'libgomp.so.*' \
            'libgfortran.so' 'libgfortran.so.*' \
            'libasan.so' 'libasan.so.*' \
            'libubsan.so' 'libubsan.so.*' \
            'libitm.so' 'libitm.so.*' \
            'libssp.so' 'libssp.so.*' \
            'libquadmath.so' 'libquadmath.so.*'
        copy_glibc_locale_data "$root_dir"
    fi
    normalize_musl_runtime_dir "$sysroot/lib" "$root_dir/lib" ld-musl-riscv64.so.1
}

copy_runtime_la_glibc() {
    root_dir=$1
    sysroot=$(loongarch64-linux-gnu-gcc -print-sysroot)
    mkdir -p "$root_dir/lib" "$root_dir/lib64"
    copy_shared_objects "$sysroot/usr/lib64" "$root_dir/lib"
    copy_shared_objects "$sysroot/lib64" "$root_dir/lib"
    copy_shared_objects "$sysroot/usr/lib64" "$root_dir/lib64"
    copy_shared_objects "$sysroot/lib64" "$root_dir/lib64"
    copy_shared_objects "$sysroot/usr/lib" "$root_dir/lib"
    copy_compiler_runtime_dir loongarch64-linux-gnu-gcc "$root_dir/lib"
    copy_compiler_runtime_dir loongarch64-linux-gnu-gcc "$root_dir/lib64"
    copy_glibc_locale_data "$root_dir"
}

copy_runtime_la_musl() {
    root_dir=$1
    sysroot=$(loongarch64-linux-musl-gcc -print-sysroot)
    mkdir -p "$root_dir/lib" "$root_dir/lib64"
    copy_shared_objects "$sysroot/lib" "$root_dir/lib"
    copy_shared_objects "$sysroot/usr/lib" "$root_dir/lib"
    if command -v loongarch64-linux-gnu-gcc >/dev/null 2>&1; then
        sysroot_gnu=$(loongarch64-linux-gnu-gcc -print-sysroot)
        copy_selected_runtime_libs "$sysroot_gnu/usr/lib64" "$root_dir/lib" \
            'libstdc++.so' 'libstdc++.so.*' \
            'libgcc_s.so' 'libgcc_s.so.*' \
            'libatomic.so' 'libatomic.so.*' \
            'libgomp.so' 'libgomp.so.*' \
            'libgfortran.so' 'libgfortran.so.*' \
            'libasan.so' 'libasan.so.*' \
            'libubsan.so' 'libubsan.so.*' \
            'libitm.so' 'libitm.so.*' \
            'libssp.so' 'libssp.so.*' \
            'libquadmath.so' 'libquadmath.so.*'
        copy_selected_runtime_libs "$sysroot_gnu/lib64" "$root_dir/lib" \
            'libstdc++.so' 'libstdc++.so.*' \
            'libgcc_s.so' 'libgcc_s.so.*' \
            'libatomic.so' 'libatomic.so.*' \
            'libgomp.so' 'libgomp.so.*' \
            'libgfortran.so' 'libgfortran.so.*' \
            'libasan.so' 'libasan.so.*' \
            'libubsan.so' 'libubsan.so.*' \
            'libitm.so' 'libitm.so.*' \
            'libssp.so' 'libssp.so.*' \
            'libquadmath.so' 'libquadmath.so.*'
        copy_selected_runtime_libs "$sysroot_gnu/usr/lib" "$root_dir/lib" \
            'libstdc++.so' 'libstdc++.so.*' \
            'libgcc_s.so' 'libgcc_s.so.*' \
            'libatomic.so' 'libatomic.so.*' \
            'libgomp.so' 'libgomp.so.*' \
            'libgfortran.so' 'libgfortran.so.*' \
            'libasan.so' 'libasan.so.*' \
            'libubsan.so' 'libubsan.so.*' \
            'libitm.so' 'libitm.so.*' \
            'libssp.so' 'libssp.so.*' \
            'libquadmath.so' 'libquadmath.so.*'
        runtime_dir=$(dirname -- "$(loongarch64-linux-gnu-gcc -print-file-name=libgcc_s.so.1 2>/dev/null || printf '%s' libgcc_s.so.1)")
        copy_selected_runtime_libs "$runtime_dir" "$root_dir/lib" \
            'libstdc++.so' 'libstdc++.so.*' \
            'libgcc_s.so' 'libgcc_s.so.*' \
            'libatomic.so' 'libatomic.so.*' \
            'libgomp.so' 'libgomp.so.*' \
            'libgfortran.so' 'libgfortran.so.*' \
            'libasan.so' 'libasan.so.*' \
            'libubsan.so' 'libubsan.so.*' \
            'libitm.so' 'libitm.so.*' \
            'libssp.so' 'libssp.so.*' \
            'libquadmath.so' 'libquadmath.so.*'
        copy_glibc_locale_data "$root_dir"
    fi
    normalize_musl_runtime_dir "$sysroot/lib" "$root_dir/lib" ld-musl-loongarch64.so.1
    if [ -f "$root_dir/lib/ld-musl-loongarch64.so.1" ] && [ ! -e "$root_dir/lib64/ld-musl-loongarch-lp64d.so.1" ]; then
        ln -sf ../lib/ld-musl-loongarch64.so.1 "$root_dir/lib64/ld-musl-loongarch-lp64d.so.1"
    fi
    if [ -f "$root_dir/lib/libc.so" ] && [ ! -e "$root_dir/lib64/libc.so" ]; then
        ln -sf ../lib/libc.so "$root_dir/lib64/libc.so"
    fi
}

rebuild_libctest_with_musl() {
    root_dir=$1
    arch=$2

    case "$arch" in
        rv)
            ensure_rv_musl_toolchain
            musl_prefix="riscv64-buildroot-linux-musl-"
            ;;
        la)
            ensure_la_musl_toolchain
            musl_prefix="loongarch64-linux-musl-"
            ;;
        *)
            echo "unsupported arch for musl libc-test rebuild: $arch" >&2
            exit 2
            ;;
    esac

    make -C "$TESTSUITS_ROOT/libc-test" clean >/dev/null 2>&1 || true
    make -C "$TESTSUITS_ROOT/libc-test" \
        disk \
        PREFIX="$musl_prefix" \
        CC="${musl_prefix}gcc -fno-pie -no-pie" \
        -j 1
    cp -r "$TESTSUITS_ROOT/libc-test/disk"/. "$root_dir"/
    mkdir -p "$root_dir/lib"
    cp "$TESTSUITS_ROOT/libc-test/src/functional"/*.so "$TESTSUITS_ROOT/libc-test/src/regression"/*.so "$root_dir/lib/"
    rm -f "$root_dir/run-all.sh"
    cp "$TESTSUITS_ROOT/scripts/libctest/libctest_testcode.sh" "$root_dir/"

    case "$arch" in
        rv)
            copy_runtime_rv_musl "$root_dir"
            ;;
        la)
            copy_runtime_la_musl "$root_dir"
            ;;
    esac
}

if [ -f "$TESTSUITS_ROOT/Makefile.sub" ]; then
    MAKEFILE_SUB_SOURCE="$TESTSUITS_ROOT/Makefile.sub"
else
    MAKEFILE_SUB_SOURCE="$VENDORED_MAKEFILE_SUB"
fi

require_file "$MAKEFILE_SUB_SOURCE"
require_cmd make

WORK_DIR=$(mktemp -d /tmp/osk-full-rootfs.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

TOOL_ALIAS_DIR="$WORK_DIR/tool-bin"
mkdir -p "$TOOL_ALIAS_DIR"
PATH="$TOOL_ALIAS_DIR:$PATH"
export PATH

TARGETS=${FULL_SUITE_TARGETS:-"basic busybox lua libc-test iozone iperf libcbench lmbench_src cyclictest ltp netperf"}
if [ "$FULL_SUITE_INCLUDE_UNIXBENCH" = "1" ]; then
    TARGETS="$TARGETS unixbench"
fi

case "$ARCH:$RUNTIME" in
    rv:glibc)
        STAGE_DIR="$WORK_DIR/riscv64-glibc"
        PREFIX="riscv64-linux-gnu-"
        require_cmd riscv64-linux-gnu-gcc
        ;;
    rv:musl)
        STAGE_DIR="$WORK_DIR/riscv64-musl"
        PREFIX="riscv64-buildroot-linux-musl-"
        ensure_rv_musl_toolchain
        ;;
    la:glibc)
        STAGE_DIR="$WORK_DIR/loongarch64-glibc"
        PREFIX="loongarch64-linux-gnu-"
        require_cmd loongarch64-linux-gnu-gcc
        ;;
    la:musl)
        STAGE_DIR="$WORK_DIR/loongarch64-musl"
        PREFIX="loongarch64-linux-musl-"
        ensure_la_musl_toolchain
        ;;
    *)
        echo "unsupported variant: $ARCH/$RUNTIME" >&2
        exit 2
        ;;
esac

seed_sys_queue_header "${PREFIX}gcc"

mkdir -p "$STAGE_DIR"

PATCHED_MAKEFILE="$WORK_DIR/Makefile.sub"
PATCHED_IPERF_BUILD="$WORK_DIR/iperf-build.sh"
PATCHED_LMBENCH_MAKEFILE="$WORK_DIR/lmbench_src.Makefile"
PATCHED_LMBENCH_SRC_MAKEFILE="$WORK_DIR/lmbench_src.src.Makefile"
PATCHED_RTTESTS_MAKEFILE="$WORK_DIR/rt-tests.Makefile"
PATCHED_RTTESTS_NUMA_HEADER="$WORK_DIR/numa.h"
PATCHED_RTTESTS_SCHED_SHIM="$WORK_DIR/osk_sched_shim.c"
PATCHED_LTP_BUILD="$WORK_DIR/ltp-build.sh"
PATCHED_BUSYBOX_PREP="$WORK_DIR/prepare-busybox-config.sh"
PATCHED_LIBCTEST_BUILD="$WORK_DIR/libctest-build.sh"
PATCHED_LIBCTEST_LA_GLIBC_MAKEFILE="$WORK_DIR/libctest.la-glibc.Makefile"

cat > "$PATCHED_BUSYBOX_PREP" <<'EOF'
#!/bin/sh
set -eu
config=$1
sed -i \
    -e 's/^CONFIG_TC=y/# CONFIG_TC is not set/' \
    -e 's/^CONFIG_FEATURE_TC_INGRESS=y/# CONFIG_FEATURE_TC_INGRESS is not set/' \
    "$config"
EOF
chmod +x "$PATCHED_BUSYBOX_PREP"

sed \
    -e 's/LDFLAGS += -Os -s -lpthread -lm -lrt/LDFLAGS += -Os -s -lm -ldl -lrt -lresolv -lpthread/' \
    "$TESTSUITS_ROOT/libc-test/Makefile" > "$PATCHED_LIBCTEST_LA_GLIBC_MAKEFILE"

cat > "$PATCHED_LIBCTEST_BUILD" <<'EOF'
#!/bin/sh
set -eu

case "${PREFIX:-}" in
    loongarch64-linux-gnu-)
        make -C libc-test \
            -f "__PATCHED_LIBCTEST_LA_GLIBC_MAKEFILE__" \
            disk \
            PREFIX="$PREFIX" \
            -j 1
        ;;
    riscv64-buildroot-linux-musl-|loongarch64-linux-musl-)
        make -C libc-test \
            disk \
            PREFIX="$PREFIX" \
            CC="${PREFIX}gcc -fno-pie -no-pie" \
            -j 1
        ;;
    *)
        make -C libc-test disk PREFIX="${PREFIX:-}" -j 1
        ;;
esac
EOF
sed -i "s@__PATCHED_LIBCTEST_LA_GLIBC_MAKEFILE__@$PATCHED_LIBCTEST_LA_GLIBC_MAKEFILE@g" "$PATCHED_LIBCTEST_BUILD"
chmod +x "$PATCHED_LIBCTEST_BUILD"

if target_enabled iperf; then
    require_file "$TESTSUITS_ROOT/iperf/build.sh"
    {
        printf '%s\n' '#!/bin/bash' ''
        printf '%s\n' 'set -eu' ''
        printf '%s\n' 'make distclean >/dev/null 2>&1 || make clean >/dev/null 2>&1 || true'
        printf '%s\n' 'rm -f src/iperf3 src/iperf3-main.o src/*.o src/*.lo src/.libs/iperf3 src/.libs/*.o src/.libs/*.a src/.libs/*.la src/.deps/iperf3-main.Po' ''
        tail -n +5 "$TESTSUITS_ROOT/iperf/build.sh" | sed \
            -e 's/--enable-static-bin/--enable-static-bin --without-openssl/' \
            -e "s/make V=1 -j */make V=1 -j $BUILD_JOBS/"
    } > "$PATCHED_IPERF_BUILD"
    chmod +x "$PATCHED_IPERF_BUILD"
fi

{
    printf '%s\n' '#!/bin/bash' ''
    printf '%s\n' 'set -ex' ''
    printf '%s\n' 'dest=$1' ''
    printf '%s\n' 'EPOLL_COMPAT=0' ''
    printf '%s\n' 'AIO_COMPAT_DIR=' ''
    printf '%s\n' 'CC_CMD=' ''
    printf '%s\n' 'CONFIGURE_ARGS=' ''
    printf '%s\n' 'if [ "${CLEAN_REMAINING_BUILD:-0}" = "1" ]; then'
    printf '%s\n' '    make clean'
    printf '%s\n' 'fi'
    printf '%s\n' "if [ ! -f VERSION ]; then printf '%s\n' 'LTP-${LTP_RELEASE}' > VERSION; fi"
    printf '%s\n' 'if [ "${CLEAN_REMAINING_BUILD:-0}" = "1" ] || [ ! -f configure ]; then'
    printf '%s\n' '    make autotools'
    printf '%s\n' 'fi' ''
    printf '%s\n' 'rm -f Version' ''
    printf '%s\n' 'case "${PREFIX:-}" in'
    printf '%s\n' "  riscv64-buildroot-linux-musl-)"
    printf '%s\n' '    EPOLL_COMPAT=1'
    printf '%s\n' '    CC_CMD=riscv64-linux-musl-gcc'
    printf '%s\n' "    CONFIGURE_ARGS=\"--prefix=/ltp --host=riscv64-linux-musl CC=riscv64-linux-musl-gcc --with-target-cflags='-march=rv64gc' --without-tirpc\""
    printf '%s\n' '    ;;'
    printf '%s\n' '  riscv64-linux-gnu-)'
    printf '%s\n' '    CC_CMD=riscv64-linux-gnu-gcc'
    printf '%s\n' '    CONFIGURE_ARGS="--prefix=/ltp --host=riscv64-linux-gnu CC=riscv64-linux-gnu-gcc --without-tirpc"'
    printf '%s\n' '    ;;'
    printf '%s\n' '  loongarch64-linux-musl-)'
    printf '%s\n' '    EPOLL_COMPAT=1'
    printf '%s\n' '    CC_CMD=loongarch64-linux-musl-gcc'
    printf '%s\n' '    CONFIGURE_ARGS="--prefix=/ltp --host=loongarch64-linux-musl CC=loongarch64-linux-musl-gcc --without-tirpc"'
    printf '%s\n' '    ;;'
    printf '%s\n' '  *)'
    printf '%s\n' '    CC_CMD=loongarch64-linux-gnu-gcc'
    printf '%s\n' '    CONFIGURE_ARGS="--prefix=/ltp --host=loongarch64-linux-gnu CC=loongarch64-linux-gnu-gcc --without-tirpc"'
    printf '%s\n' '    ;;'
    printf '%s\n' 'esac' ''
    printf '%s\n' 'if [ "$EPOLL_COMPAT" = "1" ]; then'
    printf '%s\n' '    "$CC_CMD" -O2 -c oscomp_epoll_compat.c -o oscomp_epoll_compat.o'
    printf '%s\n' '    export LIBS="$PWD/oscomp_epoll_compat.o ${LIBS:-}"'
    printf '%s\n' 'fi' ''
    printf '%s\n' 'AIO_COMPAT_DIR="$PWD/oscomp-libaio/build"'
    printf '%s\n' 'mkdir -p "$AIO_COMPAT_DIR/include" "$AIO_COMPAT_DIR/lib"'
    printf '%s\n' 'cp oscomp-libaio/libaio.h "$AIO_COMPAT_DIR/include/libaio.h"'
    printf '%s\n' '    "$CC_CMD" -O2 -fPIC -c oscomp-libaio/libaio.c -o "$AIO_COMPAT_DIR/lib/libaio.o"'
    printf '%s\n' '    "$CC_CMD" -shared -Wl,-soname,libaio.so.1 -o "$AIO_COMPAT_DIR/lib/libaio.so.1" "$AIO_COMPAT_DIR/lib/libaio.o"'
    printf '%s\n' '    ln -sf libaio.so.1 "$AIO_COMPAT_DIR/lib/libaio.so"'
    printf '%s\n' '    "${CC_CMD%gcc}ar" rcs "$AIO_COMPAT_DIR/lib/libaio.a" "$AIO_COMPAT_DIR/lib/libaio.o"'
    printf '%s\n' '    export CPPFLAGS="-I$AIO_COMPAT_DIR/include ${CPPFLAGS:-}"'
    printf '%s\n' '    export LDFLAGS="-L$AIO_COMPAT_DIR/lib ${LDFLAGS:-}"' ''
    printf '%s\n' 'eval ./configure "$CONFIGURE_ARGS"' ''
    printf '%s\n' "make -C lib -j $BUILD_JOBS"
    printf '%s\n' "make -C testcases/kernel/syscalls -j $BUILD_JOBS"
    printf '%s\n' 'make -C testcases/kernel/syscalls install DESTDIR="$dest" prefix=/ltp'
    printf '%s\n' 'mkdir -p "$dest/lib" "$dest/lib64"'
    printf '%s\n' 'cp -a "$AIO_COMPAT_DIR/lib"/libaio.so* "$dest/lib/"'
    printf '%s\n' 'cp -a "$AIO_COMPAT_DIR/lib"/libaio.so* "$dest/lib64/" 2>/dev/null || true'
    printf '%s\n' 'mkdir -p "$dest/ltp/runtest"'
    printf '%s\n' 'cp runtest/syscalls "$dest/ltp/runtest/syscalls"'
} > "$PATCHED_LTP_BUILD"
chmod +x "$PATCHED_LTP_BUILD"

if target_enabled lmbench_src; then
    require_file "$TESTSUITS_ROOT/lmbench_src/src/Makefile"
    sed \
        -e 's@COMPILE=$(CC) $(CFLAGS) -I/usr/include/tirpc  $(CPPFLAGS) $(LDFLAGS) @COMPILE=$(CC) $(CFLAGS) -I../libtirpc-1.3.6/tirpc -L../libtirpc-1.3.6/src/.libs $(CPPFLAGS) $(LDFLAGS) @' \
        -e 's@-static -lm ../libtirpc-1\.3\.6/src/\.libs/libtirpc\.a@-static -lm ../libtirpc-1.3.6/src/.libs/libtirpc.a -lpthread@' \
        "$TESTSUITS_ROOT/lmbench_src/src/Makefile" > "$PATCHED_LMBENCH_SRC_MAKEFILE"
fi

cat > "$PATCHED_RTTESTS_NUMA_HEADER" <<'EOF'
#ifndef OSK_RTTESTS_NUMA_STUB_H
#define OSK_RTTESTS_NUMA_STUB_H

#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct bitmask {
    unsigned long size;
    unsigned long *maskp;
};

static inline unsigned long osk_numa_word_count(unsigned long bits)
{
    return (bits + (8UL * sizeof(unsigned long)) - 1) / (8UL * sizeof(unsigned long));
}

static inline struct bitmask *osk_numa_alloc_mask(unsigned long bits)
{
    struct bitmask *mask = (struct bitmask *)malloc(sizeof(*mask));
    unsigned long words = osk_numa_word_count(bits);
    if (!mask) {
        return NULL;
    }
    mask->size = bits;
    mask->maskp = (unsigned long *)calloc(words, sizeof(unsigned long));
    if (!mask->maskp) {
        free(mask);
        return NULL;
    }
    return mask;
}

static inline void osk_numa_setbit(struct bitmask *mask, unsigned long bit)
{
    if (!mask || !mask->maskp || bit >= mask->size) {
        return;
    }
    mask->maskp[bit / (8UL * sizeof(unsigned long))] |= 1UL << (bit % (8UL * sizeof(unsigned long)));
}

static inline int numa_available(void)
{
    return 0;
}

static inline void *numa_alloc_onnode(size_t size, int node)
{
    (void)node;
    return malloc(size);
}

static inline void numa_free(void *ptr, size_t size)
{
    (void)size;
    free(ptr);
}

static inline int numa_run_on_node(int node)
{
    (void)node;
    return 0;
}

static inline int numa_node_of_cpu(int cpu)
{
    (void)cpu;
    return 0;
}

static inline struct bitmask *numa_allocate_cpumask(void)
{
    long cpus = sysconf(_SC_NPROCESSORS_CONF);
    if (cpus < 1) {
        cpus = 1;
    }
    return osk_numa_alloc_mask((unsigned long)cpus);
}

static inline int numa_sched_getaffinity(pid_t pid, struct bitmask *mask)
{
    cpu_set_t cpuset;
    unsigned long i;
    (void)pid;
    if (!mask) {
        return -1;
    }
    CPU_ZERO(&cpuset);
    if (sched_getaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        return -1;
    }
    memset(mask->maskp, 0, osk_numa_word_count(mask->size) * sizeof(unsigned long));
    for (i = 0; i < mask->size; i++) {
        if (CPU_ISSET((int)i, &cpuset)) {
            osk_numa_setbit(mask, i);
        }
    }
    return 0;
}

static inline int numa_sched_setaffinity(pid_t pid, struct bitmask *mask)
{
    cpu_set_t cpuset;
    unsigned long i;
    CPU_ZERO(&cpuset);
    if (!mask) {
        return sched_setaffinity(pid, sizeof(cpuset), &cpuset);
    }
    for (i = 0; i < mask->size; i++) {
        if (mask->maskp[i / (8UL * sizeof(unsigned long))] & (1UL << (i % (8UL * sizeof(unsigned long))))) {
            CPU_SET((int)i, &cpuset);
        }
    }
    return sched_setaffinity(pid, sizeof(cpuset), &cpuset);
}

static inline unsigned int numa_bitmask_isbitset(const struct bitmask *mask, unsigned long i)
{
    if (!mask || !mask->maskp || i >= mask->size) {
        return 0;
    }
    return !!(mask->maskp[i / (8UL * sizeof(unsigned long))] & (1UL << (i % (8UL * sizeof(unsigned long)))));
}

static inline void numa_bitmask_clearbit(struct bitmask *mask, unsigned long i)
{
    if (!mask || !mask->maskp || i >= mask->size) {
        return;
    }
    mask->maskp[i / (8UL * sizeof(unsigned long))] &= ~(1UL << (i % (8UL * sizeof(unsigned long))));
}

static inline unsigned int numa_bitmask_weight(const struct bitmask *mask)
{
    unsigned long i;
    unsigned int weight = 0;
    if (!mask) {
        return 1;
    }
    for (i = 0; i < mask->size; i++) {
        weight += numa_bitmask_isbitset(mask, i);
    }
    return weight;
}

static inline struct bitmask *numa_parse_cpustring_all(const char *s)
{
    struct bitmask *mask = numa_allocate_cpumask();
    (void)s;
    if (!mask) {
        return NULL;
    }
    if (numa_sched_getaffinity(0, mask) != 0) {
        memset(mask->maskp, 0, osk_numa_word_count(mask->size) * sizeof(unsigned long));
        osk_numa_setbit(mask, 0);
    }
    return mask;
}

static inline void numa_bitmask_free(struct bitmask *mask)
{
    if (!mask) {
        return;
    }
    free(mask->maskp);
    free(mask);
}

#endif
EOF

cat > "$PATCHED_RTTESTS_SCHED_SHIM" <<'EOF'
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__linux__) && (defined(__loongarch__) || defined(__riscv))
#ifndef __NR_sched_setparam
#define __NR_sched_setparam 118
#endif
#ifndef __NR_sched_setscheduler
#define __NR_sched_setscheduler 119
#endif
#ifndef __NR_sched_getscheduler
#define __NR_sched_getscheduler 120
#endif
#ifndef __NR_sched_getparam
#define __NR_sched_getparam 121
#endif

int sched_setparam(pid_t pid, const struct sched_param *param)
{
    return syscall(__NR_sched_setparam, pid, param);
}

int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
{
    return syscall(__NR_sched_setscheduler, pid, policy, param);
}

int sched_getscheduler(pid_t pid)
{
    return syscall(__NR_sched_getscheduler, pid);
}

int sched_getparam(pid_t pid, struct sched_param *param)
{
    return syscall(__NR_sched_getparam, pid, param);
}
#endif
EOF

sed \
    -e "/^VPATH\t+= src\\/oslat:/a VPATH\t+= $WORK_DIR" \
    -e "s@-I\\./numactl-2\\.0\\.14@-I$WORK_DIR -I./numactl-2.0.14@" \
    -e 's/LIBOBJS =$(addprefix $(OBJDIR)\/,rt-error.o rt-get_cpu.o rt-sched.o rt-utils.o \\/LIBOBJS =$(addprefix $(OBJDIR)\/,osk_sched_shim.o rt-error.o rt-get_cpu.o rt-sched.o rt-utils.o \\/' \
    -e 's/^all: extract_numactl $(TARGETS) hwlatdetect get_cyclictest_snapshot | $(OBJDIR)$/all: cyclictest hackbench hwlatdetect get_cyclictest_snapshot | $(OBJDIR)/' \
    -e 's/^cyclictest: $(OBJDIR)\/cyclictest.o $(OBJDIR)\/librttest.a $(OBJDIR)\/librttestnuma.a$/cyclictest: $(OBJDIR)\/cyclictest.o $(OBJDIR)\/librttest.a/' \
    -e 's/$(RTTESTLIB) $(RTTESTNUMA)/$(RTTESTLIB)/' \
    -e 's/histogram.o)/histogram.o rt-numa.o)/' \
    "$TESTSUITS_ROOT/rt-tests-2.7/Makefile" > "$PATCHED_RTTESTS_MAKEFILE"

if target_enabled lmbench_src; then
    require_file "$TESTSUITS_ROOT/lmbench_src/Makefile"
    sed \
        -e 's@mkdir -p /opt/loongarch64-linux-musl-cross/loongarch64-linux-musl/usr/include/@test ! -d /opt/toolchain-loongarch64-linux-gnu-gcc8-host-x86_64-2022-07-18/sysroot/usr/include/sys || mkdir -p /opt/loongarch64-linux-musl-cross/loongarch64-linux-musl/usr/include/@' \
        -e 's@cp -fr /opt/toolchain-loongarch64-linux-gnu-gcc8-host-x86_64-2022-07-18/sysroot/usr/include/sys /opt/loongarch64-linux-musl-cross/loongarch64-linux-musl/usr/include/@test ! -d /opt/toolchain-loongarch64-linux-gnu-gcc8-host-x86_64-2022-07-18/sysroot/usr/include/sys || cp -fr /opt/toolchain-loongarch64-linux-gnu-gcc8-host-x86_64-2022-07-18/sysroot/usr/include/sys /opt/loongarch64-linux-musl-cross/loongarch64-linux-musl/usr/include/@' \
        -e 's@rm -fr libtirpc-1\.3\.6@chmod -R u+w libtirpc-1.3.6 2>/dev/null || true; rm -fr libtirpc-1.3.6@' \
        -e 's/make -j 8/make -j $(NPROC)/' \
        -e "s@cd src && \$(MAKE)\$@mkdir -p bin/build; cd src; \$(MAKE) -f $PATCHED_LMBENCH_SRC_MAKEFILE O=../bin/build all opt@" \
        -e "s@cd src && \$(MAKE) oscomp@mkdir -p bin/build; cd src; \$(MAKE) -f $PATCHED_LMBENCH_SRC_MAKEFILE O=../bin/build oscomp@" \
        "$TESTSUITS_ROOT/lmbench_src/Makefile" > "$PATCHED_LMBENCH_MAKEFILE"
fi

sed \
    -e "s@cp config/busybox-config-\\\$(ARCH) busybox/.config@cp config/busybox-config-\\\$(ARCH) busybox/.config\\n\t$PATCHED_BUSYBOX_PREP busybox/.config@" \
    -e "s@make -C libc-test disk PREFIX=\\\$(PREFIX) -j 1@PREFIX=\\\$(PREFIX) $PATCHED_LIBCTEST_BUILD@" \
    -e 's/make -C busybox CC="$(CC) -static" STRIP=$(STRIP) -j$/make -C busybox CC="$(CC) -static" STRIP=$(STRIP) -j $(BUILD_JOBS)/' \
    -e 's/make -C lua CC="$(CC) -static" -j $(NPROC)/make -C lua CC="$(CC) -static" -j $(BUILD_JOBS)/' \
    -e 's/make -C iozone linux CC="$(CC)" -j $/make -C iozone linux CC="$(CC)" -j $(BUILD_JOBS)/' \
    -e 's/make -j 8$/make -j $(BUILD_JOBS)/' \
    -e "s@cd iperf && ./build.sh \$(DESTDIR)@cd iperf; PREFIX=\$(PREFIX) $PATCHED_IPERF_BUILD \$(DESTDIR)@" \
    -e "s@make -C lmbench_src CC=\"\$(CC)\" -j \$(NPROC)@make -C lmbench_src -f $PATCHED_LMBENCH_MAKEFILE CC=\"\$(CC)\" -j \$(NPROC)@" \
    -e "s@make -C rt-tests-2.7 CROSS_COMPILE=\$(PREFIX)@make -C rt-tests-2.7 -f $PATCHED_RTTESTS_MAKEFILE CROSS_COMPILE=\$(PREFIX)@" \
    -e "s@cd \$(LTP_SUITE_DIR) && ./build-oscomp.sh \$(DESTDIR)@cd \$(LTP_SUITE_DIR); PREFIX=\$(PREFIX) $PATCHED_LTP_BUILD \$(DESTDIR)@" \
    -e "s@cd ltp-full-${LTP_RELEASE} && ./build-oscomp.sh \$(DESTDIR)@cd ltp-full-${LTP_RELEASE}; PREFIX=\$(PREFIX) $PATCHED_LTP_BUILD \$(DESTDIR)@" \
    "$MAKEFILE_SUB_SOURCE" > "$PATCHED_MAKEFILE"

make -C "$TESTSUITS_ROOT" -f "$PATCHED_MAKEFILE" \
    PREFIX="$PREFIX" \
    NPROC="$BUILD_JOBS" \
    BUILD_JOBS="$BUILD_JOBS" \
    DESTDIR="$STAGE_DIR" \
    clean

chmod -R u+w "$TESTSUITS_ROOT/lmbench_src/libtirpc-1.3.6" 2>/dev/null || true
rm -rf "$TESTSUITS_ROOT/lmbench_src/libtirpc-1.3.6" "$TESTSUITS_ROOT/lmbench_src/bin/build"

make -C "$TESTSUITS_ROOT" -f "$PATCHED_MAKEFILE" \
    PREFIX="$PREFIX" \
    NPROC="$BUILD_JOBS" \
    BUILD_JOBS="$BUILD_JOBS" \
    DESTDIR="$STAGE_DIR" \
    $TARGETS

make -C "$TESTSUITS_ROOT/busybox" CC="${PREFIX}gcc -static" STRIP="${PREFIX}strip" CONFIG_PREFIX="$STAGE_DIR" install
cp "$TESTSUITS_ROOT/busybox/busybox" "$STAGE_DIR/busybox"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp -R "$STAGE_DIR"/. "$OUT_DIR"/

mkdir -p "$OUT_DIR/ltp/runtest"
if [ -f "$TESTSUITS_ROOT/$LTP_SUITE_DIR/runtest/syscalls" ]; then
    cp "$TESTSUITS_ROOT/$LTP_SUITE_DIR/runtest/syscalls" "$OUT_DIR/ltp/runtest/syscalls"
fi
cat > "$OUT_DIR/ltp_testcode.sh" <<'EOF'
#!/bin/bash

echo "#### OS COMP TEST GROUP START ltp ####"
target_dir="/ltp/testcases/bin"
ltp_root="/ltp"
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/ltp/testcases/bin:$PATH"
export PATH
export LTPROOT="$ltp_root"
export LIBRARY_PATH="/glibc/lib:/glibc/lib64:/musl/lib:/musl/lib64:/lib64:/lib"
export LD_LIBRARY_PATH="/glibc/lib:/glibc/lib64:/musl/lib:/musl/lib64:/lib64:/lib"
: "${LTP_TIMEOUT_MUL:=10000}"
export LTP_TIMEOUT_MUL
: "${LTP_RUNTIME_MUL:=1}"
export LTP_RUNTIME_MUL

ltp_ts_now() {
  local up rest
  if IFS=' ' read -r up rest < /proc/uptime 2>/dev/null; then
    printf '%s' "$up"
  else
    printf '0.00'
  fi
}

ltp_emit_ts() {
  local case_name="$1"
  local phase="$2"
  echo "[ltp-ts $(ltp_ts_now)] case=$case_name phase=$phase"
}

ltp_emit_log_file() {
  local log_file_path="$1"
  local line prev_line repeat_count=0 has_prev=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$has_prev" -eq 1 ] && [ "$line" = "$prev_line" ]; then
      repeat_count=$((repeat_count + 1))
      continue
    fi
    if [ "$has_prev" -eq 1 ]; then
      echo "$prev_line"
      if [ "$repeat_count" -gt 0 ]; then
        echo "[ltp-repeat] previous line repeated $repeat_count times"
      fi
    fi
    prev_line="$line"
    repeat_count=0
    has_prev=1
  done < "$log_file_path"
  if [ "$has_prev" -eq 1 ]; then
    echo "$prev_line"
    if [ "$repeat_count" -gt 0 ]; then
      echo "[ltp-repeat] previous line repeated $repeat_count times"
    fi
  fi
}

run_ltp_case() {
  local case_name="$1"
  shift
  local log_file="/tmp/.ltp_${case_name}_$$.log"
  local case_pid hb_pid ret
  : > "$log_file"

  kill_case_session() {
    local sig="$1"
    kill "-$sig" "-$case_pid" 2>/dev/null || kill "-$sig" "$case_pid" 2>/dev/null || /busybox kill "-$sig" "-$case_pid" 2>/dev/null || /busybox kill "-$sig" "$case_pid" 2>/dev/null
  }

  (cd "$target_dir" && /busybox setsid "$@") >"$log_file" 2>&1 &
  case_pid=$!
  (
    while kill -0 "$case_pid" 2>/dev/null; do
      /busybox sleep 30 2>/dev/null || break
      kill -0 "$case_pid" 2>/dev/null || break
      echo "[ltp-heartbeat] $case_name"
    done
  ) &
  hb_pid=$!
  wait "$case_pid"
  ret=$?
  kill "$hb_pid" 2>/dev/null
  wait "$hb_pid" 2>/dev/null
  kill_case_session TERM
  kill_case_session KILL
  ltp_emit_log_file "$log_file"

  local failed=0 broken=0 skipped=0 in_summary=0 line
  while IFS= read -r line; do
    case "$line" in
      Summary:)
        in_summary=1
        ;;
      failed*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          failed=${2:-0}
        fi
        ;;
      broken*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          broken=${2:-0}
        fi
        ;;
      skipped*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          skipped=${2:-0}
        fi
        ;;
    esac
  done < "$log_file"
  ltp_emit_ts "$case_name" done

  if [ "$ret" -eq 0 ] && [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ]; then
    echo "PASS LTP CASE $case_name : 0"
    echo "FAIL LTP CASE $case_name : 0"
  elif [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ] && [ "$skipped" -gt 0 ]; then
    echo "SKIP LTP CASE $case_name : $ret"
  else
    echo "FAIL LTP CASE $case_name : $ret"
  fi
}

while IFS= read -r line; do
  case "$line" in
    ""|\#*) continue ;;
  esac

  set -- $line
  name=$1
  shift

  ltp_emit_ts "$name" run
  echo "RUN LTP CASE $name"
  run_ltp_case "$name" "$@"
done < /ltp/runtest/syscalls
echo "#### OS COMP TEST GROUP END ltp ####"
exit 0
EOF
chmod +x "$OUT_DIR/ltp_testcode.sh"

case "$ARCH:$RUNTIME" in
    rv:glibc)
        rebuild_libctest_with_musl "$OUT_DIR" rv
        copy_runtime_rv_glibc "$OUT_DIR"
        ;;
    rv:musl)
        copy_runtime_rv_musl "$OUT_DIR"
        ;;
    la:glibc)
        rebuild_libctest_with_musl "$OUT_DIR" la
        copy_runtime_la_glibc "$OUT_DIR"
        ;;
    la:musl)
        copy_runtime_la_musl "$OUT_DIR"
        ;;
esac

normalize_runtime_tree "$OUT_DIR"
validate_output_tree "$OUT_DIR" "$RUNTIME"
