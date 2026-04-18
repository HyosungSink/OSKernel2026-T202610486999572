#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <rv|la> <output-image>" >&2
    exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TESTSUITS_ROOT=${TESTSUITS_ROOT:-$ROOT_DIR/testsuits-for-oskernel-pre-2025}
VENDORED_MAKEFILE_SUB=${VENDORED_MAKEFILE_SUB:-$ROOT_DIR/tools/vendor/Makefile.sub}
TOOLCHAIN_CACHE=${TOOLCHAIN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/osk-toolchains}
BUILD_JOBS=${BUILD_JOBS:-10}
LTP_RELEASE=${LTP_RELEASE:-20240524}
LTP_SUITE_DIR=ltp-full-${LTP_RELEASE}
ARCH=$1
OUT=$2

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
    if [ -f "$src" ]; then
        mkdir -p "$(dirname -- "$dst")"
        cp "$src" "$dst"
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

copy_first_existing() {
    dst=$1
    shift
    for src in "$@"; do
        if [ -n "$src" ] && [ -e "$src" ]; then
            mkdir -p "$(dirname -- "$dst")"
            cp -L "$src" "$dst"
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
    if [ -n "$sysroot" ]; then
        sysroot=$(readlink -f "$sysroot" 2>/dev/null || printf '%s' "$sysroot")
    fi
    if [ -z "$sysroot" ] || [ ! -d "$sysroot" ]; then
        return 0
    fi
    # Some distro cross compilers report "/" as sysroot; never write into host root.
    if [ "$sysroot" = "/" ]; then
        return 0
    fi
    if [ -f "$sysroot/include/sys/queue.h" ]; then
        return 0
    fi
    host_queue=$(find /usr/include -path '*/sys/queue.h' 2>/dev/null | head -n 1)
    if [ -z "$host_queue" ] || [ ! -f "$host_queue" ]; then
        return 0
    fi
    mkdir -p "$sysroot/include/sys"
    cp "$host_queue" "$sysroot/include/sys/queue.h"
}

copy_musl_runtime() {
    compiler=$1
    root_dir=$2

    sysroot=$("$compiler" -print-sysroot 2>/dev/null || true)
    triplet=$("$compiler" -dumpmachine 2>/dev/null || true)
    if [ -z "$sysroot" ] || [ ! -d "$sysroot" ]; then
        return 0
    fi

    case "$triplet" in
        riscv64*)
            loader=ld-musl-riscv64.so.1
            ;;
        loongarch64*)
            loader=ld-musl-loongarch64.so.1
            ;;
        *)
            return 0
            ;;
    esac

    copy_first_existing "$root_dir/lib/libc.so" \
        "$sysroot/lib/libc.so" \
        "$sysroot/usr/lib/libc.so" \
        "$sysroot/lib64/libc.so" \
        "$sysroot/usr/lib64/libc.so" || true

    copy_first_existing "$root_dir/lib/$loader" \
        "$sysroot/lib/$loader" \
        "$sysroot/usr/lib/$loader" \
        "$sysroot/lib64/$loader" \
        "$sysroot/usr/lib64/$loader" || true

    mkdir -p "$root_dir/musl/lib"
    copy_if_exists "$root_dir/lib/libc.so" "$root_dir/musl/lib/libc.so"
    copy_if_exists "$root_dir/lib/$loader" "$root_dir/musl/lib/$loader"
}

if [ -f "$TESTSUITS_ROOT/Makefile.sub" ]; then
    MAKEFILE_SUB_SOURCE="$TESTSUITS_ROOT/Makefile.sub"
else
    MAKEFILE_SUB_SOURCE="$VENDORED_MAKEFILE_SUB"
fi

require_file "$MAKEFILE_SUB_SOURCE"
require_cmd mkfs.ext4
require_cmd truncate

WORK_DIR=$(mktemp -d /tmp/osk-remaining.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

TARGETS=${REMAINING_TARGETS:-"busybox unixbench iperf libcbench lmbench_src cyclictest ltp netperf"}

TOOL_ALIAS_DIR="$WORK_DIR/tool-bin"
mkdir -p "$TOOL_ALIAS_DIR"
PATH="$TOOL_ALIAS_DIR:$PATH"
export PATH

case "$ARCH" in
    rv|riscv|riscv64)
        STAGE_DIR="$WORK_DIR/riscv64-musl"
        ROOT_FS_DIR="$WORK_DIR/root"
        FINAL_DIR="$ROOT_FS_DIR/musl"
        PREFIX="riscv64-buildroot-linux-musl-"
        ensure_toolchain_bin \
            riscv64-linux-musl-cross \
            riscv64-linux-musl-gcc \
            riscv64-linux-musl \
            https://raw.githubusercontent.com/zhouzhouyi-hub/os-contest-image/master/riscv64-linux-musl-cross.tgz
        alias_tool riscv64-buildroot-linux-musl-gcc riscv64-linux-musl-gcc || true
        alias_tool riscv64-buildroot-linux-musl-strip riscv64-linux-musl-strip || true
        alias_tool riscv64-buildroot-linux-musl-ar riscv64-linux-musl-ar || true
        alias_tool riscv64-buildroot-linux-musl-ranlib riscv64-linux-musl-ranlib || true
        alias_tool riscv64-buildroot-linux-musl-nm riscv64-linux-musl-nm || true
        alias_tool riscv64-buildroot-linux-musl-objdump riscv64-linux-musl-objdump || true
        alias_tool riscv64-linux-musl-gcc riscv64-buildroot-linux-musl-gcc || true
        alias_tool riscv64-linux-musl-strip riscv64-buildroot-linux-musl-strip || true
        alias_tool riscv64-linux-musl-ar riscv64-buildroot-linux-musl-ar || true
        alias_tool riscv64-linux-musl-ranlib riscv64-buildroot-linux-musl-ranlib || true
        alias_tool riscv64-linux-musl-nm riscv64-buildroot-linux-musl-nm || true
        alias_tool riscv64-linux-musl-objdump riscv64-buildroot-linux-musl-objdump || true
        if ! command -v "${PREFIX}gcc" >/dev/null 2>&1; then
            echo "missing RISC-V musl compiler: ${PREFIX}gcc" >&2
            exit 1
        fi
        ;;
    la|loongarch|loongarch64)
        STAGE_DIR="$WORK_DIR/loongarch64-musl"
        ROOT_FS_DIR="$WORK_DIR/root"
        FINAL_DIR="$ROOT_FS_DIR/musl"
        PREFIX="loongarch64-linux-musl-"
        if ! command -v loongarch64-linux-musl-gcc >/dev/null 2>&1; then
            ensure_toolchain_bin \
                loongarch64-linux-musl-cross \
                loongarch64-linux-musl-gcc \
                loongarch64-linux-musl \
                https://raw.githubusercontent.com/zhouzhouyi-hub/os-contest-image/master/loongarch64-linux-musl-cross.tgz
        fi
        if ! command -v "${PREFIX}gcc" >/dev/null 2>&1; then
            echo "missing LoongArch musl compiler: ${PREFIX}gcc" >&2
            exit 1
        fi
        ;;
    *)
        echo "unsupported arch: $ARCH" >&2
        exit 2
        ;;
esac

seed_sys_queue_header "${PREFIX}gcc"

mkdir -p "$STAGE_DIR" "$ROOT_FS_DIR" "$FINAL_DIR"

PATCHED_MAKEFILE="$WORK_DIR/Makefile.sub"
PATCHED_IPERF_BUILD="$WORK_DIR/iperf-build.sh"
PATCHED_LMBENCH_MAKEFILE="$WORK_DIR/lmbench_src.Makefile"
PATCHED_LMBENCH_SRC_MAKEFILE="$WORK_DIR/lmbench_src.src.Makefile"
PATCHED_RTTESTS_MAKEFILE="$WORK_DIR/rt-tests.Makefile"
PATCHED_RTTESTS_NUMA_HEADER="$WORK_DIR/numa.h"
PATCHED_RTTESTS_SCHED_SHIM="$WORK_DIR/osk_sched_shim.c"
PATCHED_LTP_BUILD="$WORK_DIR/ltp-build.sh"
PATCHED_BUSYBOX_PREP="$WORK_DIR/prepare-busybox-config.sh"
cat > "$PATCHED_BUSYBOX_PREP" <<'EOF'
#!/bin/sh
set -eu
arch=$1
config=$2
if [ "$arch" != "loongarch64" ]; then
    exit 0
fi
sed -i \
    -e 's/^CONFIG_TC=y/# CONFIG_TC is not set/' \
    -e 's/^CONFIG_FEATURE_TC_INGRESS=y/# CONFIG_FEATURE_TC_INGRESS is not set/' \
    "$config"
EOF
chmod +x "$PATCHED_BUSYBOX_PREP"

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
    printf '%s\n' 'if [ "${CLEAN_REMAINING_BUILD:-0}" = "1" ]; then'
    printf '%s\n' '    make clean'
    printf '%s\n' 'fi'
    printf '%s\n' "if [ ! -f VERSION ]; then printf '%s\n' 'LTP-${LTP_RELEASE}' > VERSION; fi"
    printf '%s\n' 'if [ "${CLEAN_REMAINING_BUILD:-0}" = "1" ] || [ ! -f configure ]; then'
    printf '%s\n' '    make autotools'
    printf '%s\n' 'fi' ''
    printf '%s\n' 'rm -f Version' ''
    printf '%s\n' 'case "$dest" in'
    printf '%s\n' '  *riscv*musl*)'
    printf '%s\n' "    ./configure --prefix=/ltp --host=riscv64-linux-musl CC=riscv64-linux-musl-gcc --with-target-cflags='-march=rv64gc' --without-tirpc"
    printf '%s\n' '    ;;'
    printf '%s\n' '  *riscv*)'
    printf '%s\n' '    ./configure --prefix=/ltp --host=riscv64-linux-gnu CC=riscv64-linux-gnu-gcc --without-tirpc'
    printf '%s\n' '    ;;'
    printf '%s\n' '  *loongarch*musl*)'
    printf '%s\n' '    ./configure --prefix=/ltp --host=loongarch64-linux-musl CC=loongarch64-linux-musl-gcc --without-tirpc'
    printf '%s\n' '    ;;'
    printf '%s\n' '  *)'
    printf '%s\n' '    ./configure --prefix=/ltp --host=loongarch64-linux-gnu CC=loongarch64-linux-gnu-gcc --without-tirpc'
    printf '%s\n' '    ;;'
    printf '%s\n' 'esac' ''
    printf '%s\n' "make -C lib -j $BUILD_JOBS"
    printf '%s\n' "make -C testcases/kernel/syscalls -j $BUILD_JOBS"
    printf '%s\n' 'make -C testcases/kernel/syscalls install DESTDIR="$dest" prefix=/ltp'
    printf '%s\n' 'mkdir -p "$dest/ltp/runtest"'
    printf '%s\n' 'cp runtest/syscalls "$dest/ltp/runtest/syscalls"'
} > "$PATCHED_LTP_BUILD"
chmod +x "$PATCHED_LTP_BUILD"

if target_enabled lmbench_src; then
    require_file "$TESTSUITS_ROOT/lmbench_src/src/Makefile"
    sed \
        -e 's@COMPILE=$(CC) $(CFLAGS) -I/usr/include/tirpc  $(CPPFLAGS) $(LDFLAGS) @COMPILE=$(CC) $(CFLAGS) -I../libtirpc-1.3.6/tirpc -L../libtirpc-1.3.6/src/.libs $(CPPFLAGS) $(LDFLAGS) @' \
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
    -e "s@-I\\./numactl-2\\.0\\.14@-I$WORK_DIR -I./numactl-2.0.14@" \
    -e "/^VPATH\t+= src\\/oslat:/a VPATH\t+= $WORK_DIR" \
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
    -e "s@cp config/busybox-config-\\\$(ARCH) busybox/.config@cp config/busybox-config-\\\$(ARCH) busybox/.config\\n\t$PATCHED_BUSYBOX_PREP \\\$(ARCH) busybox/.config@" \
    -e 's/make -C busybox CC="$(CC) -static" STRIP=$(STRIP) -j$/make -C busybox CC="$(CC) -static" STRIP=$(STRIP) -j $(BUILD_JOBS)/' \
    -e 's/make -C iozone linux CC="$(CC)" -j $/make -C iozone linux CC="$(CC)" -j $(BUILD_JOBS)/' \
    -e 's/make -j 8$/make -j $(BUILD_JOBS)/' \
    -e "s@cd iperf && ./build.sh \$(DESTDIR)@cd iperf; $PATCHED_IPERF_BUILD \$(DESTDIR)@" \
    -e "s@make -C lmbench_src CC=\"\$(CC)\" -j \$(NPROC)@make -C lmbench_src -f $PATCHED_LMBENCH_MAKEFILE CC=\"\$(CC)\" -j \$(NPROC)@" \
    -e "s@make -C rt-tests-2.7 CROSS_COMPILE=\$(PREFIX)@make -C rt-tests-2.7 -f $PATCHED_RTTESTS_MAKEFILE CROSS_COMPILE=\$(PREFIX)@" \
    -e "s@cd \$(LTP_SUITE_DIR) && ./build-oscomp.sh \$(DESTDIR)@cd \$(LTP_SUITE_DIR); $PATCHED_LTP_BUILD \$(DESTDIR)@" \
    -e "s@cd ltp-full-${LTP_RELEASE} && ./build-oscomp.sh \$(DESTDIR)@cd ltp-full-${LTP_RELEASE}; $PATCHED_LTP_BUILD \$(DESTDIR)@" \
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

cp -R "$STAGE_DIR"/. "$FINAL_DIR"/
cp -R "$STAGE_DIR"/. "$ROOT_FS_DIR"/

cp "$TESTSUITS_ROOT/scripts/unixbench/sort.src" "$ROOT_FS_DIR/sort.src"
copy_if_exists "$TESTSUITS_ROOT/scripts/unixbench/sort.src" "$ROOT_FS_DIR/musl/sort.src"
copy_if_exists "$TESTSUITS_ROOT/scripts/unixbench/sort.src" "$ROOT_FS_DIR/glibc/sort.src"

mkdir -p "$ROOT_FS_DIR/ltp/runtest"
cp "$TESTSUITS_ROOT/$LTP_SUITE_DIR/runtest/syscalls" "$ROOT_FS_DIR/ltp/runtest/syscalls"
cat > "$ROOT_FS_DIR/ltp_testcode.sh" <<'EOF'
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

run_ltp_case() {
  local case_name="$1"
  shift
  local log_file="/tmp/.ltp_${case_name}_$$.log"
  local case_pid hb_pid ret
  /busybox rm -f "$log_file"

  kill_case_session() {
    local sig="$1"
    /busybox kill "-$sig" "-$case_pid" 2>/dev/null || /busybox kill "-$sig" "$case_pid" 2>/dev/null
  }

  (cd "$target_dir" && "$@") >"$log_file" 2>&1 &
  case_pid=$!
  (
    while kill -0 "$case_pid" 2>/dev/null; do
      /busybox sleep 30
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
  /busybox cat "$log_file"

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
  /busybox rm -f "$log_file"

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

  echo "RUN LTP CASE $name"
  run_ltp_case "$name" "$@"
done < /ltp/runtest/syscalls
echo "#### OS COMP TEST GROUP END ltp ####"
exit 0
EOF
chmod +x "$ROOT_FS_DIR/ltp_testcode.sh"

case "$ARCH" in
    rv|riscv|riscv64)
        copy_musl_runtime "${PREFIX}gcc" "$ROOT_FS_DIR"
        copy_if_exists /opt/riscv64-linux-musl-cross/riscv64-linux-musl/lib/libc.so \
            "$ROOT_FS_DIR/lib/libc.so"
        copy_if_exists /opt/riscv64-linux-musl-cross/riscv64-linux-musl/lib/ld-musl-riscv64.so.1 \
            "$ROOT_FS_DIR/lib/ld-musl-riscv64.so.1"
        copy_if_exists /opt/riscv64-lp64d--musl--bleeding-edge-2024.02-1/riscv64-buildroot-linux-musl/sysroot/lib/libc.so \
            "$ROOT_FS_DIR/lib/libc.so"
        copy_if_exists /opt/riscv64-lp64d--musl--bleeding-edge-2024.02-1/riscv64-buildroot-linux-musl/sysroot/lib/ld-musl-riscv64.so.1 \
            "$ROOT_FS_DIR/lib/ld-musl-riscv64.so.1"
        ;;
    la|loongarch|loongarch64)
        copy_musl_runtime "${PREFIX}gcc" "$ROOT_FS_DIR"
        copy_if_exists "$TESTSUITS_ROOT/runtime/loongarch/lib64/libc.so" \
            "$ROOT_FS_DIR/lib/libc.so"
        copy_if_exists "$TESTSUITS_ROOT/runtime/loongarch/lib64/ld.so" \
            "$ROOT_FS_DIR/lib/ld-musl-loongarch64.so.1"
        ;;
esac

mkdir -p "$ROOT_FS_DIR/musl/lib"
copy_if_exists "$ROOT_FS_DIR/lib/libc.so" "$ROOT_FS_DIR/musl/lib/libc.so"
copy_if_exists "$ROOT_FS_DIR/lib/ld-musl-riscv64.so.1" "$ROOT_FS_DIR/musl/lib/ld-musl-riscv64.so.1"
copy_if_exists "$ROOT_FS_DIR/lib/ld-musl-loongarch64.so.1" "$ROOT_FS_DIR/musl/lib/ld-musl-loongarch64.so.1"

mkdir -p "$(dirname -- "$OUT")"
rm -f "$OUT"
truncate -s 4096M "$OUT"
mkfs.ext4 -q -F -d "$ROOT_FS_DIR" "$OUT"
