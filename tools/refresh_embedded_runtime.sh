#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TESTSUITS_ROOT=${TESTSUITS_ROOT:-$ROOT_DIR/testsuits-for-oskernel-pre-2025}
REFRESH_ROOT=$ROOT_DIR/kernel/starry-next/embedded-runtime-refresh
WORK_ROOT=${EMBEDDED_RUNTIME_WORK_ROOT:-$ROOT_DIR/dev/embedded-runtime-refresh-build}
TARGETS=${EMBEDDED_RUNTIME_TARGETS:-"basic busybox libc-test cyclictest"}
STAMP_FILE=$REFRESH_ROOT/.osk_refresh_stamp
VENDORED_MAKEFILE_SUB=${VENDORED_MAKEFILE_SUB:-$ROOT_DIR/tools/vendor/Makefile.sub}

hash_text() {
    sha256sum | awk '{print $1}'
}

git_state_token() {
    repo=$1
    if command -v git >/dev/null 2>&1 && [ -d "$repo/.git" -o -f "$repo/.git" ]; then
        head=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)
        if git -C "$repo" rev-parse --verify HEAD >/dev/null 2>&1; then
            dirty=$(git -C "$repo" diff --no-ext-diff --binary HEAD -- 2>/dev/null | hash_text)
        else
            dirty=$(
                {
                    git -C "$repo" diff --no-ext-diff --binary --cached -- 2>/dev/null || true
                    git -C "$repo" diff --no-ext-diff --binary -- 2>/dev/null || true
                } | hash_text
            )
        fi
        printf '%s:%s' "$head" "$dirty"
    else
        printf 'nogit:%s' "$(find "$repo" -maxdepth 2 -type f 2>/dev/null | sort | hash_text)"
    fi
}

compute_stamp() {
    {
        printf 'root=%s\n' "$(git_state_token "$ROOT_DIR")"
        printf 'testsuits=%s\n' "$(git_state_token "$TESTSUITS_ROOT")"
        printf 'targets=%s\n' "$TARGETS"
        printf 'build_full_rootfs=%s\n' "$(sha256sum "$ROOT_DIR/tools/build_full_rootfs.sh" | awk '{print $1}')"
        printf 'build_rs=%s\n' "$(sha256sum "$ROOT_DIR/kernel/starry-next/build.rs" | awk '{print $1}')"
        if [ -f "$VENDORED_MAKEFILE_SUB" ]; then
            printf 'vendored_makefile_sub=%s\n' "$(sha256sum "$VENDORED_MAKEFILE_SUB" | awk '{print $1}')"
        else
            printf 'vendored_makefile_sub=missing\n'
        fi
    } | hash_text
}

copy_required() {
    src=$1
    dst=$2
    if [ ! -f "$src" ]; then
        echo "missing generated refresh file: $src" >&2
        exit 1
    fi
    mkdir -p "$(dirname -- "$dst")"
    cp -a "$src" "$dst"
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

source_tree_ready() {
    [ -f "$TESTSUITS_ROOT/Makefile.sub" ] || [ -f "$VENDORED_MAKEFILE_SUB" ] || return 1

    if target_enabled basic; then
        [ -d "$TESTSUITS_ROOT/basic/user" ] || return 1
        [ -f "$TESTSUITS_ROOT/scripts/basic/basic_testcode.sh" ] || return 1
    fi
    if target_enabled busybox; then
        [ -f "$TESTSUITS_ROOT/busybox/Makefile" ] || return 1
        [ -f "$TESTSUITS_ROOT/config/busybox-config-riscv64" ] || return 1
        [ -f "$TESTSUITS_ROOT/config/busybox-config-loongarch64" ] || return 1
        [ -f "$TESTSUITS_ROOT/scripts/busybox/busybox_testcode.sh" ] || return 1
    fi
    if target_enabled libc-test; then
        [ -f "$TESTSUITS_ROOT/libc-test/Makefile" ] || return 1
        [ -f "$TESTSUITS_ROOT/scripts/libctest/libctest_testcode.sh" ] || return 1
    fi
    if target_enabled cyclictest; then
        [ -f "$TESTSUITS_ROOT/rt-tests-2.7/Makefile" ] || return 1
        [ -f "$TESTSUITS_ROOT/scripts/cyclictest/cyclictest_testcode.sh" ] || return 1
    fi
    if target_enabled iperf; then
        [ -f "$TESTSUITS_ROOT/iperf/build.sh" ] || return 1
        [ -f "$TESTSUITS_ROOT/scripts/iperf/iperf_testcode.sh" ] || return 1
    fi
    if target_enabled lmbench_src; then
        [ -f "$TESTSUITS_ROOT/lmbench_src/Makefile" ] || return 1
        [ -f "$TESTSUITS_ROOT/lmbench_src/src/Makefile" ] || return 1
        [ -f "$TESTSUITS_ROOT/scripts/lmbench/lmbench_testcode.sh" ] || return 1
    fi

    return 0
}

wrap_group_script() {
    runtime=$1
    group=$2
    script_path=$3

    raw_path=$(dirname -- "$script_path")/.$(basename -- "$script_path").raw
    tmp_body=$(mktemp)
    awk '
        index($0, "#### OS COMP TEST GROUP START ") == 0 &&
        index($0, "#### OS COMP TEST GROUP END ") == 0
    ' "$script_path" > "$tmp_body"
    mv "$tmp_body" "$raw_path"
    cat > "$script_path" <<EOF
#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START ${group}-${runtime} ####"
./busybox sh /${runtime}/.$(basename -- "$script_path").raw
status=\$?
./busybox echo "#### OS COMP TEST GROUP END ${group}-${runtime} ####"
exit \$status
EOF
    chmod 755 "$script_path" "$raw_path"
}

sync_runtime_subset() {
    arch=$1
    runtime=$2
    src_root=$3
    dst_root=$4

    mkdir -p "$dst_root"
    rm -rf "$dst_root/basic"
    cp -a "$src_root/basic" "$dst_root/basic"

    for rel in \
        basic_testcode.sh \
        busybox \
        busybox_cmd.txt \
        busybox_testcode.sh \
        libctest_testcode.sh \
        entry-static.exe \
        entry-dynamic.exe \
        cyclictest_testcode.sh \
        cyclictest \
        hackbench
    do
        copy_required "$src_root/$rel" "$dst_root/$rel"
    done

    if [ "$arch" = "rv" ] && [ "$runtime" = "glibc" ]; then
        copy_required "$src_root/lib/ld-linux-riscv64-lp64d.so.1" \
            "$dst_root/lib/ld-linux-riscv64-lp64d.so.1"
        copy_required "$src_root/lib/libc.so.6" "$dst_root/lib/libc.so.6"
    fi

    wrap_group_script "$runtime" basic "$dst_root/basic_testcode.sh"
    wrap_group_script "$runtime" busybox "$dst_root/busybox_testcode.sh"
    wrap_group_script "$runtime" libctest "$dst_root/libctest_testcode.sh"
    wrap_group_script "$runtime" cyclictest "$dst_root/cyclictest_testcode.sh"
}

cached_rootfs_ready() {
    root=$1
    [ -f "$root/.osk_full_rootfs_ready" ] || return 1
    [ -d "$root/basic" ] || return 1
    [ -f "$root/basic_testcode.sh" ] || return 1
    [ -f "$root/busybox" ] || return 1
    [ -f "$root/busybox_testcode.sh" ] || return 1
    [ -f "$root/libctest_testcode.sh" ] || return 1
    [ -f "$root/entry-static.exe" ] || return 1
    [ -f "$root/entry-dynamic.exe" ] || return 1
    [ -f "$root/cyclictest_testcode.sh" ] || return 1
    [ -f "$root/cyclictest" ] || return 1
    [ -f "$root/hackbench" ] || return 1
}

embedded_runtime_cache_ready() {
    [ -d "$REFRESH_ROOT/rv/glibc/basic" ] || return 1
    [ -d "$REFRESH_ROOT/rv/musl/basic" ] || return 1
    [ -d "$REFRESH_ROOT/la/glibc/basic" ] || return 1
    [ -d "$REFRESH_ROOT/la/musl/basic" ] || return 1
    [ -f "$REFRESH_ROOT/rv/glibc/lib/ld-linux-riscv64-lp64d.so.1" ] || return 1
    [ -f "$REFRESH_ROOT/rv/glibc/lib/libc.so.6" ] || return 1
    [ -f "$REFRESH_ROOT/rv/glibc/cyclictest" ] || return 1
    [ -f "$REFRESH_ROOT/rv/glibc/hackbench" ] || return 1
    [ -f "$REFRESH_ROOT/la/glibc/cyclictest" ] || return 1
    [ -f "$REFRESH_ROOT/la/glibc/hackbench" ] || return 1
}

if [ "${OSK_USE_VENDORED_EMBEDDED_RUNTIME:-0}" = "1" ]; then
    if embedded_runtime_cache_ready; then
        echo "refresh_embedded_runtime: using vendored $REFRESH_ROOT because OSK_USE_VENDORED_EMBEDDED_RUNTIME=1" >&2
        exit 0
    fi
    echo "refresh_embedded_runtime: OSK_USE_VENDORED_EMBEDDED_RUNTIME=1 but vendored $REFRESH_ROOT is incomplete" >&2
    exit 1
fi

prepare_runtime_root() {
    arch=$1
    runtime=$2
    out_dir=$3

    cached_dir=$ROOT_DIR/dev/full-suite/rootfs/$arch-$runtime
    if cached_rootfs_ready "$cached_dir"; then
        printf '%s\n' "$cached_dir"
        return 0
    fi

    FULL_SUITE_TARGETS="$TARGETS" "$ROOT_DIR/tools/build_full_rootfs.sh" "$arch" "$runtime" "$out_dir" >&2
    printf '%s\n' "$out_dir"
}

STAMP=$(compute_stamp)
if [ ! -f "$TESTSUITS_ROOT/Makefile.sub" ] && [ ! -f "$VENDORED_MAKEFILE_SUB" ]; then
    if embedded_runtime_cache_ready; then
        echo "refresh_embedded_runtime: missing both $TESTSUITS_ROOT/Makefile.sub and $VENDORED_MAKEFILE_SUB, reusing cached $REFRESH_ROOT" >&2
        exit 0
    fi
    echo "refresh_embedded_runtime: missing both $TESTSUITS_ROOT/Makefile.sub and $VENDORED_MAKEFILE_SUB, skip refresh and rely on vendored runtime assets" >&2
    exit 0
fi

if ! source_tree_ready; then
    if embedded_runtime_cache_ready; then
        echo "refresh_embedded_runtime: incomplete $TESTSUITS_ROOT, reusing cached $REFRESH_ROOT" >&2
        exit 0
    fi
    echo "refresh_embedded_runtime: incomplete $TESTSUITS_ROOT and no complete cached $REFRESH_ROOT, skip refresh and rely on vendored runtime assets" >&2
    exit 0
fi

if [ -f "$STAMP_FILE" ] && [ "$(cat "$STAMP_FILE" 2>/dev/null || true)" = "$STAMP" ]; then
    exit 0
fi

TMP_ROOT="$REFRESH_ROOT.tmp"
BUILD_ROOT="$WORK_ROOT/rootfs"
rm -rf "$TMP_ROOT"
mkdir -p "$TMP_ROOT" "$BUILD_ROOT"

for arch in rv la; do
    for runtime in glibc musl; do
        out_dir="$BUILD_ROOT/$arch-$runtime"
        src_root=$(prepare_runtime_root "$arch" "$runtime" "$out_dir")
        sync_runtime_subset "$arch" "$runtime" "$src_root" "$TMP_ROOT/$arch/$runtime"
    done
done

printf '%s\n' "$STAMP" > "$TMP_ROOT/.osk_refresh_stamp"
rm -rf "$REFRESH_ROOT"
mv "$TMP_ROOT" "$REFRESH_ROOT"
