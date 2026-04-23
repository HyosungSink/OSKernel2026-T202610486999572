#!/bin/sh
set -eu

usage() {
    echo "usage: OSK_DIRECT_COMMAND='<cmd>' $0 <rootfs-dir> <output-image> [size-mib]" >&2
    exit 2
}

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    usage
fi

ROOTFS_DIR=$1
OUT=$2
SIZE_MIB=${3:-}
DIRECT_COMMAND=${OSK_DIRECT_COMMAND:-}

[ -d "$ROOTFS_DIR" ] || {
    echo "missing rootfs dir: $ROOTFS_DIR" >&2
    exit 1
}

if [ -z "$SIZE_MIB" ]; then
    used_kib=$(du -sk "$ROOTFS_DIR" | awk '{print $1}')
    SIZE_MIB=$(( (used_kib + 1023) / 1024 + 64 ))
    if [ "$SIZE_MIB" -lt 128 ]; then
        SIZE_MIB=128
    fi
fi

TMP_PARENT=${TMPDIR:-/tmp}
WORK_DIR=$(mktemp -d "$TMP_PARENT/osk-rootfs-img.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

STAGE_DIR="$WORK_DIR/root"
if ! cp -al "$ROOTFS_DIR" "$STAGE_DIR" 2>/dev/null; then
    rm -rf "$STAGE_DIR"
    cp -a "$ROOTFS_DIR" "$STAGE_DIR"
fi

if [ -n "$DIRECT_COMMAND" ]; then
    printf '%s\n' "$DIRECT_COMMAND" > "$STAGE_DIR/.__osk_direct_run__"
fi

mkdir -p "$(dirname -- "$OUT")"
rm -f "$OUT"
truncate -s "${SIZE_MIB}M" "$OUT"
mkfs.ext4 -q -F -d "$STAGE_DIR" "$OUT"
