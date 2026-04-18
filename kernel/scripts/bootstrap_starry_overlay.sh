#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
KERNEL_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
WORK_ROOT=${WORK_ROOT:-$KERNEL_DIR/work}
WORK_TREE=${WORK_TREE:-$KERNEL_DIR/starry-next}
LOCK_FILE=${LOCK_FILE:-$KERNEL_DIR/overlay/upstream.lock}
PATCH_FILE=${PATCH_FILE:-$KERNEL_DIR/overlay/starry-next-local.patch}
STAMP_FILE=${STAMP_FILE:-$WORK_ROOT/patched.lock}
CARGO_CONFIG_TEMPLATE=${CARGO_CONFIG_TEMPLATE:-$WORK_TREE/cargo-config/config.toml}
CARGO_CONFIG_DIR=${CARGO_CONFIG_DIR:-$WORK_TREE/.cargo}
CARGO_CONFIG_FILE=${CARGO_CONFIG_FILE:-$CARGO_CONFIG_DIR/config.toml}

prepend_path_if_dir() {
  if [ -d "$1" ]; then
    PATH="$1:$PATH"
  fi
}

prepend_path_if_dir /opt/riscv64-linux-musl-cross/bin
prepend_path_if_dir /opt/loongarch64-linux-musl-cross/bin
prepend_path_if_dir "${XDG_CACHE_HOME:-$HOME/.cache}/osk-toolchains/riscv64-linux-musl-cross/bin"
prepend_path_if_dir "${XDG_CACHE_HOME:-$HOME/.cache}/osk-toolchains/loongarch64-linux-musl-cross/bin"
export PATH

mkdir -p "$WORK_ROOT"
# shellcheck disable=SC1090
source "$LOCK_FILE"

if [ ! -f "$WORK_TREE/Makefile" ]; then
  echo "vendored work tree is missing: $WORK_TREE" >&2
  exit 1
fi

if [ ! -f "$CARGO_CONFIG_TEMPLATE" ]; then
  echo "cargo config template is missing: $CARGO_CONFIG_TEMPLATE" >&2
  exit 1
fi

if [ -d "$WORK_TREE/.git" ]; then
  current_commit=$(git -C "$WORK_TREE" rev-parse HEAD 2>/dev/null || true)
  if [ -n "$current_commit" ] && [ "$current_commit" != "$commit" ]; then
    echo "warning: vendored work tree HEAD $current_commit differs from lock $commit; using vendored tree as-is" >&2
  fi
fi

mkdir -p "$CARGO_CONFIG_DIR"
cp "$CARGO_CONFIG_TEMPLATE" "$CARGO_CONFIG_FILE"

printf '%s\n' "${current_commit:-$commit}" > "$STAMP_FILE"
