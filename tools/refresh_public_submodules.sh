#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: refresh_public_submodules.sh [--source-root <dir>] [--timeout-seconds <sec>] [--jobs <n>] [--path <submodule-path> ...]
EOF
    exit 2
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SOURCE_ROOT="$ROOT_DIR"
TIMEOUT_SECONDS="${SUBMODULE_UPDATE_TIMEOUT_SECONDS:-300}"
JOBS="${SUBMODULE_UPDATE_JOBS:-4}"
REQUESTED_PATHS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-root)
            [ "$#" -ge 2 ] || usage
            SOURCE_ROOT=$2
            shift 2
            ;;
        --timeout-seconds)
            [ "$#" -ge 2 ] || usage
            TIMEOUT_SECONDS=$2
            shift 2
            ;;
        --jobs)
            [ "$#" -ge 2 ] || usage
            JOBS=$2
            shift 2
            ;;
        --path)
            [ "$#" -ge 2 ] || usage
            REQUESTED_PATHS+=("$2")
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

cd "$SOURCE_ROOT"
export GIT_TERMINAL_PROMPT=0

if [ ! -f .gitmodules ]; then
    echo "no .gitmodules, nothing to refresh"
    exit 0
fi

mapfile -t SUBMODULE_PATHS < <(
    git config --file .gitmodules --get-regexp '^submodule\..*\.path$' | awk '{print $2}'
)

if [ "${#SUBMODULE_PATHS[@]}" -eq 0 ]; then
    echo "no submodule paths found"
    exit 0
fi

if [ "${#REQUESTED_PATHS[@]}" -gt 0 ]; then
    declare -A AVAILABLE_PATHS=()
    for path in "${SUBMODULE_PATHS[@]}"; do
        AVAILABLE_PATHS["$path"]=1
    done
    FILTERED_PATHS=()
    for path in "${REQUESTED_PATHS[@]}"; do
        if [ -z "${AVAILABLE_PATHS[$path]+x}" ]; then
            echo "unknown submodule path: $path" >&2
            exit 2
        fi
        FILTERED_PATHS+=("$path")
    done
    SUBMODULE_PATHS=("${FILTERED_PATHS[@]}")
fi

git submodule sync --recursive

declare -A SEEN_PATHS=()
declare -A NEEDS_REFRESH_REASONS=()
NEEDS_REFRESH=()

mark_needs_refresh() {
    local path=$1
    local reason=$2
    if [ -z "${NEEDS_REFRESH_REASONS[$path]+x}" ]; then
        NEEDS_REFRESH+=("$path")
        NEEDS_REFRESH_REASONS["$path"]=$reason
    fi
}

submodule_worktree_incomplete() {
    local path=$1
    local first_entry=""
    local deleted_entry=""
    [ -d "$path" ] || return 0
    [ -e "$path/.git" ] || return 0
    git -C "$path" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
    first_entry=$(find "$path" -mindepth 1 -maxdepth 1 ! -name .git -print -quit)
    if [ -z "$first_entry" ]; then
        return 0
    fi
    deleted_entry=$(git -C "$path" ls-files --deleted | head -n 1 || true)
    if [ -n "$deleted_entry" ]; then
        return 0
    fi
    return 1
}

while IFS= read -r line; do
    [ -n "$line" ] || continue
    prefix=${line%"${line#?}"}
    rest=${line#?}
    path=${rest#* }
    path=${path%% *}
    SEEN_PATHS["$path"]=1
    if [ "$prefix" != " " ]; then
        mark_needs_refresh "$path" "git-submodule-status:$prefix"
    fi
done < <(git submodule status --recursive || true)

for path in "${SUBMODULE_PATHS[@]}"; do
    if [ -z "${SEEN_PATHS[$path]+x}" ]; then
        mark_needs_refresh "$path" "missing-from-submodule-status"
        continue
    fi
    if submodule_worktree_incomplete "$path"; then
        mark_needs_refresh "$path" "incomplete-worktree"
    fi
done

if [ "${#NEEDS_REFRESH[@]}" -eq 0 ]; then
    echo "submodules already initialized at recorded commits; skipping refresh"
    git submodule status --recursive
    exit 0
fi

run_update() {
    local -a cmd=(git submodule update --init --recursive --force --checkout --jobs "$JOBS")
    if [ "$#" -gt 0 ]; then
        cmd+=(-- "$@")
    fi
    echo "[refresh] updating ${#NEEDS_REFRESH[@]} submodule path(s): ${NEEDS_REFRESH[*]}"
    for path in "$@"; do
        echo "[refresh] reason $path: ${NEEDS_REFRESH_REASONS[$path]}"
    done
    echo "[refresh] timeout=${TIMEOUT_SECONDS}s jobs=$JOBS"
    if command -v timeout >/dev/null 2>&1; then
        timeout --foreground "${TIMEOUT_SECONDS}s" "${cmd[@]}"
    else
        "${cmd[@]}"
    fi
}

if run_update "${NEEDS_REFRESH[@]}"; then
    for path in "${NEEDS_REFRESH[@]}"; do
        if submodule_worktree_incomplete "$path"; then
            echo "submodule still incomplete after refresh: $path" >&2
            exit 1
        fi
    done
    git submodule status --recursive
    exit 0
else
    rc=$?
    if [ "$rc" -eq 124 ]; then
        echo "submodule update timed out after ${TIMEOUT_SECONDS}s" >&2
        exit "$rc"
    fi
fi

echo "initial submodule update failed; retrying with a full cleanup" >&2

for path in "${NEEDS_REFRESH[@]}"; do
    git submodule deinit -f -- "$path" || true
    rm -rf "$path" ".git/modules/$path"
done

run_update "${NEEDS_REFRESH[@]}"
git submodule status --recursive
