#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: prepare_official_submission_view.sh --out <dir> [--source-root <dir>] [--trusted-tools-root <dir>] [--stateful-subset "<samples>"] [--submodule-remote-timeout <sec>] [--skip-remote-check]
EOF
    exit 2
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SOURCE_ROOT="$ROOT_DIR"
TRUSTED_TOOLS_ROOT=""
OUT_DIR=""
STATEFUL_SUBSET=""
SUBMODULE_REMOTE_TIMEOUT=30
CHECK_REMOTE=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --out)
            [ "$#" -ge 2 ] || usage
            OUT_DIR=$2
            shift 2
            ;;
        --source-root)
            [ "$#" -ge 2 ] || usage
            SOURCE_ROOT=$2
            shift 2
            ;;
        --trusted-tools-root)
            [ "$#" -ge 2 ] || usage
            TRUSTED_TOOLS_ROOT=$2
            shift 2
            ;;
        --stateful-subset)
            [ "$#" -ge 2 ] || usage
            STATEFUL_SUBSET=$2
            shift 2
            ;;
        --submodule-remote-timeout)
            [ "$#" -ge 2 ] || usage
            SUBMODULE_REMOTE_TIMEOUT=$2
            shift 2
            ;;
        --skip-remote-check)
            CHECK_REMOTE=0
            shift
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$OUT_DIR" ] || usage

mkdir -p "$(dirname -- "$OUT_DIR")"
AUDIT_JSON="$OUT_DIR.submodule-audit.json"
audit_args=(python3 "$SCRIPT_DIR/github_official_repro.py" audit-submodules
    --source-root "$SOURCE_ROOT" \
    --remote-timeout "$SUBMODULE_REMOTE_TIMEOUT" \
    --out "$AUDIT_JSON")
if [ "$CHECK_REMOTE" -eq 1 ]; then
    audit_args+=(--check-remote)
fi
"${audit_args[@]}"
python3 "$SCRIPT_DIR/github_official_repro.py" prepare-submission \
    --source-root "$SOURCE_ROOT" \
    --out "$OUT_DIR"
if [ -n "$TRUSTED_TOOLS_ROOT" ]; then
    [ -d "$TRUSTED_TOOLS_ROOT/tools" ] || {
        echo "trusted tools root missing tools/: $TRUSTED_TOOLS_ROOT" >&2
        exit 1
    }
    rm -rf "$OUT_DIR/tools"
    cp -a "$TRUSTED_TOOLS_ROOT/tools" "$OUT_DIR/tools"
    find "$OUT_DIR/tools" -type d -name __pycache__ -prune -exec rm -rf {} +
    python3 "$SCRIPT_DIR/github_official_repro.py" hash-tree \
        --root "$OUT_DIR" \
        --payload-only \
        --out "$OUT_DIR/submission-view.payload.json"
    {
        printf 'trusted_tools_root=%s\n' "$TRUSTED_TOOLS_ROOT"
        git -C "$TRUSTED_TOOLS_ROOT" rev-parse HEAD 2>/dev/null | sed 's/^/trusted_tools_rev=/'
    } > "$OUT_DIR/trusted-tools.txt"
fi
cp "$AUDIT_JSON" "$OUT_DIR/submodule-audit.json"
if [ -n "$STATEFUL_SUBSET" ]; then
    printf '%s\n' "$STATEFUL_SUBSET" > "$OUT_DIR/stateful-subset.txt"
fi
du -sh "$OUT_DIR"
