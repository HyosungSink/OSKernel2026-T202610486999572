#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


TRACKED = [
    "busybox",
    "busybox_cmd.txt",
    "basic_testcode.sh",
    "libctest_testcode.sh",
    "bin/abort01",
    "bin/accept01",
    "bin/clone03",
    "entry-static.exe",
    "entry-dynamic.exe",
    "cyclictest",
    "hackbench",
    "cyclictest_testcode.sh",
    "ltp_testcode.sh",
    "lua",
    "netperf",
    "netserver",
    "lib/ld-linux-riscv64-lp64d.so.1",
    "lib/libc.so.6",
    "lib/ld-musl-riscv64.so.1",
    "lib64/ld-linux-loongarch-lp64d.so.1",
    "lib64/libc.so.6",
    "lib64/libc.so",
    "lib/ld-musl-loongarch64.so.1",
    "lib64/ld-musl-loongarch-lp64d.so.1",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def tree_summary(root: Path) -> dict[str, int]:
    files = 0
    dirs = 0
    symlinks = 0
    bytes_total = 0
    if not root.exists():
        return {"files": 0, "dirs": 0, "symlinks": 0, "bytes": 0}
    for path in root.rglob("*"):
        try:
            if path.is_symlink():
                symlinks += 1
                continue
            if path.is_dir():
                dirs += 1
                continue
            if path.is_file():
                files += 1
                bytes_total += path.stat().st_size
        except OSError:
            continue
    return {"files": files, "dirs": dirs, "symlinks": symlinks, "bytes": bytes_total}


def tracked_info(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    info: dict[str, object] = {"exists": path.exists() or path.is_symlink()}
    if path.is_symlink():
        info["kind"] = "symlink"
        info["target"] = os.readlink(path)
    elif path.is_file():
        info["kind"] = "file"
        info["bytes"] = path.stat().st_size
        info["sha256"] = sha256(path)
    elif path.is_dir():
        info["kind"] = "dir"
        info.update(tree_summary(path))
    return info


def collect_variant_root(root: Path) -> dict[str, object]:
    manifest: dict[str, object] = {}
    if not root.exists():
        return manifest
    for variant in sorted(path for path in root.iterdir() if path.is_dir()):
        info: dict[str, object] = {
            "summary": tree_summary(variant),
            "top_level": sorted(child.name for child in variant.iterdir()),
            "markers": {},
            "tracked": {},
        }
        markers = info["markers"]
        assert isinstance(markers, dict)
        for marker in [".osk_full_rootfs_ready", ".osk_full_rootfs_targets"]:
            marker_path = variant / marker
            if marker_path.exists():
                markers[marker] = marker_path.read_text(encoding="utf-8", errors="ignore").strip()
        tracked = info["tracked"]
        assert isinstance(tracked, dict)
        for relative in TRACKED:
            tracked[relative] = tracked_info(variant, relative)
        manifest[variant.name] = info
    return manifest


def collect_official_root(root: Path) -> dict[str, object]:
    manifest: dict[str, object] = {}
    if not root.exists():
        return manifest
    for variant in sorted(path for path in root.iterdir() if path.is_dir()):
        info: dict[str, object] = {
            "summary": tree_summary(variant),
            "top_level": sorted(child.name for child in variant.iterdir()),
            "markers": {},
        }
        markers = info["markers"]
        assert isinstance(markers, dict)
        for marker in [".osk_official_rootfs_ready", ".osk_official_cache_key", ".osk_allowed_runtime_groups"]:
            marker_path = variant / marker
            if marker_path.exists():
                markers[marker] = marker_path.read_text(encoding="utf-8", errors="ignore").strip()
        for runtime in ["glibc", "musl"]:
            runtime_root = variant / runtime
            if not runtime_root.exists():
                continue
            runtime_info: dict[str, object] = {
                "summary": tree_summary(runtime_root),
                "top_level": sorted(child.name for child in runtime_root.iterdir()),
                "tracked": {},
            }
            tracked = runtime_info["tracked"]
            assert isinstance(tracked, dict)
            for relative in TRACKED:
                tracked[relative] = tracked_info(runtime_root, relative)
            info[runtime] = runtime_info
        manifest[variant.name] = info
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shared-root", required=True)
    parser.add_argument("--official-root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "shared_rootfs": collect_variant_root(Path(args.shared_root)),
        "official_rootfs": collect_official_root(Path(args.official_root)),
    }
    out_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
