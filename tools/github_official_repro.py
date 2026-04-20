#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUP_ORDER = [
    "basic",
    "busybox",
    "cyclictest",
    "iozone",
    "iperf",
    "libcbench",
    "libctest",
    "lmbench",
    "ltp",
    "lua",
    "netperf",
]
DEFAULT_EXCLUDES = [
    "logs",
    "dev/full-suite",
    "dev/logs",
    "kernel/build",
    "kernel/work",
    "kernel/.work",
    "kernel/starry-next/target",
    "kernel/starry-next/arceos/target",
    "tools/__pycache__",
]
GENERATED_SUBMISSION_FILES = {
    "submission-view.included.txt",
    "submission-view.skipped-hidden.txt",
    "submission-view.skipped-excluded.txt",
    "submission-view.skipped-non-file.txt",
    "submission-view.manifest.json",
    "submission-view.payload.json",
    "stateful-subset.txt",
    "submodule-audit.json",
}


@dataclass(frozen=True)
class Sample:
    group: str
    runtime: str
    arch: str

    @property
    def name(self) -> str:
        return f"{self.group}-{self.runtime}-{self.arch}"


def repo_root(source_root: str | None = None) -> Path:
    if source_root is None:
        return ROOT
    return Path(source_root).resolve()


def run_git(args: list[str], *, cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout


def run_git_optional(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def parse_sample(name: str) -> Sample:
    parts = name.split("-")
    if len(parts) != 3:
        raise ValueError(f"invalid sample name: {name}")
    group, runtime, arch = parts
    if group not in GROUP_ORDER:
        raise ValueError(f"unknown group in sample: {name}")
    if runtime not in {"glibc", "musl"}:
        raise ValueError(f"unknown runtime in sample: {name}")
    if arch not in {"rv", "la"}:
        raise ValueError(f"unknown arch in sample: {name}")
    return Sample(group=group, runtime=runtime, arch=arch)


def iter_path_chunks(raw_chunks: list[str]) -> list[str]:
    parts: list[str] = []
    for chunk in raw_chunks:
        for piece in chunk.replace(",", " ").split():
            piece = piece.strip()
            if piece:
                parts.append(piece)
    return parts


def is_hidden_path(rel_path: str) -> bool:
    return any(part.startswith(".") for part in Path(rel_path).parts)


def is_excluded_path(rel_path: str, excludes: list[str]) -> bool:
    rel = Path(rel_path)
    for raw in excludes:
        path = Path(raw)
        if rel == path or path in rel.parents:
            return True
    return False


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def copy_tracked_path(src_root: Path, dst_root: Path, rel_path: str) -> None:
    src = src_root / rel_path
    dst = dst_root / rel_path
    ensure_parent(dst)
    if src.is_symlink():
        target = os.readlink(src)
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        os.symlink(target, dst)
        return
    shutil.copy2(src, dst)
    mode = src.stat().st_mode
    if mode & stat.S_IXUSR:
        dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def relative_payload_hashes(root_dir: Path, *, payload_only: bool) -> dict[str, dict[str, object]]:
    mapping: dict[str, dict[str, object]] = {}
    for path in sorted(root_dir.rglob("*")):
        if path.is_dir():
            continue
        rel_path = path.relative_to(root_dir).as_posix()
        if payload_only and rel_path in GENERATED_SUBMISSION_FILES:
            continue
        if path.is_symlink():
            mapping[rel_path] = {"kind": "symlink", "target": os.readlink(path)}
            continue
        mode = path.stat().st_mode
        mapping[rel_path] = {
            "kind": "file",
            "sha256": sha256_file(path),
            "executable": bool(mode & stat.S_IXUSR),
        }
    return mapping


def command_prepare_submission(args: argparse.Namespace) -> int:
    src_root = repo_root(args.source_root)
    out_dir = Path(args.out).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    excludes = DEFAULT_EXCLUDES + args.exclude
    tracked = run_git(["ls-files", "-z", "--cached", "--recurse-submodules"], cwd=src_root).split("\0")
    included: list[str] = []
    skipped_hidden: list[str] = []
    skipped_excluded: list[str] = []
    skipped_non_file: list[str] = []

    for rel_path in tracked:
        if not rel_path:
            continue
        src = src_root / rel_path
        if src.is_dir() and not src.is_symlink():
            skipped_non_file.append(rel_path)
            continue
        if is_hidden_path(rel_path):
            skipped_hidden.append(rel_path)
            continue
        if is_excluded_path(rel_path, excludes):
            skipped_excluded.append(rel_path)
            continue
        copy_tracked_path(src_root, out_dir, rel_path)
        included.append(rel_path)

    payload = relative_payload_hashes(out_dir, payload_only=True)

    manifest = {
        "source_root": str(src_root),
        "output_root": str(out_dir),
        "included_count": len(included),
        "skipped_hidden_count": len(skipped_hidden),
        "skipped_excluded_count": len(skipped_excluded),
        "skipped_non_file_count": len(skipped_non_file),
        "excludes": excludes,
    }
    (out_dir / "submission-view.included.txt").write_text("\n".join(included) + "\n", encoding="utf-8")
    (out_dir / "submission-view.skipped-hidden.txt").write_text(
        "\n".join(skipped_hidden) + ("\n" if skipped_hidden else ""),
        encoding="utf-8",
    )
    (out_dir / "submission-view.skipped-excluded.txt").write_text(
        "\n".join(skipped_excluded) + ("\n" if skipped_excluded else ""),
        encoding="utf-8",
    )
    (out_dir / "submission-view.skipped-non-file.txt").write_text(
        "\n".join(skipped_non_file) + ("\n" if skipped_non_file else ""),
        encoding="utf-8",
    )
    (out_dir / "submission-view.manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (out_dir / "submission-view.payload.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False))
    return 0


def command_expand_subset(args: argparse.Namespace) -> int:
    sample_names = iter_path_chunks(args.target_sample)
    if not sample_names:
        raise SystemExit("at least one --target-sample value is required")

    expanded: list[str] = []
    seen: set[str] = set()
    for sample_name in sample_names:
        sample = parse_sample(sample_name)
        if args.include_prefix_groups:
            stop = GROUP_ORDER.index(sample.group)
            for group in GROUP_ORDER[: stop + 1]:
                name = Sample(group=group, runtime=sample.runtime, arch=sample.arch).name
                if name not in seen:
                    seen.add(name)
                    expanded.append(name)
        else:
            if sample.name not in seen:
                seen.add(sample.name)
                expanded.append(sample.name)

    print(" ".join(expanded))
    return 0


def command_hash_tree(args: argparse.Namespace) -> int:
    root_dir = Path(args.root).resolve()
    payload = relative_payload_hashes(root_dir, payload_only=args.payload_only)
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).resolve().write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


def command_compare_tree_hash(args: argparse.Namespace) -> int:
    left = json.loads(Path(args.left).read_text(encoding="utf-8"))
    right = json.loads(Path(args.right).read_text(encoding="utf-8"))
    if left == right:
        print(json.dumps({"equal": True, "entries": len(left)}, ensure_ascii=False))
        return 0

    left_keys = set(left)
    right_keys = set(right)
    only_left = sorted(left_keys - right_keys)
    only_right = sorted(right_keys - left_keys)
    different = sorted(key for key in left_keys & right_keys if left[key] != right[key])
    summary = {
        "equal": False,
        "left_entries": len(left),
        "right_entries": len(right),
        "only_left": only_left[:20],
        "only_right": only_right[:20],
        "different": different[:20],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 1


def command_pack_submission(args: argparse.Namespace) -> int:
    root_dir = Path(args.root).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tar = shutil.which("tar")
    if tar is not None:
        subprocess.run(
            [tar, "-I", "gzip -1", "-cf", str(out_path), "-C", str(root_dir.parent), root_dir.name],
            check=True,
        )
    else:
        with tarfile.open(out_path, "w:gz", compresslevel=1) as archive:
            archive.add(root_dir, arcname=root_dir.name)
    print(json.dumps({"archive": str(out_path), "root": str(root_dir)}, ensure_ascii=False))
    return 0


def gitmodules_entries(source_root: Path) -> list[dict[str, str]]:
    gitmodules = source_root / ".gitmodules"
    if not gitmodules.exists():
        return []
    proc = run_git_optional(
        ["config", "--file", str(gitmodules), "--get-regexp", r"^submodule\..*\.(path|url)$"],
        cwd=source_root,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or "failed to parse .gitmodules")

    entries_by_name: dict[str, dict[str, str]] = {}
    pattern = re.compile(r"^submodule\.(.+)\.(path|url)$")
    for raw_line in proc.stdout.splitlines():
        key, _, value = raw_line.partition(" ")
        match = pattern.match(key)
        if not match:
            continue
        name, field = match.groups()
        entry = entries_by_name.setdefault(name, {"name": name})
        entry[field] = value.strip()
    return list(entries_by_name.values())


def submodule_url_is_public(url: str) -> tuple[bool, str]:
    lowered = url.lower()
    if lowered.startswith("git@") or lowered.startswith("ssh://"):
        return False, "ssh submodule URLs are not accepted by official reproduction"
    if re.match(r"^[a-z][a-z0-9+.-]*://[^/@]+@", lowered):
        return False, "submodule URL contains embedded credentials"
    if lowered.startswith("http://") or lowered.startswith("https://") or lowered.startswith("git://"):
        return True, "public-url-syntax"
    if lowered.startswith("../") or lowered.startswith("./") or lowered.startswith("/"):
        return False, "relative/local submodule URLs cannot be proven public"
    return False, "unsupported submodule URL scheme"


def command_audit_submodules(args: argparse.Namespace) -> int:
    source_root = repo_root(args.source_root)
    entries = gitmodules_entries(source_root)
    results: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []

    for entry in entries:
        url = entry.get("url", "")
        path = entry.get("path", "")
        ok, reason = submodule_url_is_public(url)
        result: dict[str, object] = {
            "name": entry.get("name", ""),
            "path": path,
            "url": url,
            "public_url": ok,
            "reason": reason,
        }
        if ok and args.check_remote:
            try:
                proc = subprocess.run(
                    ["git", "ls-remote", "--exit-code", url, "HEAD"],
                    cwd=source_root,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=args.remote_timeout,
                )
                remote_ok = proc.returncode == 0
                result["remote_publicly_readable"] = remote_ok
                if not remote_ok:
                    result["reason"] = "unauthenticated git ls-remote failed"
                    result["stderr"] = proc.stderr.strip()[-500:]
                    ok = False
            except subprocess.TimeoutExpired:
                result["remote_publicly_readable"] = False
                result["reason"] = f"unauthenticated git ls-remote timed out after {args.remote_timeout}s"
                ok = False
        if not ok:
            failures.append(result)
        results.append(result)

    summary = {
        "source_root": str(source_root),
        "submodule_count": len(entries),
        "failures": failures,
        "results": results,
    }
    rendered = json.dumps(summary, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        out_path = Path(args.out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Helpers for GitHub official-style reproduction CI.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare-submission", help="Create a sanitized submission view from tracked files.")
    prepare.add_argument("--out", required=True, help="Output directory for the sanitized submission tree.")
    prepare.add_argument(
        "--source-root",
        help="Source repository root. Defaults to the repository containing this script.",
    )
    prepare.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Additional repo-relative directory to exclude from the submission view.",
    )
    prepare.set_defaults(func=command_prepare_submission)

    expand = subparsers.add_parser("expand-subset", help="Expand target samples to official prefix subsets.")
    expand.add_argument(
        "--target-sample",
        action="append",
        default=[],
        help="Target sample name(s); may be repeated or contain comma/space separated values.",
    )
    expand.add_argument(
        "--include-prefix-groups",
        action="store_true",
        help="Expand each target sample to all groups up to and including the target group for the same runtime/arch.",
    )
    expand.set_defaults(func=command_expand_subset)

    hash_tree = subparsers.add_parser("hash-tree", help="Hash a directory tree for submission transport validation.")
    hash_tree.add_argument("--root", required=True, help="Root directory to hash.")
    hash_tree.add_argument("--out", help="Optional JSON output path.")
    hash_tree.add_argument(
        "--payload-only",
        action="store_true",
        help="Ignore generated submission metadata files and hash payload files only.",
    )
    hash_tree.set_defaults(func=command_hash_tree)

    compare = subparsers.add_parser("compare-tree-hash", help="Compare two tree hash JSON files.")
    compare.add_argument("--left", required=True, help="Left JSON path.")
    compare.add_argument("--right", required=True, help="Right JSON path.")
    compare.set_defaults(func=command_compare_tree_hash)

    pack = subparsers.add_parser("pack-submission", help="Create a tar.gz archive of a prepared submission view.")
    pack.add_argument("--root", required=True, help="Submission view root directory.")
    pack.add_argument("--out", required=True, help="Output tar.gz path.")
    pack.set_defaults(func=command_pack_submission)

    audit = subparsers.add_parser(
        "audit-submodules",
        help="Fail if .gitmodules contains private or non-public submodule URLs.",
    )
    audit.add_argument(
        "--source-root",
        help="Source repository root. Defaults to the repository containing this script.",
    )
    audit.add_argument("--out", help="Optional JSON output path.")
    audit.add_argument(
        "--check-remote",
        action="store_true",
        help="Run unauthenticated git ls-remote against each public-looking submodule URL.",
    )
    audit.add_argument(
        "--remote-timeout",
        type=int,
        default=30,
        help="Per-submodule ls-remote timeout in seconds.",
    )
    audit.set_defaults(func=command_audit_submodules)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
