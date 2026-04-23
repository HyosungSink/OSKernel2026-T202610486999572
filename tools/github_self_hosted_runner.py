#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


DEFAULT_REQUIRED_COMMANDS = [
    "docker",
    "git",
    "python3",
    "tar",
]

DEFAULT_INSPECT_COMMANDS = [
    *DEFAULT_REQUIRED_COMMANDS,
    "mkfs.ext4",
    "truncate",
    "qemu-system-riscv64",
    "qemu-system-loongarch64",
]


def bytes_to_gib(value: int) -> float:
    return round(value / (1024**3), 2)


def command_version(command: str) -> str:
    proc = subprocess.run(
        [command, "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    text = (proc.stdout or proc.stderr).strip()
    return text.splitlines()[0] if text else ""


def command_path(command: str) -> str | None:
    resolved = shutil.which(command)
    return resolved if resolved is not None else None


def docker_info() -> dict[str, object]:
    proc = subprocess.run(
        ["docker", "info", "--format", "{{json .}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "docker info failed")
    data = json.loads(proc.stdout)
    return {
        "root_dir": data.get("DockerRootDir"),
        "driver": data.get("Driver"),
        "server_version": data.get("ServerVersion"),
    }


def disk_usage(path: Path) -> dict[str, object]:
    if not path.exists():
        return {
            "path": str(path),
            "exists": False,
            "note": "path is not visible from this runner environment",
        }
    usage = shutil.disk_usage(path)
    return {
        "path": str(path),
        "exists": True,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "total_gib": bytes_to_gib(usage.total),
        "used_gib": bytes_to_gib(usage.used),
        "free_gib": bytes_to_gib(usage.free),
    }


def parse_command_values(values: list[str] | None, defaults: list[str]) -> list[str]:
    commands: list[str] = []
    for value in values or []:
        for command in value.replace(",", " ").split():
            if command and command not in commands:
                commands.append(command)
    if not commands:
        commands = list(defaults)
    return commands


def merge_command_values(*command_lists: list[str]) -> list[str]:
    merged: list[str] = []
    for command_list in command_lists:
        for command in command_list:
            if command not in merged:
                merged.append(command)
    return merged


def command_preflight(args: argparse.Namespace) -> int:
    required_commands = parse_command_values(args.required_command, DEFAULT_REQUIRED_COMMANDS)
    extra_inspect_commands = parse_command_values(args.inspect_command, [])
    inspected_commands = merge_command_values(
        required_commands,
        DEFAULT_INSPECT_COMMANDS,
        extra_inspect_commands,
    )
    command_paths = {command: command_path(command) for command in inspected_commands}
    missing_commands = [command for command in required_commands if command_paths.get(command) is None]
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "/tmp")).resolve()
    cache_root = Path(args.cache_root).resolve() if args.cache_root else None

    failures: list[str] = []
    warnings: list[str] = []
    docker: dict[str, object]
    docker_root: Path | None = None
    if command_paths.get("docker") is None:
        docker = {"error": "docker command not found"}
    else:
        try:
            docker = docker_info()
            docker_root_value = docker.get("root_dir")
            if docker_root_value:
                docker_root = Path(str(docker_root_value)).resolve()
        except RuntimeError as exc:
            docker = {"error": str(exc)}
            failures.append(f"docker info failed: {exc}")
    checks = {
        "workspace": disk_usage(workspace),
        "runner_temp": disk_usage(runner_temp),
    }
    if cache_root is not None:
        checks["cache_root"] = disk_usage(cache_root)
    if docker_root is not None:
        checks["docker_root"] = disk_usage(docker_root)
    commands = {
        command: {
            "path": command_paths.get(command),
            "version": command_version(command) if command_paths.get(command) else "",
        }
        for command in inspected_commands
    }
    image_present = False
    if command_paths.get("docker") is not None:
        image_present = subprocess.run(
            ["docker", "image", "inspect", args.official_image],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0

    if missing_commands:
        failures.append("missing commands: " + ", ".join(missing_commands))
    for key, usage in checks.items():
        if not usage.get("exists", True):
            warnings.append(f"{key} path is not visible: {usage['path']}")
            continue
        if usage["free_bytes"] < args.min_free_gib * (1024**3):
            failures.append(
                f"{key} free space {usage['free_gib']} GiB is below required {args.min_free_gib} GiB"
            )

    payload = {
        "workspace": str(workspace),
        "runner_temp": str(runner_temp),
        "cache_root": str(cache_root) if cache_root is not None else "",
        "official_image": args.official_image,
        "official_image_present": image_present,
        "required_commands": required_commands,
        "inspected_commands": inspected_commands,
        "docker": docker,
        "commands": commands,
        "disk": checks,
        "warnings": warnings,
        "failures": failures,
    }
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Helpers for GitHub self-hosted official reproduction runners.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser("preflight", help="Validate disk space and required commands on a self-hosted runner.")
    preflight.add_argument("--out", required=True, help="JSON output path.")
    preflight.add_argument(
        "--min-free-gib",
        type=int,
        default=80,
        help="Minimum required free GiB on workspace, RUNNER_TEMP, and Docker root.",
    )
    preflight.add_argument(
        "--official-image",
        default="zhouzhouyi/os-contest:20260104",
        help="Official Docker image tag expected by the workflow.",
    )
    preflight.add_argument(
        "--cache-root",
        help="Optional persistent cache root that should also satisfy the free-space requirement.",
    )
    preflight.add_argument(
        "--required-command",
        action="append",
        help=(
            "Command required on the self-hosted runner host. May be repeated or comma/space separated. "
            f"Defaults to: {', '.join(DEFAULT_REQUIRED_COMMANDS)}."
        ),
    )
    preflight.add_argument(
        "--inspect-command",
        action="append",
        help="Extra host command to report in JSON without making it a hard requirement.",
    )
    preflight.set_defaults(func=command_preflight)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
