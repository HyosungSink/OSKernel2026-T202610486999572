#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

QEMU_BIN_DIR = Path("/opt/qemu-bin-10.0.2/bin")


def resolve_qemu(binary: str) -> str:
    bundled = QEMU_BIN_DIR / binary
    if bundled.exists():
        return str(bundled)
    return shutil.which(binary) or binary


def rv_command(kernel: Path, fs_image: Path, extra_image: Path | None, memory: str, smp: int) -> list[str]:
    cmd = [
        resolve_qemu("qemu-system-riscv64"),
        "-machine", "virt",
        "-kernel", str(kernel),
        "-m", memory,
        "-nographic",
        "-smp", str(smp),
        "-bios", "default",
        "-drive", f"file={fs_image},if=none,format=raw,id=x0",
        "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
        "-no-reboot",
        "-device", "virtio-net-device,netdev=net",
        "-netdev", "user,id=net",
        "-rtc", "base=utc",
    ]
    if extra_image is not None:
        cmd.extend([
            "-drive", f"file={extra_image},if=none,format=raw,id=x1",
            "-device", "virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1",
        ])
    return cmd


def la_command(kernel: Path, fs_image: Path, extra_image: Path | None, memory: str, smp: int) -> list[str]:
    cmd = [
        resolve_qemu("qemu-system-loongarch64"),
        "-kernel", str(kernel),
        "-m", memory,
        "-nographic",
        "-smp", str(smp),
        "-drive", f"file={fs_image},if=none,format=raw,id=x0",
        "-device", "virtio-blk-pci,drive=x0,bus=virtio-mmio-bus.0",
        "-no-reboot",
        "-device", "virtio-net-pci,netdev=net0",
        "-netdev", "user,id=net0,hostfwd=tcp::5555-:5555,hostfwd=udp::5555-:5555",
        "-rtc", "base=utc",
    ]
    if extra_image is not None:
        cmd.extend([
            "-drive", f"file={extra_image},if=none,format=raw,id=x1",
            "-device", "virtio-blk-pci,drive=x1,bus=virtio-mmio-bus.1",
        ])
    return cmd


def terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    proc.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run exact official-style QEMU commands and capture raw serial logs.")
    parser.add_argument("--arch", choices=["rv", "la"], required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--fs-image", required=True)
    parser.add_argument("--extra-image")
    parser.add_argument("--log-path", required=True)
    parser.add_argument("--meta-path")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--memory", default="1G")
    parser.add_argument("--smp", type=int, default=1)
    args = parser.parse_args()

    kernel = Path(args.kernel).resolve()
    fs_image = Path(args.fs_image).resolve()
    extra_image = Path(args.extra_image).resolve() if args.extra_image else None
    log_path = Path(args.log_path).resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path = Path(args.meta_path).resolve() if args.meta_path else log_path.with_suffix(log_path.suffix + ".json")

    if args.arch == "rv":
        cmd = rv_command(kernel, fs_image, extra_image, args.memory, args.smp)
    else:
        cmd = la_command(kernel, fs_image, extra_image, args.memory, args.smp)

    meta = {
        "arch": args.arch,
        "kernel": str(kernel),
        "fs_image": str(fs_image),
        "extra_image": str(extra_image) if extra_image else None,
        "timeout": args.timeout,
        "memory": args.memory,
        "smp": args.smp,
        "command": cmd,
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    started_at = time.time()
    with log_path.open("wb") as log_file:
        proc = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        timed_out = False
        try:
            returncode = proc.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group(proc)
            returncode = 124
    finished_at = time.time()
    meta.update({
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_sec": round(finished_at - started_at, 3),
        "returncode": returncode,
        "timed_out": timed_out,
    })
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, ensure_ascii=False))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
