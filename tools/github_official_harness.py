#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import time
from pathlib import Path


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
    parser = argparse.ArgumentParser(
        description="Outer timeout and combined serial/stdio capture wrapper for GitHub official reproduction.",
    )
    parser.add_argument("--timeout", type=int, required=True, help="Outer timeout in seconds.")
    parser.add_argument("--log-path", required=True, help="Combined stdout/stderr capture path.")
    parser.add_argument("--meta-path", help="Optional JSON metadata path.")
    parser.add_argument("--cwd", help="Optional working directory for the wrapped command.")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to execute after --.")
    args = parser.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise SystemExit("missing wrapped command; pass it after --")

    cwd = Path(args.cwd).resolve() if args.cwd else None
    log_path = Path(args.log_path).resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path = Path(args.meta_path).resolve() if args.meta_path else log_path.with_suffix(log_path.suffix + ".json")

    meta = {
        "timeout": args.timeout,
        "cwd": str(cwd) if cwd else None,
        "command": cmd,
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    started_at = time.time()
    with log_path.open("wb") as log_file:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
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

    meta.update(
        {
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_sec": round(finished_at - started_at, 3),
            "returncode": returncode,
            "timed_out": timed_out,
            "log_path": str(log_path),
        }
    )
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, ensure_ascii=False))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
