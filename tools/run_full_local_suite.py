#!/usr/bin/env python3

from __future__ import annotations

import argparse
import atexit
import concurrent.futures
from collections import deque
import fcntl
import hashlib
import http.server
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable


ROOT = Path(__file__).resolve().parents[1]
TESTSUITS_ROOT = Path(os.environ.get("TESTSUITS_ROOT", ROOT / "testsuits-for-oskernel-pre-2025"))
LTP_RELEASE = "20240524"
LTP_SUITE_DIR = f"ltp-full-{LTP_RELEASE}"
LTP_RUNTEST_PATH = TESTSUITS_ROOT / LTP_SUITE_DIR / "runtest" / "syscalls"


def default_work_root() -> Path:
    return Path(os.environ.get("OSK_WORK_ROOT", ROOT / "dev/full-suite"))


def default_shared_cache_root() -> Path:
    return Path(os.environ.get("OSK_SHARED_CACHE_ROOT", Path.home() / ".cache" / "osk-full-suite"))


WORK_ROOT = default_work_root()
SHARED_CACHE_ROOT = default_shared_cache_root()
QEMU_BIN_DIR = Path("/opt/qemu-bin-10.0.2/bin")


def resolve_host_tool(env_name: str, bundled_name: str, fallback_name: str) -> str:
    if value := os.environ.get(env_name):
        return value
    bundled_path = QEMU_BIN_DIR / bundled_name
    if bundled_path.exists():
        return str(bundled_path)
    return shutil.which(fallback_name) or fallback_name


QEMU_IMG = os.environ.get("QEMU_IMG") or shutil.which("qemu-img") or "qemu-img"
QEMU_SYSTEM_RISCV64 = resolve_host_tool(
    "QEMU_SYSTEM_RISCV64",
    "qemu-system-riscv64",
    "qemu-system-riscv64",
)
QEMU_SYSTEM_LOONGARCH64 = resolve_host_tool(
    "QEMU_SYSTEM_LOONGARCH64",
    "qemu-system-loongarch64",
    "qemu-system-loongarch64",
)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
WARNING_RE = re.compile(r"\bwarning\b", re.IGNORECASE)
CONFIGURE_RE = re.compile(r"\bconfigure\b|\bconfig\.status\b|\bconfig\.log\b|^\s*checking\b", re.IGNORECASE)
FATAL_LOG_RE = re.compile(
    r"stack smashing detected|segmentation fault|kernel panic|panic:|BUG:|Oops:|general protection fault|watchdog timeout",
    re.IGNORECASE,
)
IGNORED_FATAL_LOG_RE = re.compile(r"Competition script watchdog timeout", re.IGNORECASE)
COMPETITION_SCRIPT_WATCHDOG_RE = re.compile(r"Competition script watchdog timeout:", re.IGNORECASE)
LTP_PASS_LINE_RE = re.compile(r"^PASS LTP CASE ([A-Za-z0-9_.+-]+) : 0$")
LTP_LEGACY_OK_LINE_RE = re.compile(r"^FAIL LTP CASE ([A-Za-z0-9_.+-]+) : 0$")
LTP_FAIL_LINE_RE = re.compile(r"^FAIL LTP CASE ([A-Za-z0-9_.+-]+) : \d+$")
LTP_SKIP_LINE_RE = re.compile(r"^SKIP LTP CASE ([A-Za-z0-9_.+-]+) : \d+$")
LTP_RUN_LINE_RE = re.compile(r"^RUN LTP CASE ([A-Za-z0-9_.+-]+)$")
LTP_HEARTBEAT_LINE_RE = re.compile(r"^\[ltp-heartbeat\](?:\s+([A-Za-z0-9_.+-]+))?$")
QEMU_TERMINATING_LINE_RE = re.compile(r"^qemu-system-[^:]+: terminating on signal \d+\b")
LTP_PROGRESS_LINE_RE = re.compile(r"\[epoll-ltp-progress\]\s+epoll_ctl_count=(\d+)\b")
LTP_CASE_SUFFIX_WITH_UNDERSCORE_RE = re.compile(r"^(?P<base>.+)_(?P<suffix>\d+)$")
LTP_CASE_SUFFIX_DIGITS_RE = re.compile(r"^(?P<base>.*?\D)(?P<suffix>\d{2,})$")
KERNEL_LOG_TIMESTAMP_RE = re.compile(r"^\[\s*(\d+(?:\.\d+)?)\b")
DEFAULT_TIMEOUT = 3600
DEFAULT_BUILD_JOBS = max(1, os.cpu_count() or 1)
DEFAULT_ROOTFS_VARIANT_JOBS = 1
FATAL_IDLE_TIMEOUT = 15.0
SILENT_IDLE_TIMEOUT = 90.0
SHARDED_LTP_SILENT_IDLE_TIMEOUT = 60.0
LTP_HEARTBEAT_INTERVAL_SEC = 30
LTP_SINGLE_CASE_TIMEOUT_SEC = 300
DEDICATED_LTP_RUNTIME_MUL = 1.0
DEDICATED_LTP_SHARDS = 10
LTP_QUEUE_GUEST_HOST = "10.0.2.2"
LTP_QUEUE_DONE_SENTINEL = "__OSK_LTP_DONE__"
LTP_SHARD_POINT_WEIGHTS = {
    "fanotify": 6,
    "fork": 6,
    "timerfd_settime": 6,
    "fcntl": 4,
    "ioctl": 4,
    "mount": 4,
    "move_pages": 4,
    "preadv": 4,
    "prctl": 4,
    "ptrace": 4,
    "pwritev": 4,
    "quotactl": 4,
    "semctl": 4,
    "statx": 4,
    "mmap": 3,
    "open": 3,
    "rename": 3,
    "sendfile": 3,
}
LTP_RUNTIME_WEIGHT_SAMPLE_BY_VARIANT = {
    "glibc-rv": "ltp-glibc-rv",
    "musl-rv": "ltp-musl-rv",
    "glibc-la": "ltp-glibc-la",
    "musl-la": "ltp-musl-la",
}
LTP_RUNTIME_WEIGHT_EXPORT_LOG_BY_VARIANT = {
    "glibc-rv": ROOT / "logs" / "local_Riscv输出.txt",
    "musl-rv": ROOT / "logs" / "local_Riscv输出.txt",
    "glibc-la": ROOT / "logs" / "local_LoongArch输出.txt",
    "musl-la": ROOT / "logs" / "local_LoongArch输出.txt",
}
LTP_FALLBACK_RUNTIME_WEIGHT_EXPORT_LOG_BY_VARIANT = {
    "glibc-rv": ROOT / "logs" / "fallback_local_Riscv输出.txt",
    "musl-rv": ROOT / "logs" / "fallback_local_Riscv输出.txt",
    "glibc-la": ROOT / "logs" / "fallback_local_LoongArch输出.txt",
    "musl-la": ROOT / "logs" / "fallback_local_LoongArch输出.txt",
}
LTP_PERSISTED_WEIGHT_FILE = ROOT / "logs" / "local_ltp_shard_weights.json"
LTP_RUNTIME_WEIGHT_UNIT_SEC = 1
LTP_WEIGHT_CASE_BASE_SEC = 3
LTP_WEIGHT_CASE_TAIL_SEC = max(3, LTP_HEARTBEAT_INTERVAL_SEC // 2)
LTP_WEIGHT_BATCH_BOOT_SEC = 20
LTP_WEIGHT_STALLED_PENALTY_SEC = SHARDED_LTP_SILENT_IDLE_TIMEOUT
LTP_WEIGHT_POINT_QUANTILE = 0.75
LTP_HEAVY_CASE_WEIGHT_THRESHOLD = 180
LTP_MEDIUM_CASE_WEIGHT_THRESHOLD = 90
LTP_WARM_CASE_WEIGHT_THRESHOLD = 45
LTP_DYNAMIC_LEASE_REGULAR_TARGET_SEC = 60
LTP_DYNAMIC_LEASE_WARM_TARGET_SEC = 90
LTP_DYNAMIC_LEASE_REGULAR_MAX_CASES = 12
LTP_DYNAMIC_LEASE_WARM_MAX_CASES = 4
ENABLE_LTP_RUNTIME_WEIGHT_REFRESH = False
LTP_RUNTIME_WEIGHT_REFRESH_VARIANTS: set[str] = set()
FULL_RUN_FAILURE_LIMIT = 4
TAIL_LINES = 40
LIVE_LINE_PREFIX = "[live] "
LIVE_POLL_INTERVAL = 0.2
LIVE_LINE_ENABLED = sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"
LIVE_OUTPUT_ENABLED = LIVE_LINE_ENABLED
ACTIVE_LIVE_STATUS_RENDERER_OWNER: object | None = None
ACTIVE_LIVE_STATUS_RENDERER: Callable[[], None] | None = None
ACTIVE_LIVE_STATUS_CLEARER: Callable[[], None] | None = None
LTP_PROGRESS_SNAPSHOT_INTERVAL = 15.0
TERMINATE_GRACE_PERIOD = 1.0
OFFICIAL_IMAGE_SIZE = os.environ.get("OSK_OFFICIAL_IMAGE_SIZE", "")
OFFICIAL_IMAGE_EXTRA_MIB = int(os.environ.get("OSK_OFFICIAL_IMAGE_EXTRA_MIB", "512"))
DIRECT_IMAGE_SIZE = "4096M"
OFFICIAL_GROUP_MARKER_RE = re.compile(r"^#### OS COMP TEST GROUP (START|END) ([a-z0-9]+)-(glibc|musl) ####$")
OFFICIAL_CASE_LINE_RE = re.compile(r"^\[case\] ([a-z0-9]+)-([a-z]+)-([a-z0-9]+) (.+)$")
FAILED_SAMPLE_LINE_RE = re.compile(r"^\[fail\] ([a-z0-9-]+): ")
TIMED_OUT_SAMPLE_LINE_RE = re.compile(r"^\[timeout\] ([a-z0-9-]+): ")
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
RUNTIME_ORDER = ["glibc", "musl"]
ARCH_ORDER = ["rv", "la"]
SAMPLE_ORDER = [
    "basic-glibc-la",
    "basic-glibc-rv",
    "basic-musl-la",
    "basic-musl-rv",
    "busybox-glibc-la",
    "busybox-glibc-rv",
    "busybox-musl-la",
    "busybox-musl-rv",
    "cyclictest-glibc-la",
    "cyclictest-glibc-rv",
    "cyclictest-musl-la",
    "cyclictest-musl-rv",
    "iozone-glibc-la",
    "iozone-glibc-rv",
    "iozone-musl-la",
    "iozone-musl-rv",
    "iperf-glibc-la",
    "iperf-glibc-rv",
    "iperf-musl-la",
    "iperf-musl-rv",
    "libcbench-glibc-la",
    "libcbench-glibc-rv",
    "libcbench-musl-la",
    "libcbench-musl-rv",
    "libctest-glibc-la",
    "libctest-glibc-rv",
    "libctest-musl-la",
    "libctest-musl-rv",
    "lmbench-glibc-la",
    "lmbench-glibc-rv",
    "lmbench-musl-la",
    "lmbench-musl-rv",
    "ltp-glibc-la",
    "ltp-glibc-rv",
    "ltp-musl-la",
    "ltp-musl-rv",
    "lua-glibc-la",
    "lua-glibc-rv",
    "lua-musl-la",
    "lua-musl-rv",
    "netperf-glibc-la",
    "netperf-glibc-rv",
    "netperf-musl-la",
    "netperf-musl-rv",
]

SCRIPT_BY_GROUP = {
    "basic": "basic_testcode.sh",
    "busybox": "busybox_testcode.sh",
    "cyclictest": "cyclictest_testcode.sh",
    "iozone": "iozone_testcode.sh",
    "iperf": "iperf_testcode.sh",
    "libcbench": "libcbench_testcode.sh",
    "libctest": "libctest_testcode.sh",
    "lmbench": "lmbench_testcode.sh",
    "ltp": "ltp_testcode.sh",
    "lua": "lua_testcode.sh",
    "netperf": "netperf_testcode.sh",
}

OFFICIAL_CACHE_KEY_FILE = ".osk_official_cache_key"
OFFICIAL_ALLOWED_GROUPS_FILE = ".osk_allowed_runtime_groups"

OFFICIAL_RUNTIME_BASE_ENTRIES = (
    "bin",
    "lib",
    "lib64",
    "sbin",
)
OFFICIAL_REQUIRED_RUNTIME_BASE_ENTRIES = ("bin", "lib")

OFFICIAL_GROUP_PAYLOADS: dict[str, tuple[str, ...]] = {
    "basic": ("basic",),
    "busybox": (),
    "cyclictest": ("cyclictest", "hackbench"),
    "iozone": ("iozone",),
    "iperf": ("iperf3",),
    "libcbench": ("libc-bench",),
    "libctest": (),
    "lmbench": ("lmbench_all",),
    "ltp": ("ltp",),
    "lua": (
        "date.lua",
        "file_io.lua",
        "lua",
        "max_min.lua",
        "random.lua",
        "remove.lua",
        "round_num.lua",
        "sin30.lua",
        "sort.lua",
        "strings.lua",
        "test.sh",
    ),
    "netperf": ("netperf", "netserver"),
}

OFFICIAL_REFRESH_BASE_PAYLOADS: tuple[str, ...] = (
    "basic",
    ".basic_testcode.sh.raw",
    "basic_testcode.sh",
    "busybox",
    "busybox_cmd.txt",
    ".busybox_testcode.sh.raw",
    "busybox_testcode.sh",
    ".libctest_testcode.sh.raw",
    "libctest_testcode.sh",
    "entry-static.exe",
    "entry-dynamic.exe",
    ".cyclictest_testcode.sh.raw",
    "cyclictest_testcode.sh",
    "cyclictest",
    "hackbench",
)

OFFICIAL_REFRESH_BASE_TARGETS = "basic busybox libc-test cyclictest"
OFFICIAL_REFRESH_BASE_GROUPS = ("basic", "busybox", "libctest", "cyclictest")

OFFICIAL_ONLINE_REFRESH_BASELINE_MISSING: dict[tuple[str, str], tuple[str, ...]] = {
    ("rv", "glibc"): ("basic/test_echo", "basic/text.txt"),
    ("rv", "musl"): ("basic/test_echo",),
    ("la", "glibc"): ("basic/test_echo", "basic/text.txt"),
    ("la", "musl"): ("basic/test_echo", "basic/text.txt"),
}

OFFICIAL_ONLINE_REFRESH_BASELINE_EXACT: dict[tuple[str, str], tuple[str, ...]] = {
    ("rv", "musl"): ("basic/text.txt",),
    ("la", "glibc"): ("basic/sleep",),
    ("la", "musl"): ("basic/sleep",),
}

TRANSCRIPT_LOG_PATH: Path | None = None
LTP_EXPECTED_CASES_OVERRIDE: list[str] | None = None
ACTIVE_CHILD_PROC: subprocess.Popen[str] | None = None
ACTIVE_CHILD_PROCS: set[subprocess.Popen[str]] = set()
ACTIVE_CHILD_PROCS_LOCK = threading.Lock()
LTP_CASE_RUNTIME_WEIGHT_CACHE: dict[str, tuple[dict[str, int], dict[str, int]]] = {}


@dataclass
class DetailRow:
    name: str
    passed: int
    total: int
    status: str


@dataclass
class CaseResult:
    sample: str
    group: str
    runtime: str
    arch: str
    log_path: Path
    timed_out: bool = False
    returncode: int | None = None
    ok: bool = False
    summary: str = ""
    error: str | None = None
    stop_reason: str | None = None
    skipped: bool = False
    details: list[DetailRow] | None = None
    shard_timing_lines: list[str] | None = None

    @property
    def passed(self) -> int:
        return sum(row.passed for row in self.details or [])

    @property
    def total(self) -> int:
        return sum(row.total for row in self.details or [])

    @property
    def cell(self) -> str:
        if self.skipped:
            return "SKIP"
        if self.timed_out:
            return "TIMEOUT"
        if self.details is None:
            return "ERR"
        return f"{self.passed}/{self.total}"


@dataclass
class LtpSingleBootEstimate:
    startup_sec: int
    case_sec: int
    total_sec: int
    exact_case_count: int
    point_case_count: int
    history_case_count: int
    total_case_count: int
    startup_source: str


@dataclass(frozen=True)
class LtpQueueCase:
    case_index: int
    case_name: str
    runtest_line: str
    weight_sec: int


class LtpWorkStealingQueue:
    def __init__(self, cases: list[LtpQueueCase]) -> None:
        self.lock = threading.Lock()
        self.pending_cases: deque[LtpQueueCase] = deque(cases)
        self.worker_attempts: dict[int, int] = {}
        self.in_flight: dict[int, LtpQueueCase] = {}
        self.assigned_cases: dict[tuple[int, int], list[LtpQueueCase]] = {}

    def set_worker_attempt(self, worker_index: int, attempt: int) -> None:
        with self.lock:
            self.worker_attempts[worker_index] = attempt
            self.in_flight.pop(worker_index, None)

    def claim_next(self, worker_index: int) -> LtpQueueCase | None:
        with self.lock:
            if not self.pending_cases:
                self.in_flight.pop(worker_index, None)
                return None
            attempt = self.worker_attempts.get(worker_index, 1)
            case = self.pending_cases.popleft()
            self.in_flight[worker_index] = case
            self.assigned_cases.setdefault((worker_index, attempt), []).append(case)
            return case

    def mark_case_finished(self, case_name: str) -> None:
        with self.lock:
            for worker_index, case in list(self.in_flight.items()):
                if case.case_name == case_name:
                    self.in_flight.pop(worker_index, None)
                    break

    def mark_worker_stalled(self, worker_index: int) -> LtpQueueCase | None:
        with self.lock:
            return self.in_flight.pop(worker_index, None)

    def assigned_case_names(self, worker_index: int, attempt: int) -> list[str]:
        with self.lock:
            return [case.case_name for case in self.assigned_cases.get((worker_index, attempt), [])]

    def has_pending_cases(self) -> bool:
        with self.lock:
            return bool(self.pending_cases)


class LtpWorkStealingHttpServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], queue: LtpWorkStealingQueue, token: str) -> None:
        self.queue = queue
        self.token = token
        super().__init__(address, _LtpWorkStealingRequestHandler)


class _LtpWorkStealingRequestHandler(http.server.BaseHTTPRequestHandler):
    server: LtpWorkStealingHttpServer

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/next":
            self.send_error(404)
            return
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        token = params.get("token", [""])[0]
        if token != self.server.token:
            self.send_error(403)
            return
        try:
            worker_index = max(0, int(params.get("worker", ["1"])[0]) - 1)
        except ValueError:
            self.send_error(400)
            return
        case = self.server.queue.claim_next(worker_index)
        body = ((case.runtest_line if case is not None else LTP_QUEUE_DONE_SENTINEL) + "\n").encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, format: str, *args: object) -> None:
        return


def ltp_point_name(case_name: str) -> str:
    point = case_name
    while True:
        if match := LTP_CASE_SUFFIX_WITH_UNDERSCORE_RE.match(point):
            point = match.group("base")
            continue
        if match := LTP_CASE_SUFFIX_DIGITS_RE.match(point):
            point = match.group("base")
            continue
        return point


def expected_ltp_point_totals() -> dict[str, int]:
    totals: dict[str, int] = {}
    for case_name in expected_ltp_cases():
        point = ltp_point_name(case_name)
        totals[point] = totals.get(point, 0) + 1
    return totals


def sanitize_line(raw: str) -> str:
    return ANSI_ESCAPE_RE.sub("", raw.rstrip("\n").rstrip("\r"))


def read_text(path: Path) -> str:
    return "\n".join(
        sanitize_line(line)
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
    )


def resolve_repo_path(path: str) -> Path:
    resolved = Path(path)
    if not resolved.is_absolute():
        resolved = ROOT / resolved
    return resolved


class FileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._file: object | None = None

    def __enter__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("w", encoding="utf-8")
        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._file is None:
            return
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()
        self._file = None


def marker_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore").strip()


def rootfs_ready_token(rootfs_dir: Path) -> str:
    for marker_name in (".osk_official_rootfs_ready", ".osk_full_rootfs_ready"):
        marker = rootfs_dir / marker_name
        token = marker_text(marker)
        if token:
            return token
    stat = rootfs_dir.stat()
    return f"{rootfs_dir.name}:{stat.st_mtime_ns}"


def git_output(args: list[str]) -> str | None:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def quick_kernel_revision_token() -> str | None:
    override = os.environ.get("OSK_QUICK_KERNEL_CACHE_TOKEN", "").strip()
    if override:
        return override
    head = git_output(["rev-parse", "HEAD"])
    if not head:
        return None
    dirty = git_output(
        [
            "status",
            "--porcelain",
            "--untracked-files=no",
            "--",
            "Makefile",
            "kernel",
            "tools/refresh_embedded_runtime.sh",
        ]
    )
    if dirty:
        return None
    return head


def hash_key(*parts: str) -> str:
    data = "\n".join(parts).encode("utf-8")
    return hashlib.sha1(data).hexdigest()


def merge_build_targets(primary_targets: str | None, extra_targets: str | None) -> str | None:
    ordered = [
        "basic",
        "busybox",
        "lua",
        "libc-test",
        "iozone",
        "iperf",
        "libcbench",
        "lmbench_src",
        "cyclictest",
        "ltp",
        "netperf",
    ]
    merged: set[str] = set()
    for chunk in (primary_targets, extra_targets):
        if not chunk:
            continue
        merged.update(part for part in chunk.split() if part)
    if not merged:
        return None
    return " ".join(target for target in ordered if target in merged)


def effective_quick_build_targets(build_targets: str | None) -> str | None:
    extra_targets = os.environ.get("OSK_QUICK_ROOTFS_TARGETS")
    return merge_build_targets(build_targets, extra_targets)


def file_content_token(path: Path) -> str:
    if not path.exists():
        return "missing"
    digest = hashlib.sha1()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def normalized_build_targets(build_targets: str | None) -> str:
    ordered = [
        "basic",
        "busybox",
        "lua",
        "libc-test",
        "iozone",
        "iperf",
        "libcbench",
        "lmbench_src",
        "cyclictest",
        "ltp",
        "netperf",
    ]
    if build_targets is None:
        return "ALL"
    requested = {part for part in build_targets.split() if part}
    return " ".join(target for target in ordered if target in requested)


def fail(message: str) -> None:
    raise ValueError(message)


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remain = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m{remain:04.1f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h{int(minutes):02d}m{remain:04.1f}s"


def terminal_width() -> int:
    return max(40, shutil.get_terminal_size((120, 20)).columns)


def truncate_for_terminal(text: str, prefix: str = "") -> str:
    width = terminal_width()
    available = max(8, width - len(prefix))
    if len(text) <= available:
        return prefix + text
    return prefix + text[: max(0, available - 3)] + "..."


def read_last_log_line(path: Path) -> str:
    if not path.exists():
        return ""
    size = path.stat().st_size
    if size <= 0:
        return ""
    block = b""
    with path.open("rb") as file:
        pos = size
        while pos > 0 and len(block) < 65536:
            step = min(4096, pos)
            pos -= step
            file.seek(pos)
            block = file.read(step) + block
            if block.count(b"\n") >= 2:
                break
    lines = block.splitlines()
    if not lines:
        return ""
    return sanitize_line(lines[-1].decode("utf-8", errors="ignore"))


def read_recent_log_lines(path: Path, count: int = 8) -> list[str]:
    if not path.exists():
        return []
    size = path.stat().st_size
    if size <= 0:
        return []
    block = b""
    with path.open("rb") as file:
        pos = size
        while pos > 0 and len(block) < 131072:
            step = min(8192, pos)
            pos -= step
            file.seek(pos)
            block = file.read(step) + block
            if block.count(b"\n") >= count + 1:
                break
    lines = [sanitize_line(line.decode("utf-8", errors="ignore")) for line in block.splitlines()]
    return lines[-count:]


def read_appended_log_lines(path: Path, offset: int, partial: str) -> tuple[int, str, list[str]]:
    if not path.exists():
        return offset, partial, []
    with path.open("r", encoding="utf-8", errors="ignore") as file:
        file.seek(offset)
        chunk = file.read()
        offset = file.tell()
    if not chunk:
        return offset, partial, []
    text = partial + chunk
    lines: list[str] = []
    tail = ""
    for piece in text.splitlines(keepends=True):
        if piece.endswith("\n") or piece.endswith("\r"):
            lines.append(sanitize_line(piece))
        else:
            tail = piece
    return offset, tail, lines


def fatal_log_reason(lines: list[str]) -> str | None:
    if not lines:
        return None
    for line in reversed(lines):
        if not line:
            continue
        if IGNORED_FATAL_LOG_RE.search(line):
            continue
        match = FATAL_LOG_RE.search(line)
        if match:
            return sanitize_line(match.group(0))
    return None


def is_restartable_stall(reason: str | None) -> bool:
    return bool(
        reason
        and (
            reason.startswith("fatal log stall after ")
            or reason.startswith("silent log stall after ")
        )
    )


def is_timeout_like_stop_reason(reason: str | None) -> bool:
    if not reason:
        return False
    return (
        reason.startswith("timeout after ")
        or reason.startswith("silent log stall after ")
        or reason.startswith("fatal log stall after watchdog timeout")
    )


def clear_live_line() -> None:
    global LIVE_OUTPUT_ENABLED
    if not LIVE_OUTPUT_ENABLED:
        return
    clearer = ACTIVE_LIVE_STATUS_CLEARER
    if clearer is not None:
        clearer()
        return
    try:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
    except (BrokenPipeError, OSError, ValueError):
        LIVE_OUTPUT_ENABLED = False


def set_live_status_renderer(
    owner: object,
    renderer: Callable[[], None] | None,
    clearer: Callable[[], None] | None = None,
) -> None:
    global ACTIVE_LIVE_STATUS_CLEARER, ACTIVE_LIVE_STATUS_RENDERER_OWNER, ACTIVE_LIVE_STATUS_RENDERER
    if renderer is None:
        if ACTIVE_LIVE_STATUS_RENDERER_OWNER is owner:
            if ACTIVE_LIVE_STATUS_CLEARER is not None:
                ACTIVE_LIVE_STATUS_CLEARER()
            ACTIVE_LIVE_STATUS_RENDERER_OWNER = None
            ACTIVE_LIVE_STATUS_RENDERER = None
            ACTIVE_LIVE_STATUS_CLEARER = None
        return
    ACTIVE_LIVE_STATUS_RENDERER_OWNER = owner
    ACTIVE_LIVE_STATUS_RENDERER = renderer
    ACTIVE_LIVE_STATUS_CLEARER = clearer


def rerender_live_status() -> None:
    if not LIVE_OUTPUT_ENABLED:
        return
    renderer = ACTIVE_LIVE_STATUS_RENDERER
    if renderer is None:
        return
    renderer()


def safe_print(message: str, *, err: bool = False) -> None:
    global LIVE_OUTPUT_ENABLED
    stream = sys.stderr if err else sys.stdout
    try:
        print(message, file=stream, flush=True)
    except (BrokenPipeError, OSError, ValueError):
        LIVE_OUTPUT_ENABLED = False


def disable_live_output() -> None:
    global LIVE_OUTPUT_ENABLED
    LIVE_OUTPUT_ENABLED = False


atexit.register(disable_live_output)


def append_transcript_line(message: str) -> None:
    if TRANSCRIPT_LOG_PATH is None:
        return
    TRANSCRIPT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with TRANSCRIPT_LOG_PATH.open("a", encoding="utf-8", errors="ignore") as file:
        file.write(message + "\n")


def init_transcript_log(path: Path) -> None:
    global TRANSCRIPT_LOG_PATH
    TRANSCRIPT_LOG_PATH = path
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()
        return
    if path.stat().st_size == 0:
        return
    with path.open("rb+") as file:
        file.seek(-1, os.SEEK_END)
        if file.read(1) != b"\n":
            file.write(b"\n")


def refresh_live_line(path: Path) -> None:
    global LIVE_OUTPUT_ENABLED
    if not LIVE_OUTPUT_ENABLED:
        return
    last_line = read_last_log_line(path)
    if not last_line:
        return
    message = truncate_for_terminal(last_line, prefix=LIVE_LINE_PREFIX)
    try:
        sys.stdout.write("\r\033[K" + message)
        sys.stdout.flush()
    except (BrokenPipeError, OSError, ValueError):
        LIVE_OUTPUT_ENABLED = False


def capture_tty_state() -> list[tuple[int, list[int | bytes]]]:
    states: list[tuple[int, list[int | bytes]]] = []
    seen: set[int] = set()
    for stream in [sys.stdin, sys.stdout, sys.stderr]:
        try:
            fd = stream.fileno()
        except (AttributeError, OSError, ValueError):
            continue
        if fd in seen or not os.isatty(fd):
            continue
        try:
            states.append((fd, termios.tcgetattr(fd)))
            seen.add(fd)
        except termios.error:
            continue
    return states


def restore_tty_state(states: list[tuple[int, list[int | bytes]]]) -> None:
    for fd, attrs in states:
        try:
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except termios.error:
            continue


def terminate_process_group(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + TERMINATE_GRACE_PERIOD
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    proc.wait()


def register_active_child_proc(proc: subprocess.Popen[str]) -> None:
    global ACTIVE_CHILD_PROC
    with ACTIVE_CHILD_PROCS_LOCK:
        ACTIVE_CHILD_PROC = proc
        ACTIVE_CHILD_PROCS.add(proc)


def unregister_active_child_proc(proc: subprocess.Popen[str]) -> None:
    global ACTIVE_CHILD_PROC
    with ACTIVE_CHILD_PROCS_LOCK:
        ACTIVE_CHILD_PROCS.discard(proc)
        if ACTIVE_CHILD_PROC is proc:
            ACTIVE_CHILD_PROC = next(iter(ACTIVE_CHILD_PROCS), None)


def terminate_all_active_child_procs() -> None:
    global ACTIVE_CHILD_PROC
    with ACTIVE_CHILD_PROCS_LOCK:
        procs = list(ACTIVE_CHILD_PROCS)
        ACTIVE_CHILD_PROCS.clear()
        ACTIVE_CHILD_PROC = None
    for proc in procs:
        terminate_process_group(proc)


def terminate_active_child_proc() -> None:
    terminate_all_active_child_procs()


def handle_termination_signal(signum: int, _frame: object) -> None:
    terminate_all_active_child_procs()
    raise SystemExit(128 + signum)


signal.signal(signal.SIGTERM, handle_termination_signal)


def official_case_label(group: str, runtime: str, arch: str) -> str:
    return f"{runtime}-{arch}-{group}"


class OfficialProgressReporter:
    def __init__(
        self,
        arch: str,
        raw_log_path: Path,
        logs_dir: Path,
    ) -> None:
        self.arch = arch
        self.raw_log_path = raw_log_path
        self.logs_dir = logs_dir
        self.started: dict[tuple[str, str], float] = {}
        self.reported: set[tuple[str, str]] = set()
        self.completed_results: dict[str, CaseResult] = {}
        self.active_group: tuple[str, str] | None = None
        self.active_ltp_started_at: float | None = None
        self.last_ltp_point_at: float | None = None
        self.last_ltp_point_name: str | None = None
        self.active_ltp_case: str | None = None
        self.active_ltp_case_started_at: float | None = None
        self.ltp_point_totals: dict[str, int] = expected_ltp_point_totals()
        self.ltp_point_passed: dict[str, int] = {}
        self.ltp_point_finished_cases: set[str] = set()
        self.ltp_point_finished_count: dict[str, int] = {}
        self.ltp_reported_points: set[str] = set()

    def poll(self, now: float) -> str | None:
        _ = now
        return None

    def consume(self, lines: list[str], now: float) -> str | None:
        for line in lines:
            if COMPETITION_SCRIPT_WATCHDOG_RE.search(line):
                continue
            if self.active_group is not None and self.active_group[0] == "ltp":
                group_started_at = self.started.get(self.active_group, now)
                pass_match = LTP_PASS_LINE_RE.match(line)
                legacy_ok_match = LTP_LEGACY_OK_LINE_RE.match(line)
                if pass_match:
                    case_name = pass_match.group(1)
                    emit_live_ltp_case_progress(
                        self.arch,
                        self.active_group[1],
                        case_name,
                        max(0.0, now - group_started_at),
                        True,
                        self.ltp_point_totals,
                        self.ltp_point_passed,
                        self.ltp_point_finished_cases,
                        self.ltp_point_finished_count,
                        self.ltp_reported_points,
                    )
                    self.last_ltp_point_at = now
                    self.last_ltp_point_name = case_name
                    self.active_ltp_case = None
                    self.active_ltp_case_started_at = None
                elif legacy_ok_match:
                    case_name = legacy_ok_match.group(1)
                    emit_live_ltp_case_progress(
                        self.arch,
                        self.active_group[1],
                        case_name,
                        max(0.0, now - group_started_at),
                        True,
                        self.ltp_point_totals,
                        self.ltp_point_passed,
                        self.ltp_point_finished_cases,
                        self.ltp_point_finished_count,
                        self.ltp_reported_points,
                    )
                    self.last_ltp_point_at = now
                    self.last_ltp_point_name = case_name
                    self.active_ltp_case = None
                    self.active_ltp_case_started_at = None
                else:
                    fail_match = LTP_FAIL_LINE_RE.match(line)
                    if fail_match:
                        case_name = fail_match.group(1)
                        emit_live_ltp_case_progress(
                            self.arch,
                            self.active_group[1],
                            case_name,
                            max(0.0, now - group_started_at),
                            False,
                            self.ltp_point_totals,
                            self.ltp_point_passed,
                            self.ltp_point_finished_cases,
                            self.ltp_point_finished_count,
                            self.ltp_reported_points,
                        )
                        self.last_ltp_point_at = now
                        self.last_ltp_point_name = case_name
                        self.active_ltp_case = None
                        self.active_ltp_case_started_at = None
                        continue
                    skip_match = LTP_SKIP_LINE_RE.match(line)
                    if skip_match:
                        case_name = skip_match.group(1)
                        emit_live_ltp_case_progress(
                            self.arch,
                            self.active_group[1],
                            case_name,
                            max(0.0, now - group_started_at),
                            False,
                            self.ltp_point_totals,
                            self.ltp_point_passed,
                            self.ltp_point_finished_cases,
                            self.ltp_point_finished_count,
                            self.ltp_reported_points,
                        )
                        self.last_ltp_point_at = now
                        self.last_ltp_point_name = case_name
                        self.active_ltp_case = None
                        self.active_ltp_case_started_at = None
                        continue
                    run_match = LTP_RUN_LINE_RE.match(line)
                    if run_match:
                        self.active_ltp_case = run_match.group(1)
                        self.active_ltp_case_started_at = now
                        continue
                    heartbeat_match = LTP_HEARTBEAT_LINE_RE.match(line)
                    if heartbeat_match:
                        heartbeat_case = heartbeat_match.group(1)
                        if heartbeat_case:
                            self.active_ltp_case = heartbeat_case
                        self.active_ltp_case_started_at = now
                        continue
                    progress_match = LTP_PROGRESS_LINE_RE.search(line)
                    if progress_match:
                        continue
            match = OFFICIAL_GROUP_MARKER_RE.search(line)
            if not match:
                continue
            phase, group, runtime = match.groups()
            key = (group, runtime)
            if phase == "START":
                if self.active_group is not None and self.active_group != key:
                    prev_group, prev_runtime = self.active_group
                    prev_key = self.active_group
                    prev_started_at = self.started.pop(prev_key, now)
                    if prev_key not in self.reported:
                        self.reported.add(prev_key)
                        prev_sample = f"{prev_group}-{prev_runtime}-{self.arch}"
                        prev_log_path = self.logs_dir / f"{prev_sample}.out"
                        prev_group_name = f"{prev_group}-{prev_runtime}"
                        prev_status = write_group_log(self.raw_log_path, prev_group_name, prev_log_path)
                        if prev_status == "complete":
                            try:
                                prev_result = validate_case(prev_sample, prev_log_path)
                            except Exception as exc:
                                prev_result = zero_result_for_missing_group(prev_sample, prev_log_path, str(exc))
                        elif prev_status == "partial":
                            partial_text = read_text(prev_log_path)
                            partial_timed_out = "Competition script watchdog timeout" in partial_text
                            error = (
                                f"incomplete group markers for {prev_group_name}"
                                if not partial_timed_out
                                else f"group timed out before end marker for {prev_group_name}"
                            )
                            prev_result = partial_result_for_group(
                                prev_sample,
                                prev_log_path,
                                error,
                                timed_out=partial_timed_out,
                            )
                        else:
                            prev_result = zero_result_for_missing_group(
                                prev_sample,
                                prev_log_path,
                                f"missing group markers for {prev_group_name}",
                            )
                        self.completed_results[prev_sample] = prev_result
                        console(
                            f"[case] {official_case_label(prev_group, prev_runtime, self.arch)} "
                            f"{format_duration(max(0.0, now - prev_started_at))} "
                            f"points {prev_result.passed}/{prev_result.total}"
                        )
                self.started[key] = now
                self.active_group = key
                if group == "ltp":
                    self.active_ltp_started_at = now
                    self.last_ltp_point_at = None
                    self.last_ltp_point_name = None
                    self.active_ltp_case = None
                    self.active_ltp_case_started_at = None
                    self.ltp_point_totals = expected_ltp_point_totals()
                    self.ltp_point_passed = {}
                    self.ltp_point_finished_cases = set()
                    self.ltp_point_finished_count = {}
                    self.ltp_reported_points = set()
                continue
            started_at = self.started.pop(key, now)
            if self.active_group == key:
                self.active_group = None
            if group == "ltp":
                self.active_ltp_started_at = None
                self.last_ltp_point_at = None
                self.last_ltp_point_name = None
                self.active_ltp_case = None
                self.active_ltp_case_started_at = None
                self.ltp_point_passed = {}
                self.ltp_point_finished_cases = set()
                self.ltp_point_finished_count = {}
                self.ltp_reported_points = set()
            if key in self.reported:
                continue
            self.reported.add(key)
            sample = f"{group}-{runtime}-{self.arch}"
            sample_log_path = self.logs_dir / f"{sample}.out"
            group_name = f"{group}-{runtime}"
            result: CaseResult | None = None
            group_log_status = write_group_log(self.raw_log_path, group_name, sample_log_path)
            if group_log_status == "complete":
                try:
                    result = validate_case(sample, sample_log_path)
                except Exception as exc:
                    result = zero_result_for_missing_group(sample, sample_log_path, str(exc))
            elif group_log_status == "partial":
                partial_text = read_text(sample_log_path)
                partial_timed_out = "Competition script watchdog timeout" in partial_text
                error = (
                    f"incomplete group markers for {group_name}"
                    if not partial_timed_out
                    else f"group timed out before end marker for {group_name}"
                )
                result = zero_result_for_incomplete_group(
                    sample,
                    sample_log_path,
                    error,
                    timed_out=partial_timed_out,
                )
            else:
                result = zero_result_for_missing_group(sample, sample_log_path, f"missing group markers for {group_name}")
            self.completed_results[sample] = result
            console(
                f"[case] {official_case_label(group, runtime, self.arch)} "
                f"{format_duration(max(0.0, now - started_at))} points {result.passed}/{result.total}"
            )
        return None


def begin_stage(stage: str) -> float:
    clear_live_line()
    message = f"[stage] {stage}"
    safe_print(message)
    append_transcript_line(message)
    return time.monotonic()


def finish_stage(stage: str, started_at: float) -> None:
    message = f"[stage] {stage} ({format_duration(time.monotonic() - started_at)})"
    append_transcript_line(message)
    if LIVE_OUTPUT_ENABLED:
        clear_live_line()
        try:
            sys.stdout.write("\033[1A\r\033[K" + truncate_for_terminal(message) + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, OSError, ValueError):
            disable_live_output()
        return
    safe_print(message)


def complete_stage(stage: str, elapsed: float = 0.0) -> None:
    clear_live_line()
    message = f"[stage] {stage} ({format_duration(elapsed)})"
    safe_print(message)
    append_transcript_line(message)


def format_progress_bar(done: int, total: int, width: int = 20) -> str:
    if total <= 0:
        return "[" + "-" * width + "]"
    done = max(0, min(done, total))
    filled = min(width, int(width * done / total))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def format_stage_progress_message(
    stage: str,
    done: int,
    total: int,
    started_at: float,
    *,
    detail: str | None = None,
) -> str:
    message = (
        f"[stage] {stage} {format_progress_bar(done, total)} "
        f"{done}/{total} ({format_duration(time.monotonic() - started_at)})"
    )
    if detail:
        message += f" {detail}"
    return message


def update_stage_progress(
    stage: str,
    done: int,
    total: int,
    started_at: float,
    *,
    detail: str | None = None,
) -> None:
    global LIVE_OUTPUT_ENABLED
    if not LIVE_OUTPUT_ENABLED:
        return
    message = format_stage_progress_message(stage, done, total, started_at, detail=detail)
    try:
        sys.stdout.write("\r\033[K" + truncate_for_terminal(message))
        sys.stdout.flush()
    except (BrokenPipeError, OSError, ValueError):
        LIVE_OUTPUT_ENABLED = False


def finish_stage_progress(
    stage: str,
    done: int,
    total: int,
    started_at: float,
    *,
    detail: str | None = None,
) -> None:
    clear_live_line()
    message = format_stage_progress_message(stage, done, total, started_at, detail=detail)
    safe_print(message)
    append_transcript_line(message)


def format_ltp_shard_progress_message(
    label: str,
    done: int,
    total: int,
    started_at: float,
    passed: int,
    point_total: int,
    *,
    detail: str | None = None,
) -> str:
    message = (
        f"[ltp-shard] {label} {format_progress_bar(done, total)} "
        f"{done}/{total} ({format_duration(time.monotonic() - started_at)}) "
        f"points {passed}/{point_total}"
    )
    if detail:
        message += f" {detail}"
    return message


def update_ltp_shard_progress(
    label: str,
    done: int,
    total: int,
    started_at: float,
    passed: int,
    point_total: int,
    *,
    detail: str | None = None,
) -> None:
    global LIVE_OUTPUT_ENABLED
    if not LIVE_OUTPUT_ENABLED:
        return
    if ACTIVE_LIVE_STATUS_RENDERER is not None:
        rerender_live_status()
        return
    message = format_ltp_shard_progress_message(
        label,
        done,
        total,
        started_at,
        passed,
        point_total,
        detail=detail,
    )
    try:
        sys.stdout.write("\r\033[K" + truncate_for_terminal(message))
        sys.stdout.flush()
    except (BrokenPipeError, OSError, ValueError):
        LIVE_OUTPUT_ENABLED = False


def finish_ltp_shard_progress(
    label: str,
    done: int,
    total: int,
    started_at: float,
    passed: int,
    point_total: int,
) -> None:
    clear_live_line()
    message = format_ltp_shard_progress_message(label, done, total, started_at, passed, point_total)
    safe_print(message)
    append_transcript_line(message)


class LtpShardRuntimeProgressReporter:
    def __init__(self, label: str, total_shards: int, total_cases: int) -> None:
        self.label = label
        self.total_shards = total_shards
        self.total_cases = total_cases
        self.started_at = time.monotonic()
        self.last_console_snapshot_at = self.started_at
        self.lock = threading.Lock()
        self.finished_cases: set[str] = set()
        self.passed_cases: set[str] = set()
        self.completed_shards: set[int] = set()
        self.active_cases: dict[int, str] = {}
        self.worker_states: dict[int, str] = {index: "booting" for index in range(total_shards)}
        self.worker_idle_started_at: dict[int, float | None] = {
            index: None for index in range(total_shards)
        }
        self.worker_idle_total_sec: dict[int, float] = {
            index: 0.0 for index in range(total_shards)
        }
        self.worker_restart_started_at: dict[int, float | None] = {
            index: None for index in range(total_shards)
        }
        self.worker_restart_total_sec: dict[int, float] = {
            index: 0.0 for index in range(total_shards)
        }
        self.rendered_line_count = 0
        set_live_status_renderer(
            self,
            lambda: self.poll(time.monotonic()),
            self.clear_live_display,
        )

    def _detail_parts(self) -> tuple[str | None, str | None]:
        active = [self.active_cases[index] for index in sorted(self.active_cases) if self.active_cases.get(index)]
        active_part = None
        if active:
            active_part = "active=" + ",".join(active)
        elif self.total_shards > 1:
            active_part = "active=-"
        summary_parts: list[str] = []
        booting = sum(1 for state in self.worker_states.values() if state == "booting")
        switching = sum(1 for state in self.worker_states.values() if state == "switching")
        idle = sum(1 for state in self.worker_states.values() if state == "idle")
        if booting > 0:
            summary_parts.append(f"booting {booting}")
        if switching > 0:
            summary_parts.append(f"switching {switching}")
        if idle > 0:
            summary_parts.append(f"idle {idle}")
        summary_part = " | ".join(summary_parts) if summary_parts else None
        return summary_part, active_part

    def _summary_message(self, now: float) -> str:
        summary_part, _active_part = self._detail_parts()
        message = (
            f"[ltp-progress] {self.label} "
            f"{format_progress_bar(len(self.finished_cases), self.total_cases)} "
            f"cases {len(self.finished_cases)}/{self.total_cases} "
            f"pass {len(self.passed_cases)} "
            f"shards {len(self.completed_shards)}/{self.total_shards} "
            f"({format_duration(max(0.0, now - self.started_at))})"
        )
        if summary_part:
            message += f" | {summary_part}"
        return message

    def _timing_total_locked(
        self,
        shard_index: int,
        now: float,
        *,
        total: dict[int, float],
        started_at: dict[int, float | None],
    ) -> float:
        elapsed = total.get(shard_index, 0.0)
        started = started_at.get(shard_index)
        if started is not None:
            elapsed += max(0.0, now - started)
        return elapsed

    def _wrapped_metric_lines(self, prefix: str, values: list[str]) -> list[str]:
        width = terminal_width()
        lines: list[str] = []
        current = prefix
        for value in values:
            addition = value if current == prefix else f" | {value}"
            if len(current) + len(addition) > width and current != prefix:
                lines.append(current)
                current = prefix + value
            else:
                current += addition
        if current != prefix:
            lines.append(current)
        return lines

    def _shard_timing_lines(self, now: float) -> list[str]:
        if self.total_shards <= 1:
            return []
        idle_values: list[str] = []
        restart_values: list[str] = []
        for shard_index in range(self.total_shards):
            idle_sec = self._timing_total_locked(
                shard_index,
                now,
                total=self.worker_idle_total_sec,
                started_at=self.worker_idle_started_at,
            )
            restart_sec = self._timing_total_locked(
                shard_index,
                now,
                total=self.worker_restart_total_sec,
                started_at=self.worker_restart_started_at,
            )
            idle_values.append(format_duration(idle_sec))
            restart_values.append(format_duration(restart_sec))
        return self._wrapped_metric_lines("[ltp-idle] ", idle_values) + self._wrapped_metric_lines(
            "[ltp-restart] ",
            restart_values,
        )

    def _message_lines(self, now: float) -> list[str]:
        summary_part, active_part = self._detail_parts()
        lines = [
            f"[ltp-progress] {self.label} "
            f"{format_progress_bar(len(self.finished_cases), self.total_cases)} "
            f"cases {len(self.finished_cases)}/{self.total_cases} "
            f"pass {len(self.passed_cases)} "
            f"shards {len(self.completed_shards)}/{self.total_shards} "
            f"({format_duration(max(0.0, now - self.started_at))})"
            + (f" | {summary_part}" if summary_part else "")
        ]
        if active_part:
            lines.append(f"[ltp-active] {active_part}")
            lines.extend(self._shard_timing_lines(now))
        return lines

    def snapshot_timing_lines(self, now: float | None = None) -> list[str]:
        with self.lock:
            snapshot_now = time.monotonic() if now is None else now
            lines = self._shard_timing_lines(snapshot_now)
            if not lines:
                return []
            return [f"[ltp-shard-timing] {self.label}", *lines]

    def _maybe_console_snapshot_lines_locked(self, now: float) -> list[str]:
        if LIVE_OUTPUT_ENABLED:
            return []
        if now - self.last_console_snapshot_at < LTP_PROGRESS_SNAPSHOT_INTERVAL:
            return []
        has_transient_state = any(
            state in {"booting", "switching"} for state in self.worker_states.values()
        ) or any(started_at is not None for started_at in self.worker_restart_started_at.values())
        has_active_cases = bool(self.active_cases)
        if not has_transient_state and not has_active_cases:
            return []
        self.last_console_snapshot_at = now
        return list(self._message_lines(now))

    def _render(self, now: float) -> None:
        global LIVE_OUTPUT_ENABLED
        if not LIVE_OUTPUT_ENABLED:
            return
        try:
            lines = self._message_lines(now)
            rendered = "\n".join(truncate_for_terminal(line) for line in lines)
            if self.rendered_line_count > 0:
                self._clear_rendered_lines_locked()
            else:
                sys.stdout.write("\r\033[K")
            sys.stdout.write(rendered)
            sys.stdout.flush()
            self.rendered_line_count = len(lines)
        except (BrokenPipeError, OSError, ValueError):
            LIVE_OUTPUT_ENABLED = False

    def _clear_rendered_lines_locked(self) -> None:
        global LIVE_OUTPUT_ENABLED
        if not LIVE_OUTPUT_ENABLED or self.rendered_line_count <= 0:
            return
        try:
            sys.stdout.write("\r\033[K")
            for _ in range(self.rendered_line_count - 1):
                sys.stdout.write("\033[1A\r\033[K")
            sys.stdout.flush()
            self.rendered_line_count = 0
        except (BrokenPipeError, OSError, ValueError):
            LIVE_OUTPUT_ENABLED = False

    def clear_live_display(self) -> None:
        with self.lock:
            self._clear_rendered_lines_locked()

    def _mark_finished_locked(self, case_name: str | None, *, passed: bool = False) -> bool:
        if not case_name:
            return False
        changed = False
        if case_name not in self.finished_cases:
            self.finished_cases.add(case_name)
            changed = True
        if passed and case_name not in self.passed_cases:
            self.passed_cases.add(case_name)
            changed = True
        return changed

    def _set_idle_state_locked(
        self,
        shard_index: int,
        now: float,
        *,
        idle: bool,
    ) -> bool:
        current = self.worker_idle_started_at.get(shard_index)
        if idle:
            if current is None:
                self.worker_idle_started_at[shard_index] = now
                return True
            return False
        if current is not None:
            self.worker_idle_total_sec[shard_index] = self.worker_idle_total_sec.get(shard_index, 0.0) + max(
                0.0,
                now - current,
            )
            self.worker_idle_started_at[shard_index] = None
            return True
        return False

    def _refresh_idle_state_locked(self, shard_index: int, now: float) -> bool:
        state = self.worker_states.get(shard_index, "booting")
        restart_active = self.worker_restart_started_at.get(shard_index) is not None
        return self._set_idle_state_locked(
            shard_index,
            now,
            idle=(state == "idle" and not restart_active),
        )

    def _set_restart_state_locked(
        self,
        shard_index: int,
        now: float,
        *,
        restarting: bool,
    ) -> bool:
        current = self.worker_restart_started_at.get(shard_index)
        if restarting:
            if current is None:
                self.worker_restart_started_at[shard_index] = now
                return self._refresh_idle_state_locked(shard_index, now) or True
            return self._refresh_idle_state_locked(shard_index, now)
        if current is not None:
            self.worker_restart_total_sec[shard_index] = self.worker_restart_total_sec.get(
                shard_index,
                0.0,
            ) + max(0.0, now - current)
            self.worker_restart_started_at[shard_index] = None
            return self._refresh_idle_state_locked(shard_index, now) or True
        return self._refresh_idle_state_locked(shard_index, now)

    def _set_worker_state_locked(
        self,
        shard_index: int,
        state: str,
        now: float,
        case_name: str | None = None,
    ) -> bool:
        changed = self.worker_states.get(shard_index) != state
        self.worker_states[shard_index] = state
        if state == "active":
            if case_name is not None and self.active_cases.get(shard_index) != case_name:
                self.active_cases[shard_index] = case_name
                changed = True
        else:
            if shard_index in self.active_cases:
                self.active_cases.pop(shard_index, None)
                changed = True
        changed = self._refresh_idle_state_locked(shard_index, now) or changed
        return changed

    def consume(self, shard_index: int, lines: list[str], now: float) -> str | None:
        changed = False
        with self.lock:
            for line in lines:
                if COMPETITION_SCRIPT_WATCHDOG_RE.search(line):
                    continue
                run_match = LTP_RUN_LINE_RE.match(line)
                if run_match:
                    changed = self._set_restart_state_locked(
                        shard_index,
                        now,
                        restarting=False,
                    ) or changed
                    changed = self._mark_finished_locked(self.active_cases.get(shard_index)) or changed
                    changed = self._set_worker_state_locked(
                        shard_index,
                        "active",
                        now,
                        run_match.group(1),
                    ) or changed
                    continue
                heartbeat_match = LTP_HEARTBEAT_LINE_RE.match(line)
                if heartbeat_match:
                    heartbeat_case = heartbeat_match.group(1)
                    changed = self._set_restart_state_locked(
                        shard_index,
                        now,
                        restarting=False,
                    ) or changed
                    if heartbeat_case:
                        changed = self._set_worker_state_locked(
                            shard_index,
                            "active",
                            now,
                            heartbeat_case,
                        ) or changed
                    continue
                if line.startswith("#### OS COMP TEST GROUP END ") or QEMU_TERMINATING_LINE_RE.match(line):
                    changed = self._mark_finished_locked(self.active_cases.pop(shard_index, None)) or changed
                    changed = self._set_worker_state_locked(shard_index, "switching", now) or changed
                    continue
                pass_match = LTP_PASS_LINE_RE.match(line)
                legacy_ok_match = LTP_LEGACY_OK_LINE_RE.match(line)
                fail_match = LTP_FAIL_LINE_RE.match(line)
                skip_match = LTP_SKIP_LINE_RE.match(line)
                case_name: str | None = None
                passed = False
                if pass_match:
                    case_name = pass_match.group(1)
                    passed = True
                elif legacy_ok_match:
                    case_name = legacy_ok_match.group(1)
                    passed = True
                elif fail_match:
                    case_name = fail_match.group(1)
                elif skip_match:
                    case_name = skip_match.group(1)
                if case_name is None:
                    continue
                changed = self._mark_finished_locked(case_name, passed=passed) or changed
                changed = self._set_worker_state_locked(shard_index, "switching", now) or changed
            if changed:
                self._render(now)
        return None

    def poll(self, now: float) -> str | None:
        snapshot_lines: list[str] = []
        with self.lock:
            self._render(now)
            snapshot_lines = self._maybe_console_snapshot_lines_locked(now)
        if snapshot_lines:
            emit_console_lines(snapshot_lines, rerender=False)
        return None

    def mark_stalled_case(self, shard_index: int, case_name: str) -> None:
        with self.lock:
            now = time.monotonic()
            self._mark_finished_locked(case_name)
            self._set_worker_state_locked(shard_index, "switching", now)
            self._set_restart_state_locked(shard_index, now, restarting=True)
            if case_name not in self.finished_cases:
                self.finished_cases.add(case_name)
            self._render(now)

    def mark_worker_booting(self, shard_index: int, *, restarting: bool = False) -> None:
        with self.lock:
            now = time.monotonic()
            self._set_worker_state_locked(shard_index, "booting", now)
            self._set_restart_state_locked(shard_index, now, restarting=restarting)
            self._render(now)

    def mark_worker_switching(self, shard_index: int, *, restarting: bool = False) -> None:
        with self.lock:
            now = time.monotonic()
            self._set_worker_state_locked(shard_index, "switching", now)
            self._set_restart_state_locked(shard_index, now, restarting=restarting)
            self._render(now)

    def mark_worker_idle(self, shard_index: int) -> None:
        with self.lock:
            now = time.monotonic()
            self._set_worker_state_locked(shard_index, "idle", now)
            self._set_restart_state_locked(shard_index, now, restarting=False)
            self._render(now)

    def mark_shard_completed(self, shard_index: int) -> None:
        with self.lock:
            now = time.monotonic()
            self._set_worker_state_locked(shard_index, "completed", now)
            self._set_restart_state_locked(shard_index, now, restarting=False)
            self.completed_shards.add(shard_index)
            self._render(now)

    def clear(self) -> None:
        set_live_status_renderer(self, None)


def emit_console_lines(
    messages: Iterable[str],
    *,
    err: bool = False,
    rerender: bool = True,
) -> None:
    clear_live_line()
    for message in messages:
        safe_print(message, err=err)
        append_transcript_line(message)
    if rerender:
        rerender_live_status()


def console(message: str, *, err: bool = False) -> None:
    emit_console_lines([message], err=err, rerender=True)


def relative_path(path: Path) -> Path:
    try:
        return path.relative_to(ROOT)
    except ValueError:
        return path


def tail_lines(path: Path, count: int = TAIL_LINES) -> list[str]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [sanitize_line(line) for line in lines[-count:]]


def emit_log_tail(label: str, path: Path, *, count: int = TAIL_LINES, err: bool = True) -> None:
    lines = tail_lines(path, count)
    if not lines:
        return
    console(f"[tail] {label}: {relative_path(path)}", err=err)
    for line in lines:
        console(line, err=err)


def emit_stage_log_refs(stage: str, path: Path, *, err: bool = True) -> None:
    console(f"[logs] {stage}: {relative_path(path)}", err=err)
    for suffix in [".configure.log", ".warnings.log"]:
        extra = path.with_suffix(suffix)
        if extra.exists() and extra.stat().st_size > 0:
            console(f"[logs] {stage}: {relative_path(extra)}", err=err)


def write_filtered_log(src: Path, dst: Path, predicate: Callable[[str], bool]) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    matched = []
    for raw in src.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = sanitize_line(raw)
        if predicate(line):
            matched.append(line)
    dst.write_text("\n".join(matched) + ("\n" if matched else ""), encoding="utf-8")


def extract_side_logs(stage_log: Path) -> None:
    write_filtered_log(stage_log, stage_log.with_suffix(".warnings.log"), lambda line: bool(WARNING_RE.search(line)))
    write_filtered_log(stage_log, stage_log.with_suffix(".configure.log"), lambda line: bool(CONFIGURE_RE.search(line)))


def run_logged_command(
    cmd: list[str],
    *,
    cwd: Path,
    log_path: Path,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
    fatal_idle_timeout: float | None = None,
    silent_idle_timeout: float | None = SILENT_IDLE_TIMEOUT,
    pre_output_idle_timeout: float | None = None,
    on_output: Callable[[list[str], float], str | None] | None = None,
    on_poll: Callable[[float], str | None] | None = None,
    suppress_live_log: bool = False,
) -> tuple[int | None, bool, str | None]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    tty_state = capture_tty_state()
    with log_path.open("w", encoding="utf-8", errors="ignore") as log_file:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            text=True,
        )
        register_active_child_proc(proc)
        start = time.monotonic()
        last_size = 0
        read_offset = 0
        partial_line = ""
        last_progress_at = start
        fatal_seen_at: float | None = None
        fatal_reason: str | None = None
        try:
            while True:
                returncode = proc.poll()
                if not suppress_live_log:
                    refresh_live_line(log_path)
                try:
                    size = log_path.stat().st_size
                except FileNotFoundError:
                    size = 0
                if size != last_size:
                    last_size = size
                    now = time.monotonic()
                    last_progress_at = now
                    read_offset, partial_line, new_lines = read_appended_log_lines(log_path, read_offset, partial_line)
                    if on_output is not None and new_lines:
                        stop_reason = on_output(new_lines, now)
                        if stop_reason is not None:
                            terminate_process_group(proc)
                            clear_live_line()
                            restore_tty_state(tty_state)
                            return None, True, stop_reason
                    reason = fatal_log_reason(read_recent_log_lines(log_path))
                    if reason is not None:
                        fatal_seen_at = now
                        fatal_reason = reason
                if returncode is not None:
                    read_offset, partial_line, new_lines = read_appended_log_lines(log_path, read_offset, partial_line)
                    if partial_line:
                        new_lines.append(sanitize_line(partial_line))
                    if on_output is not None and new_lines:
                        stop_reason = on_output(new_lines, time.monotonic())
                        if stop_reason is not None:
                            clear_live_line()
                            restore_tty_state(tty_state)
                            return None, True, stop_reason
                    clear_live_line()
                    restore_tty_state(tty_state)
                    unregister_active_child_proc(proc)
                    return returncode, False, None
                if on_poll is not None:
                    stop_reason = on_poll(time.monotonic())
                    if stop_reason is not None:
                        terminate_process_group(proc)
                        clear_live_line()
                        restore_tty_state(tty_state)
                        return None, True, stop_reason
                if timeout is not None and time.monotonic() - start > timeout:
                    terminate_process_group(proc)
                    clear_live_line()
                    restore_tty_state(tty_state)
                    return None, True, f"timeout after {timeout}s"
                if (
                    pre_output_idle_timeout is not None
                    and size == 0
                    and time.monotonic() - start > pre_output_idle_timeout
                ):
                    terminate_process_group(proc)
                    clear_live_line()
                    restore_tty_state(tty_state)
                    return (
                        None,
                        True,
                        f"silent boot stall after {pre_output_idle_timeout:.0f}s before first log line",
                    )
                if (
                    silent_idle_timeout is not None
                    and size > 0
                    and time.monotonic() - last_progress_at > silent_idle_timeout
                ):
                    terminate_process_group(proc)
                    clear_live_line()
                    restore_tty_state(tty_state)
                    return None, True, f"silent log stall after {silent_idle_timeout:.0f}s idle"
                if (
                    fatal_idle_timeout is not None
                    and fatal_seen_at is not None
                    and time.monotonic() - last_progress_at > fatal_idle_timeout
                ):
                    terminate_process_group(proc)
                    clear_live_line()
                    restore_tty_state(tty_state)
                    return None, True, f"fatal log stall after {fatal_reason} ({fatal_idle_timeout:.0f}s idle)"
                time.sleep(LIVE_POLL_INTERVAL)
        except KeyboardInterrupt:
            terminate_process_group(proc)
            clear_live_line()
            restore_tty_state(tty_state)
            raise
        finally:
            unregister_active_child_proc(proc)


def require_logged_success(
    stage: str,
    cmd: list[str],
    *,
    cwd: Path,
    log_path: Path,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
    show_tail_on_failure: bool = False,
) -> None:
    started_at = begin_stage(stage)
    returncode, timed_out, stop_reason = run_logged_command(
        cmd,
        cwd=cwd,
        log_path=log_path,
        env=env,
        timeout=timeout,
        fatal_idle_timeout=FATAL_IDLE_TIMEOUT,
    )
    finish_stage(stage, started_at)
    extract_side_logs(log_path)
    if timed_out:
        console(f"[timeout] {stage}: {stop_reason or f'exceeded {timeout}s'}", err=True)
        if show_tail_on_failure:
            emit_log_tail(stage, log_path)
        emit_stage_log_refs(stage, log_path)
        raise RuntimeError(f"{stage}: {stop_reason or f'exceeded {timeout}s'}")
    if returncode != 0:
        console(f"[fail] {stage} exited with code {returncode}", err=True)
        if show_tail_on_failure:
            emit_log_tail(stage, log_path)
        emit_stage_log_refs(stage, log_path)
        raise RuntimeError(f"{stage} failed, see {relative_path(log_path)}")


def extract_group(full_text: str, group: str) -> list[str]:
    start = f"#### OS COMP TEST GROUP START {group} ####"
    end = f"#### OS COMP TEST GROUP END {group} ####"
    inside = False
    lines: list[str] = []
    for raw in full_text.split("\n"):
        line = sanitize_line(raw)
        if not inside:
            if line == start:
                inside = True
            continue
        if line == end:
            return lines
        lines.append(line)
    fail(f"missing group markers for {group}")


def extract_group_with_status(full_text: str, group: str) -> tuple[list[str], str]:
    start = f"#### OS COMP TEST GROUP START {group} ####"
    end = f"#### OS COMP TEST GROUP END {group} ####"
    inside = False
    lines: list[str] = []
    for raw in full_text.split("\n"):
        line = sanitize_line(raw)
        if not inside:
            if line == start:
                inside = True
            continue
        marker_match = OFFICIAL_GROUP_MARKER_RE.search(line)
        if marker_match:
            phase, nested_group, nested_runtime = marker_match.groups()
            nested_name = f"{nested_group}-{nested_runtime}"
            if phase == "END" and nested_name == group:
                return lines, "complete"
            if phase == "START":
                return lines, "partial"
        if line == end:
            return lines, "complete"
        lines.append(line)
    if inside:
        return lines, "partial"
    return [], "missing"


def find_competition_script_watchdog_reason(full_text: str) -> str | None:
    for raw in reversed(full_text.split("\n")):
        line = sanitize_line(raw)
        if COMPETITION_SCRIPT_WATCHDOG_RE.search(line):
            return line
    return None


def expected_shell_cases(path: Path, func_name: str) -> list[str]:
    cases: list[str] = []
    pattern = re.compile(rf'^\s*{re.escape(func_name)}\s+"?([A-Z0-9_]+)"?')
    for line in read_text(path).splitlines():
        match = pattern.match(line)
        if match:
            cases.append(match.group(1))
    return cases


def find_line_index(lines: list[str], needle: str, start: int = 0) -> int:
    for index in range(start, len(lines)):
        if lines[index] == needle:
            return index
    return -1


def find_line_with_prefix(lines: list[str], prefix: str, start: int = 0) -> int:
    for index in range(start, len(lines)):
        if lines[index].startswith(prefix):
            return index
    return -1


def parse_first_number(line: str) -> float:
    match = re.search(r"(-?\d+(?:\.\d+)?)", line)
    if not match:
        fail(f"missing numeric value in line: {line}")
    return float(match.group(1))


def parse_basic_details(full_log: Path) -> list[DetailRow]:
    runner = TESTSUITS_ROOT / "basic/user/src/oscomp/test_runner.py"
    proc = subprocess.run(
        ["python3", str(runner), str(full_log)],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    data = json.loads(proc.stdout)
    return [
        DetailRow(name=item["name"], passed=item["passed"], total=item["all"], status="ok" if item["passed"] == item["all"] else "fail")
        for item in data
    ]


def parse_busybox_details(lines: list[str]) -> list[DetailRow]:
    cmd_file = TESTSUITS_ROOT / "scripts/busybox/busybox_cmd.txt"
    commands = [line.strip() for line in read_text(cmd_file).splitlines() if line.strip()]
    details: list[DetailRow] = []
    for command in commands:
        normalized = re.sub(r"\\(.)", r"\1", command)
        success_tokens = {
            f"testcase busybox {command} success",
            f"testcase busybox {normalized} success",
        }
        passed = int(any(any(token in line for token in success_tokens) for line in lines))
        details.append(DetailRow(name=f"busybox {command}", passed=passed, total=1, status="ok" if passed else "fail"))
    return details


def parse_lua_details(lines: list[str]) -> list[DetailRow]:
    path = TESTSUITS_ROOT / "scripts/lua/lua_testcode.sh"
    scripts = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("./test.sh "):
            scripts.append(stripped.split(maxsplit=1)[1])
    details: list[DetailRow] = []
    for script in scripts:
        success_token = f"testcase lua {script} success"
        passed = int(any(success_token in line for line in lines))
        details.append(DetailRow(name=script, passed=passed, total=1, status="ok" if passed else "fail"))
    return details


def parse_iozone_details(lines: list[str]) -> list[DetailRow]:
    labels = []
    path = TESTSUITS_ROOT / "scripts/iozone/iozone_testcode.sh"
    for line in read_text(path).splitlines():
        if "./busybox echo " in line:
            label = line.split("./busybox echo ", 1)[1].strip().strip('"')
            if label.startswith("####"):
                continue
            labels.append(label)

    positions: list[int] = []
    for label in labels:
        idx = find_line_index(lines, label)
        if idx < 0:
            fail(f"iozone missing label: {label}")
        positions.append(idx)

    details: list[DetailRow] = []
    for index, label in enumerate(labels):
        start = positions[index] + 1
        end = positions[index + 1] if index + 1 < len(positions) else len(lines)
        body = [line for line in lines[start:end] if line.strip()]
        has_output = any(re.search(r"\d", line) for line in body)
        details.append(DetailRow(name=label, passed=int(has_output), total=1, status="ok" if has_output else "fail"))
    return details


def parse_iperf_details(lines: list[str]) -> list[DetailRow]:
    tests = expected_shell_cases(TESTSUITS_ROOT / "scripts/iperf/iperf_testcode.sh", "run_iperf")
    details: list[DetailRow] = []
    pos = 0
    for name in tests:
        begin = f"====== iperf {name} begin ======"
        end = f"====== iperf {name} end: success ======"
        begin_idx = find_line_index(lines, begin, pos)
        end_idx = find_line_index(lines, end, begin_idx + 1 if begin_idx >= 0 else 0)
        passed = begin_idx >= 0 and end_idx >= 0 and any(line.startswith("[") for line in lines[begin_idx + 1:end_idx])
        details.append(DetailRow(name=name, passed=int(passed), total=1, status="ok" if passed else "fail"))
        if end_idx >= 0:
            pos = end_idx + 1
    return details


def expected_libcbench_labels() -> list[str]:
    path = TESTSUITS_ROOT / "libc-bench/main.c"
    labels: list[str] = []
    pattern = re.compile(r"^\s*RUN\(([^,]+),\s*(.+)\);\s*$")
    for line in read_text(path).splitlines():
        match = pattern.match(line)
        if not match:
            continue
        labels.append(f"{match.group(1).strip()} ({match.group(2).strip()})")
    return labels


def parse_libcbench_details(lines: list[str]) -> list[DetailRow]:
    labels = expected_libcbench_labels()
    details: list[DetailRow] = []
    pos = 0
    for label in labels:
        idx = find_line_index(lines, label, pos)
        time_idx = find_line_with_prefix(lines, "  time:", idx + 1 if idx >= 0 else 0)
        passed = idx >= 0 and time_idx >= 0
        details.append(DetailRow(name=label, passed=int(passed), total=1, status="ok" if passed else "fail"))
        if time_idx >= 0:
            pos = time_idx + 1
    return details


LMBENCH_HEADERS = [
    "latency measurements",
    "file system latency",
    "Bandwidth measurements",
    "context switch overhead",
]

LMBENCH_LABELED_RULES = [
    ("Simple syscall:", ("Simple syscall:",)),
    ("Simple read:", ("Simple read:",)),
    ("Simple write:", ("Simple write:",)),
    ("Simple stat:", ("Simple stat:",)),
    ("Simple fstat:", ("Simple fstat:",)),
    ("Simple open/close:", ("Simple open/close:",)),
    ("Select on file:", ("Select on file:", "Select on 100 fd's:", "Select on 100 fd:")),
    ("Signal handler installation:", ("Signal handler installation:",)),
    ("Signal handler overhead:", ("Signal handler overhead:",)),
    ("Protection fault:", ("Protection fault:",)),
    ("Pipe latency:", ("Pipe latency:",)),
    ("Process fork+exit:", ("Process fork+exit:",)),
    ("Process fork+execve:", ("Process fork+execve:",)),
    ("Process fork+/bin/sh -c:", ("Process fork+/bin/sh -c:",)),
    ("File /var/tmp/XXX write bandwidth:", ("File /var/tmp/XXX write bandwidth:",)),
]

LMBENCH_BANDWIDTH_DETAIL_NAMES = [
    "File /var/tmp/XXX read bandwidth:",
    "File /var/tmp/XXX read open2close bandwidth:",
    "Mmap read bandwidth:",
    "Mmap read open2close bandwidth:",
]

LMBENCH_RAW_VALUE_RE = re.compile(r"^\d+(?:\.\d+)?\s+\d+(?:\.\d+)?$")
LMBENCH_ZERO_DETAIL_NAMES = [
    *(name for name, _ in LMBENCH_LABELED_RULES),
    "Pagefaults on /var/tmp/XXX:",
    "Mmap latency:",
    "File system create+delete:",
    "Pipe bandwidth:",
    *LMBENCH_BANDWIDTH_DETAIL_NAMES,
    "96p/32K ctxsw:",
]


def parse_lmbench_details(lines: list[str]) -> list[DetailRow]:
    header_positions: list[int] = []
    pos = 0
    for header in LMBENCH_HEADERS:
        idx = find_line_index(lines, header, pos)
        if idx < 0:
            fail(f"lmbench missing section header: {header}")
        header_positions.append(idx)
        pos = idx + 1

    latency_lines = lines[header_positions[0] + 1:header_positions[1]]
    fs_lines = lines[header_positions[1] + 1:header_positions[2]]
    bandwidth_lines = lines[header_positions[2] + 1:header_positions[3]]
    ctx_lines = lines[header_positions[3] + 1:]

    def find_prefixed_line(section: list[str], prefixes: tuple[str, ...]) -> str | None:
        for line in section:
            if any(line.startswith(prefix) for prefix in prefixes):
                return line
        return None

    def parse_positive_value(line: str, prefixes: tuple[str, ...]) -> bool:
        for prefix in prefixes:
            if line.startswith(prefix):
                return parse_first_number(line[len(prefix):]) > 0
        return False

    def parse_raw_second_value(line: str) -> float:
        parts = line.split()
        if len(parts) < 2:
            fail(f"lmbench raw line malformed: {line}")
        return float(parts[1])

    details: list[DetailRow] = []
    for name, prefixes in LMBENCH_LABELED_RULES:
        line = find_prefixed_line(latency_lines, prefixes)
        passed = line is not None and parse_positive_value(line, prefixes)
        details.append(DetailRow(name=name, passed=int(passed), total=1, status="ok" if passed else "fail"))

    pagefault_line = find_prefixed_line(latency_lines, ("Pagefaults on /var/tmp/XXX:",))
    if pagefault_line is not None:
        passed = parse_positive_value(pagefault_line, ("Pagefaults on /var/tmp/XXX:",))
        details.append(
            DetailRow(
                name="Pagefaults on /var/tmp/XXX:",
                passed=int(passed),
                total=1,
                status="ok" if passed else "fail",
            )
        )

    latency_raw_lines = [line for line in latency_lines if LMBENCH_RAW_VALUE_RE.fullmatch(line)]
    mmap_passed = bool(latency_raw_lines) and parse_raw_second_value(latency_raw_lines[-1]) > 0
    details.append(
        DetailRow(name="Mmap latency:", passed=int(mmap_passed), total=1, status="ok" if mmap_passed else "fail")
    )

    fs_rows = {}
    for line in fs_lines:
        parts = line.split()
        if len(parts) == 4 and parts[0] in {"0k", "1k", "4k", "10k"}:
            try:
                values = [float(part) for part in parts[1:]]
            except ValueError:
                continue
            fs_rows[parts[0]] = values
    fs_passed = len(fs_rows) == 4 and all(all(value > 0 for value in row) for row in fs_rows.values())
    details.append(
        DetailRow(
            name="File system create+delete:",
            passed=int(fs_passed),
            total=1,
            status="ok" if fs_passed else "fail",
        )
    )

    pipe_bandwidth_line = find_prefixed_line(bandwidth_lines, ("Pipe bandwidth:",))
    pipe_bandwidth_passed = pipe_bandwidth_line is not None and parse_positive_value(
        pipe_bandwidth_line, ("Pipe bandwidth:",)
    )
    details.append(
        DetailRow(
            name="Pipe bandwidth:",
            passed=int(pipe_bandwidth_passed),
            total=1,
            status="ok" if pipe_bandwidth_passed else "fail",
        )
    )

    bandwidth_raw_lines = [line for line in bandwidth_lines if LMBENCH_RAW_VALUE_RE.fullmatch(line)]
    for index, name in enumerate(LMBENCH_BANDWIDTH_DETAIL_NAMES):
        passed = index < len(bandwidth_raw_lines) and parse_raw_second_value(bandwidth_raw_lines[index]) > 0
        details.append(DetailRow(name=name, passed=int(passed), total=1, status="ok" if passed else "fail"))

    ctx_value = None
    for line in ctx_lines:
        parts = line.split()
        if len(parts) == 2 and parts[0] == "96":
            try:
                ctx_value = float(parts[1])
            except ValueError:
                ctx_value = None
            break
    ctx_passed = ctx_value is not None and ctx_value > 0
    details.append(DetailRow(name="96p/32K ctxsw:", passed=int(ctx_passed), total=1, status="ok" if ctx_passed else "fail"))
    return details


def parse_netperf_details(lines: list[str]) -> list[DetailRow]:
    tests = expected_shell_cases(TESTSUITS_ROOT / "scripts/netperf/netperf_testcode.sh", "run_netperf")
    details: list[DetailRow] = []
    pos = 0
    for name in tests:
        begin = f"====== netperf {name} begin ======"
        end = f"====== netperf {name} end: success ======"
        begin_idx = find_line_index(lines, begin, pos)
        end_idx = find_line_index(lines, end, begin_idx + 1 if begin_idx >= 0 else 0)
        passed = begin_idx >= 0 and end_idx >= 0 and any(
            "Throughput" in line or "per sec" in line
            for line in lines[begin_idx + 1:end_idx]
        )
        details.append(DetailRow(name=name, passed=int(passed), total=1, status="ok" if passed else "fail"))
        if end_idx >= 0:
            pos = end_idx + 1
    return details


def parse_cyclictest_details(lines: list[str]) -> list[DetailRow]:
    tests = expected_shell_cases(TESTSUITS_ROOT / "scripts/cyclictest/cyclictest_testcode.sh", "run_cyclictest")
    details: list[DetailRow] = []
    pos = 0
    for name in tests:
        begin = f"====== cyclictest {name} begin ======"
        end = f"====== cyclictest {name} end: success ======"
        begin_idx = find_line_index(lines, begin, pos)
        end_idx = find_line_index(lines, end, begin_idx + 1 if begin_idx >= 0 else 0)
        minimum = 8 if name.endswith("P8") else 1
        thread_lines = [line for line in lines[begin_idx + 1:end_idx] if line.startswith("T:")] if begin_idx >= 0 and end_idx >= 0 else []
        passed = begin_idx >= 0 and end_idx >= 0 and len(thread_lines) >= minimum
        details.append(DetailRow(name=name, passed=int(passed), total=1, status="ok" if passed else "fail"))
        if end_idx >= 0:
            pos = end_idx + 1
    hackbench_start = find_line_index(lines, "====== start hackbench ======") >= 0
    hackbench_kill = find_line_index(lines, "====== kill hackbench: success ======") >= 0
    details.append(DetailRow(name="hackbench_start", passed=int(hackbench_start), total=1, status="ok" if hackbench_start else "fail"))
    details.append(DetailRow(name="hackbench_stop", passed=int(hackbench_kill), total=1, status="ok" if hackbench_kill else "fail"))
    return details


def expected_ltp_cases() -> list[str]:
    if LTP_EXPECTED_CASES_OVERRIDE is not None:
        return list(LTP_EXPECTED_CASES_OVERRIDE)
    path = LTP_RUNTEST_PATH
    cases: list[str] = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cases.append(stripped.split()[0])
    return cases


def parse_ltp_details_for_cases(lines: list[str], cases: list[str]) -> list[DetailRow]:
    details: list[DetailRow] = []
    pos = 0
    for name in cases:
        run_line = f"RUN LTP CASE {name}"
        run_idx = find_line_index(lines, run_line, pos)
        search_pos = run_idx + 1 if run_idx >= 0 else 0
        pass_idx = find_line_index(lines, f"PASS LTP CASE {name} : 0", search_pos)
        skip_idx = find_line_with_prefix(lines, f"SKIP LTP CASE {name} : ", search_pos)
        legacy_ok_idx = find_line_index(lines, f"FAIL LTP CASE {name} : 0", search_pos)
        ok_idx = pass_idx if pass_idx >= 0 else legacy_ok_idx
        if run_idx >= 0 and skip_idx >= 0 and (ok_idx < 0 or skip_idx < ok_idx):
            details.append(DetailRow(name=name, passed=0, total=0, status="skip"))
            pos = skip_idx + 1
            continue
        passed = run_idx >= 0 and ok_idx >= 0
        details.append(DetailRow(name=name, passed=int(passed), total=1, status="ok" if passed else "fail"))
        if ok_idx >= 0:
            pos = ok_idx + 1
    return details


def ltp_terminal_for_block(case_name: str, block: list[str]) -> list[str]:
    failed: int | None = None
    broken: int | None = None
    skipped: int | None = None
    in_summary = False
    for raw in block:
        line = sanitize_line(raw).strip()
        if line == "Summary:":
            in_summary = True
            continue
        if not in_summary:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            value = int(parts[1])
        except ValueError:
            continue
        if parts[0] == "failed":
            failed = value
        elif parts[0] == "broken":
            broken = value
        elif parts[0] == "skipped":
            skipped = value

    if failed == 0 and broken == 0:
        if skipped is not None and skipped > 0:
            return [f"SKIP LTP CASE {case_name} : 32"]
        return [
            f"PASS LTP CASE {case_name} : 0",
            f"FAIL LTP CASE {case_name} : 0",
        ]
    return [f"FAIL LTP CASE {case_name} : 1"]


def ltp_line_is_terminal_for_case(line: str, case_name: str) -> bool:
    return (
        line == f"PASS LTP CASE {case_name} : 0"
        or line == f"FAIL LTP CASE {case_name} : 0"
        or line.startswith(f"FAIL LTP CASE {case_name} : ")
        or line.startswith(f"SKIP LTP CASE {case_name} : ")
    )


def normalize_ltp_case_terminals(text: str) -> tuple[str, bool]:
    lines = text.splitlines()
    normalized: list[str] = []
    changed = False
    index = 0
    while index < len(lines):
        line = sanitize_line(lines[index])
        normalized.append(line)
        run_match = LTP_RUN_LINE_RE.match(line)
        if run_match is None:
            index += 1
            continue

        case_name = run_match.group(1)
        block: list[str] = []
        has_terminal = False
        index += 1
        while index < len(lines):
            next_line = sanitize_line(lines[index])
            if LTP_RUN_LINE_RE.match(next_line) or next_line.startswith("#### OS COMP TEST GROUP END "):
                break
            if ltp_line_is_terminal_for_case(next_line, case_name):
                has_terminal = True
            block.append(next_line)
            normalized.append(next_line)
            index += 1

        if not has_terminal:
            normalized.extend(ltp_terminal_for_block(case_name, block))
            changed = True
    if not changed:
        return text, False
    return "\n".join(normalized).rstrip() + "\n", True


def normalize_ltp_log_file(path: Path) -> None:
    if not path.exists():
        return
    normalized, changed = normalize_ltp_case_terminals(path.read_text(encoding="utf-8", errors="ignore"))
    if changed:
        path.write_text(normalized, encoding="utf-8")


def parse_ltp_details(lines: list[str]) -> list[DetailRow]:
    return parse_ltp_details_for_cases(lines, expected_ltp_cases())


def expected_libctest_cases() -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []
    for mode, filename in [("static", "static.txt"), ("dynamic", "dynamic.txt")]:
        path = TESTSUITS_ROOT / "libc-test" / filename
        for line in read_text(path).splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            name = Path(stripped).stem.replace("-", "_")
            cases.append((mode, name))
    return cases


def parse_libctest_details(lines: list[str]) -> list[DetailRow]:
    details: list[DetailRow] = []
    pos = 0
    for mode, name in expected_libctest_cases():
        wrap = f"entry-{mode}.exe"
        start = f"========== START {wrap} {name} =========="
        end = f"========== END {wrap} {name} =========="
        start_idx = find_line_index(lines, start, pos)
        end_idx = find_line_index(lines, end, start_idx + 1 if start_idx >= 0 else 0)
        block = lines[start_idx + 1:end_idx] if start_idx >= 0 and end_idx >= 0 else []
        passed = start_idx >= 0 and end_idx >= 0 and all(not line.startswith("FAIL ") for line in block)
        details.append(DetailRow(name=f"{mode}:{name}", passed=int(passed), total=1, status="ok" if passed else "fail"))
        if end_idx >= 0:
            pos = end_idx + 1
    return details


DETAIL_PARSERS: dict[str, Callable[[list[str] | Path], list[DetailRow]]] = {
    "basic": lambda value: parse_basic_details(value if isinstance(value, Path) else fail("basic parser requires path")),
    "busybox": parse_busybox_details,
    "lua": parse_lua_details,
    "iozone": parse_iozone_details,
    "iperf": parse_iperf_details,
    "libcbench": parse_libcbench_details,
    "lmbench": parse_lmbench_details,
    "netperf": parse_netperf_details,
    "cyclictest": parse_cyclictest_details,
    "ltp": parse_ltp_details,
    "libctest": parse_libctest_details,
}


def parse_sample(sample: str) -> tuple[str, str, str]:
    group, runtime, arch = sample.split("-")
    return group, runtime, arch


def select_samples(subset: list[str] | None, *, skip_ltp: bool) -> list[str]:
    samples = list(subset or SAMPLE_ORDER)
    if skip_ltp:
        samples = [sample for sample in samples if parse_sample(sample)[0] != "ltp"]
    return samples


def official_execution_key(sample: str) -> tuple[int, int]:
    group, runtime, _ = parse_sample(sample)
    return (RUNTIME_ORDER.index(runtime), GROUP_ORDER.index(group))


def parse_completed_samples_from_resume_log(path: Path) -> set[str]:
    if not path.exists():
        return set()
    completed: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = sanitize_line(raw)
        case_match = OFFICIAL_CASE_LINE_RE.match(line)
        if case_match:
            runtime, arch, group, _ = case_match.groups()
            sample = f"{group}-{runtime}-{arch}"
            if sample in SAMPLE_ORDER:
                completed.add(sample)
            continue
        for pattern in [FAILED_SAMPLE_LINE_RE, TIMED_OUT_SAMPLE_LINE_RE]:
            match = pattern.match(line)
            if match and match.group(1) in SAMPLE_ORDER:
                completed.add(match.group(1))
                break
    return completed


def load_validated_results(samples: list[str], logs_dir: Path) -> dict[str, CaseResult]:
    results: dict[str, CaseResult] = {}
    for sample in samples:
        log_path = logs_dir / f"{sample}.out"
        if not log_path.exists() or log_path.stat().st_size == 0:
            continue
        try:
            results[sample] = validate_case(sample, log_path)
        except Exception:
            continue
    return results


LTP_TESTCODE_SCRIPT_TEMPLATE = """#!/bin/bash

echo "#### OS COMP TEST GROUP START ltp ####"

target_dir="__OSK_LTP_TARGET_DIR__"
ltp_root="__OSK_LTP_ROOT__"
PATH="__OSK_LTP_SEARCH_PATH__"
export PATH
export LTPROOT="$ltp_root"
export LIBRARY_PATH="__OSK_LTP_LIBRARY_PATH__"
export LD_LIBRARY_PATH="__OSK_LTP_LIBRARY_PATH__"
: "${LTP_TIMEOUT_MUL:=__OSK_LTP_TIMEOUT_MUL__}"
export LTP_TIMEOUT_MUL
: "${LTP_RUNTIME_MUL:=__OSK_LTP_RUNTIME_MUL__}"
export LTP_RUNTIME_MUL
: "${LTP_CASE_TIMEOUT_SEC:=__OSK_LTP_CASE_TIMEOUT_SEC__}"
export LTP_CASE_TIMEOUT_SEC

ltp_ts_now() {
  local up rest
  if IFS=' ' read -r up rest < /proc/uptime 2>/dev/null; then
    printf '%s' "$up"
  else
    printf '0.00'
  fi
}

ltp_emit_ts() {
  local case_name="$1"
  local phase="$2"
  echo "[ltp-ts $(ltp_ts_now)] case=$case_name phase=$phase"
}

ltp_emit_log_file() {
  local log_file_path="$1"
  local line prev_line repeat_count=0 has_prev=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$has_prev" -eq 1 ] && [ "$line" = "$prev_line" ]; then
      repeat_count=$((repeat_count + 1))
      continue
    fi
    if [ "$has_prev" -eq 1 ]; then
      echo "$prev_line"
      if [ "$repeat_count" -gt 0 ]; then
        echo "[ltp-repeat] previous line repeated $repeat_count times"
      fi
    fi
    prev_line="$line"
    repeat_count=0
    has_prev=1
  done < "$log_file_path"
  if [ "$has_prev" -eq 1 ]; then
    echo "$prev_line"
    if [ "$repeat_count" -gt 0 ]; then
      echo "[ltp-repeat] previous line repeated $repeat_count times"
    fi
  fi
}

run_ltp_case() {
  local case_name="$1"
  shift
  local log_file="/tmp/.ltp_${case_name}_$$.log"
  local case_pid hb_pid watchdog_pid ret
  : > "$log_file"

  kill_case_session() {
    local sig="$1"
    kill "-$sig" "-$case_pid" 2>/dev/null || kill "-$sig" "$case_pid" 2>/dev/null || /busybox kill "-$sig" "-$case_pid" 2>/dev/null || /busybox kill "-$sig" "$case_pid" 2>/dev/null
  }

  (cd "$target_dir" && /busybox setsid "$@") >"$log_file" 2>&1 &
  case_pid=$!
  (
    while kill -0 "$case_pid" 2>/dev/null; do
      /busybox sleep __OSK_LTP_HEARTBEAT_INTERVAL_SEC__ 2>/dev/null || break
      kill -0 "$case_pid" 2>/dev/null || break
      echo "[ltp-heartbeat] $case_name"
    done
  ) &
  hb_pid=$!
  (
    /busybox sleep "$LTP_CASE_TIMEOUT_SEC" 2>/dev/null || exit 0
    if kill -0 "$case_pid" 2>/dev/null; then
      echo "[ltp-case-timeout] $case_name exceeded ${LTP_CASE_TIMEOUT_SEC}s"
      kill_case_session TERM
      /busybox sleep 2 2>/dev/null || true
      kill_case_session KILL
    fi
  ) &
  watchdog_pid=$!
  wait "$case_pid"
  ret=$?
  kill "$hb_pid" 2>/dev/null
  wait "$hb_pid" 2>/dev/null
  kill "$watchdog_pid" 2>/dev/null
  wait "$watchdog_pid" 2>/dev/null
  kill_case_session TERM
  kill_case_session KILL
  ltp_emit_log_file "$log_file"

  local failed=0 broken=0 skipped=0 in_summary=0 line
  while IFS= read -r line; do
    case "$line" in
      Summary:)
        in_summary=1
        ;;
      failed*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          failed=${2:-0}
        fi
        ;;
      broken*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          broken=${2:-0}
        fi
        ;;
      skipped*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          skipped=${2:-0}
        fi
        ;;
    esac
  done < "$log_file"
  ltp_emit_ts "$case_name" done

  if [ "$ret" -eq 0 ] && [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ]; then
    echo "PASS LTP CASE $case_name : 0"
    echo "FAIL LTP CASE $case_name : 0"
  elif [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ] && [ "$skipped" -gt 0 ]; then
    echo "SKIP LTP CASE $case_name : $ret"
  else
    echo "FAIL LTP CASE $case_name : $ret"
  fi
}

while IFS= read -r line; do
  case "$line" in
    ""|\\#*) continue ;;
  esac

  set -- $line
  name=$1
  shift

  ltp_emit_ts "$name" run
  echo "RUN LTP CASE $name"
  run_ltp_case "$name" "$@"
done < __OSK_LTP_RUNTEST_PATH__
echo "#### OS COMP TEST GROUP END ltp ####"
"""


LTP_DYNAMIC_TESTCODE_SCRIPT_TEMPLATE = """#!/bin/bash

echo "#### OS COMP TEST GROUP START ltp ####"

target_dir="__OSK_LTP_TARGET_DIR__"
ltp_root="__OSK_LTP_ROOT__"
PATH="__OSK_LTP_SEARCH_PATH__"
export PATH
export LTPROOT="$ltp_root"
export LIBRARY_PATH="__OSK_LTP_LIBRARY_PATH__"
export LD_LIBRARY_PATH="__OSK_LTP_LIBRARY_PATH__"
: "${LTP_TIMEOUT_MUL:=__OSK_LTP_TIMEOUT_MUL__}"
export LTP_TIMEOUT_MUL
: "${LTP_RUNTIME_MUL:=__OSK_LTP_RUNTIME_MUL__}"
export LTP_RUNTIME_MUL
: "${LTP_CASE_TIMEOUT_SEC:=__OSK_LTP_CASE_TIMEOUT_SEC__}"
export LTP_CASE_TIMEOUT_SEC

ltp_queue_url="__OSK_LTP_QUEUE_URL__"
ltp_worker_id="__OSK_LTP_WORKER_ID__"
ltp_queue_tmp="/tmp/.ltp_queue_${ltp_worker_id}_$$.txt"

ltp_ts_now() {
  local up rest
  if IFS=' ' read -r up rest < /proc/uptime 2>/dev/null; then
    printf '%s' "$up"
  else
    printf '0.00'
  fi
}

ltp_emit_ts() {
  local case_name="$1"
  local phase="$2"
  echo "[ltp-ts $(ltp_ts_now)] case=$case_name phase=$phase"
}

ltp_emit_log_file() {
  local log_file_path="$1"
  local line prev_line repeat_count=0 has_prev=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$has_prev" -eq 1 ] && [ "$line" = "$prev_line" ]; then
      repeat_count=$((repeat_count + 1))
      continue
    fi
    if [ "$has_prev" -eq 1 ]; then
      echo "$prev_line"
      if [ "$repeat_count" -gt 0 ]; then
        echo "[ltp-repeat] previous line repeated $repeat_count times"
      fi
    fi
    prev_line="$line"
    repeat_count=0
    has_prev=1
  done < "$log_file_path"
  if [ "$has_prev" -eq 1 ]; then
    echo "$prev_line"
    if [ "$repeat_count" -gt 0 ]; then
      echo "[ltp-repeat] previous line repeated $repeat_count times"
    fi
  fi
}

ltp_fetch_next_line() {
  : > "$ltp_queue_tmp"
  /busybox wget -q -O "$ltp_queue_tmp" "$ltp_queue_url&worker=$ltp_worker_id"
}

run_ltp_case() {
  local case_name="$1"
  shift
  local log_file="/tmp/.ltp_${case_name}_$$.log"
  local case_pid hb_pid watchdog_pid ret
  : > "$log_file"

  kill_case_session() {
    local sig="$1"
    kill "-$sig" "-$case_pid" 2>/dev/null || kill "-$sig" "$case_pid" 2>/dev/null || /busybox kill "-$sig" "-$case_pid" 2>/dev/null || /busybox kill "-$sig" "$case_pid" 2>/dev/null
  }

  (cd "$target_dir" && /busybox setsid "$@") >"$log_file" 2>&1 &
  case_pid=$!
  (
    while kill -0 "$case_pid" 2>/dev/null; do
      /busybox sleep __OSK_LTP_HEARTBEAT_INTERVAL_SEC__ 2>/dev/null || break
      kill -0 "$case_pid" 2>/dev/null || break
      echo "[ltp-heartbeat] $case_name"
    done
  ) &
  hb_pid=$!
  (
    /busybox sleep "$LTP_CASE_TIMEOUT_SEC" 2>/dev/null || exit 0
    if kill -0 "$case_pid" 2>/dev/null; then
      echo "[ltp-case-timeout] $case_name exceeded ${LTP_CASE_TIMEOUT_SEC}s"
      kill_case_session TERM
      /busybox sleep 2 2>/dev/null || true
      kill_case_session KILL
    fi
  ) &
  watchdog_pid=$!
  wait "$case_pid"
  ret=$?
  kill "$hb_pid" 2>/dev/null
  wait "$hb_pid" 2>/dev/null
  kill "$watchdog_pid" 2>/dev/null
  wait "$watchdog_pid" 2>/dev/null
  kill_case_session TERM
  kill_case_session KILL
  ltp_emit_log_file "$log_file"

  local failed=0 broken=0 skipped=0 in_summary=0 line
  while IFS= read -r line; do
    case "$line" in
      Summary:)
        in_summary=1
        ;;
      failed*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          failed=${2:-0}
        fi
        ;;
      broken*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          broken=${2:-0}
        fi
        ;;
      skipped*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          skipped=${2:-0}
        fi
        ;;
    esac
  done < "$log_file"
  ltp_emit_ts "$case_name" done

  if [ "$ret" -eq 0 ] && [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ]; then
    echo "PASS LTP CASE $case_name : 0"
    echo "FAIL LTP CASE $case_name : 0"
  elif [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ] && [ "$skipped" -gt 0 ]; then
    echo "SKIP LTP CASE $case_name : $ret"
  else
    echo "FAIL LTP CASE $case_name : $ret"
  fi
}

while true; do
  ltp_fetch_next_line
  fetch_status=$?
  if [ "$fetch_status" -ne 0 ]; then
    echo "[ltp-queue] fetch failed worker=$ltp_worker_id status=$fetch_status"
    /busybox sleep 1 2>/dev/null || break
    continue
  fi
  if IFS= read -r line < "$ltp_queue_tmp"; then
    :
  else
    line=""
  fi
  case "$line" in
    "" )
      echo "[ltp-queue] empty response worker=$ltp_worker_id"
      /busybox sleep 1 2>/dev/null || break
      continue
      ;;
    "__OSK_LTP_DONE__" )
      break
      ;;
    \\#* )
      continue
      ;;
  esac

  set -- $line
  name=$1
  shift

  ltp_emit_ts "$name" run
  echo "RUN LTP CASE $name"
  run_ltp_case "$name" "$@"
done
echo "#### OS COMP TEST GROUP END ltp ####"
"""


LTP_STDIN_TESTCODE_READY_MARKER = "[ltp-stdin] ready"


LTP_STDIN_TESTCODE_SCRIPT_TEMPLATE = """#!/bin/bash

echo "#### OS COMP TEST GROUP START ltp ####"

target_dir="__OSK_LTP_TARGET_DIR__"
ltp_root="__OSK_LTP_ROOT__"
PATH="__OSK_LTP_SEARCH_PATH__"
export PATH
export LTPROOT="$ltp_root"
export LIBRARY_PATH="__OSK_LTP_LIBRARY_PATH__"
export LD_LIBRARY_PATH="__OSK_LTP_LIBRARY_PATH__"
: "${LTP_TIMEOUT_MUL:=__OSK_LTP_TIMEOUT_MUL__}"
export LTP_TIMEOUT_MUL
: "${LTP_RUNTIME_MUL:=__OSK_LTP_RUNTIME_MUL__}"
export LTP_RUNTIME_MUL
: "${LTP_CASE_TIMEOUT_SEC:=__OSK_LTP_CASE_TIMEOUT_SEC__}"
export LTP_CASE_TIMEOUT_SEC

ltp_ts_now() {
  local up rest
  if IFS=' ' read -r up rest < /proc/uptime 2>/dev/null; then
    printf '%s' "$up"
  else
    printf '0.00'
  fi
}

ltp_emit_ts() {
  local case_name="$1"
  local phase="$2"
  echo "[ltp-ts $(ltp_ts_now)] case=$case_name phase=$phase"
}

ltp_emit_log_file() {
  local log_file_path="$1"
  local line prev_line repeat_count=0 has_prev=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$has_prev" -eq 1 ] && [ "$line" = "$prev_line" ]; then
      repeat_count=$((repeat_count + 1))
      continue
    fi
    if [ "$has_prev" -eq 1 ]; then
      echo "$prev_line"
      if [ "$repeat_count" -gt 0 ]; then
        echo "[ltp-repeat] previous line repeated $repeat_count times"
      fi
    fi
    prev_line="$line"
    repeat_count=0
    has_prev=1
  done < "$log_file_path"
  if [ "$has_prev" -eq 1 ]; then
    echo "$prev_line"
    if [ "$repeat_count" -gt 0 ]; then
      echo "[ltp-repeat] previous line repeated $repeat_count times"
    fi
  fi
}

run_ltp_case() {
  local case_name="$1"
  shift
  local log_file="/tmp/.ltp_${case_name}_$$.log"
  local case_pid hb_pid watchdog_pid ret
  : > "$log_file"

  kill_case_session() {
    local sig="$1"
    kill "-$sig" "-$case_pid" 2>/dev/null || kill "-$sig" "$case_pid" 2>/dev/null || /busybox kill "-$sig" "-$case_pid" 2>/dev/null || /busybox kill "-$sig" "$case_pid" 2>/dev/null
  }

  (cd "$target_dir" && /busybox setsid "$@") >"$log_file" 2>&1 &
  case_pid=$!
  (
    while kill -0 "$case_pid" 2>/dev/null; do
      /busybox sleep __OSK_LTP_HEARTBEAT_INTERVAL_SEC__ 2>/dev/null || break
      kill -0 "$case_pid" 2>/dev/null || break
      echo "[ltp-heartbeat] $case_name"
    done
  ) &
  hb_pid=$!
  (
    /busybox sleep "$LTP_CASE_TIMEOUT_SEC" 2>/dev/null || exit 0
    if kill -0 "$case_pid" 2>/dev/null; then
      echo "[ltp-case-timeout] $case_name exceeded ${LTP_CASE_TIMEOUT_SEC}s"
      kill_case_session TERM
      /busybox sleep 2 2>/dev/null || true
      kill_case_session KILL
    fi
  ) &
  watchdog_pid=$!
  wait "$case_pid"
  ret=$?
  kill "$hb_pid" 2>/dev/null
  wait "$hb_pid" 2>/dev/null
  kill "$watchdog_pid" 2>/dev/null
  wait "$watchdog_pid" 2>/dev/null
  kill_case_session TERM
  kill_case_session KILL
  ltp_emit_log_file "$log_file"

  local failed=0 broken=0 skipped=0 in_summary=0 line
  while IFS= read -r line; do
    case "$line" in
      Summary:)
        in_summary=1
        ;;
      failed*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          failed=${2:-0}
        fi
        ;;
      broken*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          broken=${2:-0}
        fi
        ;;
      skipped*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          skipped=${2:-0}
        fi
        ;;
    esac
  done < "$log_file"
  ltp_emit_ts "$case_name" done

  if [ "$ret" -eq 0 ] && [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ]; then
    echo "PASS LTP CASE $case_name : 0"
    echo "FAIL LTP CASE $case_name : 0"
  elif [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ] && [ "$skipped" -gt 0 ]; then
    echo "SKIP LTP CASE $case_name : $ret"
  else
    echo "FAIL LTP CASE $case_name : $ret"
  fi
}

while true; do
  echo "__OSK_LTP_STDIN_READY__"
  if ! IFS= read -r line; then
    break
  fi
  case "$line" in
    "" )
      continue
      ;;
    "__OSK_LTP_DONE__" )
      break
      ;;
    \\#* )
      continue
      ;;
  esac

  set -- $line
  name=$1
  shift

  ltp_emit_ts "$name" run
  echo "RUN LTP CASE $name"
  run_ltp_case "$name" "$@"
done
echo "#### OS COMP TEST GROUP END ltp ####"
"""


def ltp_runtime_root_name(rootfs_dir: Path) -> str | None:
    return rootfs_dir.name if rootfs_dir.name in RUNTIME_ORDER else None


def ltp_runtime_root_prefix(rootfs_dir: Path) -> str:
    runtime = ltp_runtime_root_name(rootfs_dir)
    return f"/{runtime}" if runtime else ""


def ltp_runtime_target_dir(rootfs_dir: Path) -> str:
    prefix = ltp_runtime_root_prefix(rootfs_dir)
    return f"{prefix}/ltp/testcases/bin" if prefix else "/ltp/testcases/bin"


def ltp_runtime_root_path(rootfs_dir: Path) -> str:
    prefix = ltp_runtime_root_prefix(rootfs_dir)
    return f"{prefix}/ltp" if prefix else "/ltp"


def ltp_runtime_search_path(rootfs_dir: Path) -> str:
    runtime = ltp_runtime_root_name(rootfs_dir)
    if runtime == "glibc":
        return "/glibc/bin:/glibc/sbin:/glibc/usr/bin:/glibc/usr/sbin:/glibc/ltp/testcases/bin:$PATH"
    if runtime == "musl":
        return "/musl/bin:/musl/sbin:/musl/usr/bin:/musl/usr/sbin:/musl/ltp/testcases/bin:$PATH"
    return "/bin:/sbin:/usr/bin:/usr/sbin:/ltp/testcases/bin:$PATH"


def ltp_runtime_library_path(rootfs_dir: Path) -> str:
    runtime = ltp_runtime_root_name(rootfs_dir)
    if runtime == "glibc":
        return "/glibc/lib:/glibc/lib64:/lib64:/lib"
    if runtime == "musl":
        return "/musl/lib:/musl/lib64:/lib64:/lib"
    return "/glibc/lib:/glibc/lib64:/musl/lib:/musl/lib64:/lib64:/lib"


def read_ltp_runtest_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def filter_ltp_runtest_lines(
    lines: list[str],
    selected_cases: list[str] | None = None,
    start_case: str | None = None,
) -> list[str]:
    if selected_cases and start_case:
        fail("--ltp-case cannot be combined with --ltp-start-case")
    if not selected_cases and not start_case:
        return lines
    by_name: dict[str, str] = {}
    ordered_names: list[str] = []
    for raw in lines:
        stripped = sanitize_line(raw).strip()
        if not stripped or stripped.startswith("#"):
            continue
        case_name = stripped.split()[0]
        by_name[case_name] = raw
        ordered_names.append(case_name)
    if selected_cases:
        missing = [case for case in selected_cases if case not in by_name]
        if missing:
            fail(f"unknown LTP cases: {', '.join(missing)}")
        return [by_name[case] for case in selected_cases]
    assert start_case is not None
    if start_case not in by_name:
        fail(f"unknown LTP start case: {start_case}")
    start_index = ordered_names.index(start_case)
    return [by_name[case] for case in ordered_names[start_index:]]


def ltp_case_names(
    selected_cases: list[str] | None = None,
    start_case: str | None = None,
) -> list[str]:
    src = LTP_RUNTEST_PATH
    names: list[str] = []
    for raw in filter_ltp_runtest_lines(read_ltp_runtest_lines(src), selected_cases, start_case):
        stripped = sanitize_line(raw).strip()
        if not stripped or stripped.startswith("#"):
            continue
        names.append(stripped.split()[0])
    return names


def legacy_ltp_weight_to_seconds(weight: int) -> int:
    if weight <= 0:
        return 0
    return max(
        LTP_WEIGHT_CASE_BASE_SEC,
        weight * LTP_HEARTBEAT_INTERVAL_SEC + LTP_WEIGHT_CASE_BASE_SEC,
    )


def ltp_case_runtime_weight_seconds(heartbeat_count: int, *, stalled: bool = False) -> int:
    heartbeat_count = max(0, heartbeat_count)
    runtime_sec = LTP_WEIGHT_CASE_BASE_SEC
    if heartbeat_count > 0:
        runtime_sec += heartbeat_count * LTP_HEARTBEAT_INTERVAL_SEC + LTP_WEIGHT_CASE_TAIL_SEC
    if stalled:
        runtime_sec += LTP_WEIGHT_STALLED_PENALTY_SEC
    return max(LTP_WEIGHT_CASE_BASE_SEC, int(math.ceil(runtime_sec)))


def quantile_int(values: list[int], q: float) -> int:
    if not values:
        return 0
    if len(values) == 1:
        return int(math.ceil(values[0]))
    ordered = sorted(int(math.ceil(value)) for value in values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * q) - 1))
    return ordered[index]


def ltp_weight_key(runtime: str, arch: str) -> str:
    return f"{runtime}-{arch}"


def parse_ltp_weight_key(weight_key: str) -> tuple[str, str]:
    try:
        runtime, arch = weight_key.split("-", 1)
    except ValueError:
        fail(f"invalid LTP weight variant: {weight_key}")
    if runtime not in RUNTIME_ORDER or arch not in ARCH_ORDER:
        fail(f"invalid LTP weight variant: {weight_key}")
    return runtime, arch


def ltp_shard_case_weight(
    case_name: str,
    case_runtime_weights: dict[str, int],
    point_runtime_weights: dict[str, int],
) -> int:
    if case_name in case_runtime_weights:
        return case_runtime_weights[case_name]
    point = ltp_point_name(case_name)
    if point in point_runtime_weights:
        return point_runtime_weights[point]
    return legacy_ltp_weight_to_seconds(LTP_SHARD_POINT_WEIGHTS.get(point, 1))


def ltp_batch_total_weight(batch: list[tuple[int, str, int]]) -> int:
    if not batch:
        return 0
    return LTP_WEIGHT_BATCH_BOOT_SEC + sum(weight for _, _, weight in batch)


def assign_ltp_case_shards(
    case_names: list[str],
    shard_count: int,
    case_runtime_weights: dict[str, int],
    point_runtime_weights: dict[str, int],
) -> tuple[list[list[str]], list[int]]:
    if shard_count <= 1 or len(case_names) <= 1:
        single_shard = list(case_names)
        single_weight = sum(
            ltp_shard_case_weight(case_name, case_runtime_weights, point_runtime_weights)
            for case_name in single_shard
        )
        return ([single_shard] if single_shard else []), ([single_weight] if single_shard else [])

    indexed_cases = list(enumerate(case_names))
    shards: list[list[tuple[int, str]]] = [[] for _ in range(shard_count)]
    shard_weights = [0] * shard_count
    for original_index, case_name in sorted(
        indexed_cases,
        key=lambda item: (-ltp_shard_case_weight(item[1], case_runtime_weights, point_runtime_weights), item[0]),
    ):
        weight = ltp_shard_case_weight(case_name, case_runtime_weights, point_runtime_weights)
        index = min(
            range(shard_count),
            key=lambda idx: (shard_weights[idx], len(shards[idx]), idx),
        )
        shards[index].append((original_index, case_name))
        shard_weights[index] += weight

    compact_shards: list[list[str]] = []
    compact_weights: list[int] = []
    for shard_index, cases in enumerate(shards):
        if not cases:
            continue
        compact_shards.append([case_name for _, case_name in sorted(cases)])
        compact_weights.append(shard_weights[shard_index])
    return compact_shards, compact_weights


def ltp_runtime_lines_from_log(log_path: Path, runtime: str) -> list[str]:
    all_lines = [sanitize_line(raw).strip() for raw in log_path.read_text(encoding="utf-8", errors="ignore").splitlines()]
    group_start = f"#### OS COMP TEST GROUP START ltp-{runtime} ####"
    group_end = f"#### OS COMP TEST GROUP END ltp-{runtime} ####"
    selected: list[str] = []
    inside = False
    saw_runtime_group_marker = False
    saw_any_ltp_group_marker = False
    for line in all_lines:
        marker_match = OFFICIAL_GROUP_MARKER_RE.match(line)
        if marker_match and marker_match.group(2) == "ltp":
            saw_any_ltp_group_marker = True
        if line == group_start:
            saw_runtime_group_marker = True
            inside = True
            continue
        if line == group_end:
            saw_runtime_group_marker = True
            inside = False
            continue
        if inside:
            selected.append(line)
    if saw_runtime_group_marker:
        return selected
    if saw_any_ltp_group_marker:
        return []
    return all_lines


def parse_ltp_case_runtime_weights_from_log(log_path: Path, runtime: str) -> tuple[dict[str, int], dict[str, int]]:
    case_runtime_max_sec: dict[str, int] = {}
    if not log_path.exists():
        return ({}, {})

    def record_case(case_name: str | None, heartbeat_count: int, *, stalled: bool = False) -> None:
        if case_name is None:
            return
        weight_sec = ltp_case_runtime_weight_seconds(heartbeat_count, stalled=stalled)
        case_runtime_max_sec[case_name] = max(case_runtime_max_sec.get(case_name, 0), weight_sec)

    current_case: str | None = None
    current_heartbeat_count = 0
    for line in ltp_runtime_lines_from_log(log_path, runtime):
        run_match = LTP_RUN_LINE_RE.match(line)
        if run_match:
            record_case(current_case, current_heartbeat_count)
            current_case = run_match.group(1)
            current_heartbeat_count = 0
            continue
        heartbeat_match = LTP_HEARTBEAT_LINE_RE.match(line)
        if heartbeat_match and current_case == heartbeat_match.group(1):
            current_heartbeat_count += 1
            continue
        if line.startswith("#### OS COMP TEST GROUP END "):
            record_case(current_case, current_heartbeat_count)
            current_case = None
            current_heartbeat_count = 0
            continue
        if QEMU_TERMINATING_LINE_RE.match(line):
            record_case(current_case, current_heartbeat_count, stalled=True)
            current_case = None
            current_heartbeat_count = 0
            continue
        pass_match = LTP_PASS_LINE_RE.match(line)
        legacy_ok_match = LTP_LEGACY_OK_LINE_RE.match(line)
        fail_match = LTP_FAIL_LINE_RE.match(line)
        skip_match = LTP_SKIP_LINE_RE.match(line)
        finished_case: str | None = None
        if pass_match:
            finished_case = pass_match.group(1)
        elif legacy_ok_match:
            finished_case = legacy_ok_match.group(1)
        elif fail_match:
            finished_case = fail_match.group(1)
        elif skip_match:
            finished_case = skip_match.group(1)
        if finished_case is None or finished_case != current_case:
            continue
        record_case(finished_case, current_heartbeat_count)
        current_case = None
        current_heartbeat_count = 0
    record_case(current_case, current_heartbeat_count)

    case_weights = {
        case_name: max(LTP_WEIGHT_CASE_BASE_SEC, runtime_sec)
        for case_name, runtime_sec in case_runtime_max_sec.items()
    }
    point_case_weights: dict[str, list[int]] = {}
    for case_name, weight in case_weights.items():
        point = ltp_point_name(case_name)
        point_case_weights.setdefault(point, []).append(weight)
    point_weights = {
        point: max(LTP_WEIGHT_CASE_BASE_SEC, quantile_int(weights, LTP_WEIGHT_POINT_QUANTILE))
        for point, weights in point_case_weights.items()
    }
    return (case_weights, point_weights)


def ltp_runtime_weight_log_candidates(weight_key: str, *, fallback: bool = False) -> list[Path]:
    candidates: list[Path] = []
    sample = LTP_RUNTIME_WEIGHT_SAMPLE_BY_VARIANT.get(weight_key)
    if sample:
        logs_dir = WORK_ROOT / "logs"
        candidates.append(logs_dir / f"{sample}.out")
        candidates.extend(sorted(logs_dir.glob(f"{sample}.worker*.out")))
        candidates.extend(sorted(logs_dir.glob(f"{sample}.worker*.try*.out")))
    export_map = (
        LTP_FALLBACK_RUNTIME_WEIGHT_EXPORT_LOG_BY_VARIANT
        if fallback
        else LTP_RUNTIME_WEIGHT_EXPORT_LOG_BY_VARIANT
    )
    export_log = export_map.get(weight_key)
    if export_log is not None:
        candidates.append(export_log)

    unique_candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_candidates.append(candidate)
    return unique_candidates


def preferred_ltp_runtime_weight_log(weight_key: str, *, fallback: bool = False) -> Path | None:
    for candidate in ltp_runtime_weight_log_candidates(weight_key, fallback=fallback):
        if candidate.exists():
            return candidate
    return None


def parse_ltp_case_runtime_weights_for_variant(
    weight_key: str,
    *,
    fallback: bool = False,
) -> tuple[dict[str, int], dict[str, int]]:
    runtime, _arch = parse_ltp_weight_key(weight_key)
    merged_case_weights: dict[str, int] = {}
    merged_point_weights: dict[str, int] = {}
    for log_path in ltp_runtime_weight_log_candidates(weight_key, fallback=fallback):
        if not log_path.exists():
            continue
        case_weights, point_weights = parse_ltp_case_runtime_weights_from_log(log_path, runtime)
        merged_case_weights = merge_ltp_runtime_weight_maps(merged_case_weights, case_weights)
        merged_point_weights = merge_ltp_runtime_weight_maps(merged_point_weights, point_weights)
    return (merged_case_weights, merged_point_weights)


def kernel_log_timestamp_seconds(line: str) -> float | None:
    match = KERNEL_LOG_TIMESTAMP_RE.match(line)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def parse_ltp_startup_samples_from_log(log_path: Path | None, runtime: str) -> list[int]:
    if log_path is None or not log_path.exists():
        return []
    command_marker = f'Running direct command: ["/busybox", "sh", "/{runtime}/ltp_testcode.sh"]'
    samples: list[int] = []
    for raw in read_text(log_path).splitlines():
        line = sanitize_line(raw).strip()
        if command_marker not in line:
            continue
        timestamp = kernel_log_timestamp_seconds(line)
        if timestamp is None:
            continue
        samples.append(max(1, int(math.ceil(timestamp))))
    return samples


def estimate_ltp_single_boot_startup_seconds(
    runtime: str,
    arch: str,
    *,
    observed_log_path: Path | None = None,
) -> tuple[int, str]:
    observed_samples = parse_ltp_startup_samples_from_log(observed_log_path, runtime)
    if observed_samples:
        return (max(1, quantile_int(observed_samples, LTP_WEIGHT_POINT_QUANTILE)), "current")

    history_log = preferred_ltp_runtime_weight_log(ltp_weight_key(runtime, arch))
    history_samples = parse_ltp_startup_samples_from_log(history_log, runtime)
    if history_samples:
        return (max(1, quantile_int(history_samples, LTP_WEIGHT_POINT_QUANTILE)), "history")

    return (LTP_WEIGHT_BATCH_BOOT_SEC, "fallback")


def estimate_ltp_single_boot_runtime(
    case_names: list[str],
    runtime: str,
    arch: str,
    *,
    observed_log_path: Path | None = None,
) -> LtpSingleBootEstimate:
    observed_case_weights, observed_point_weights = (
        parse_ltp_case_runtime_weights_from_log(observed_log_path, runtime)
        if observed_log_path is not None and observed_log_path.exists()
        else ({}, {})
    )
    baseline_case_weights, baseline_point_weights = load_ltp_case_runtime_weights(runtime, arch)
    startup_sec, startup_source = estimate_ltp_single_boot_startup_seconds(
        runtime,
        arch,
        observed_log_path=observed_log_path,
    )

    case_sec = 0
    exact_case_count = 0
    point_case_count = 0
    history_case_count = 0
    for case_name in case_names:
        if case_name in observed_case_weights:
            case_sec += observed_case_weights[case_name]
            exact_case_count += 1
            continue
        point = ltp_point_name(case_name)
        if point in observed_point_weights:
            case_sec += observed_point_weights[point]
            point_case_count += 1
            continue
        case_sec += ltp_shard_case_weight(case_name, baseline_case_weights, baseline_point_weights)
        history_case_count += 1

    return LtpSingleBootEstimate(
        startup_sec=startup_sec,
        case_sec=case_sec,
        total_sec=startup_sec + case_sec,
        exact_case_count=exact_case_count,
        point_case_count=point_case_count,
        history_case_count=history_case_count,
        total_case_count=len(case_names),
        startup_source=startup_source,
    )


def sanitize_runtime_weight_map(raw: object, *, legacy_units: bool = False) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    sanitized: dict[str, int] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        try:
            weight = int(value)
        except (TypeError, ValueError):
            continue
        if weight > 0:
            if legacy_units:
                weight = legacy_ltp_weight_to_seconds(weight)
            sanitized[key] = weight
    return sanitized


def load_persisted_ltp_case_runtime_weights(weight_key: str) -> tuple[dict[str, int], dict[str, int]]:
    if not LTP_PERSISTED_WEIGHT_FILE.exists():
        return ({}, {})
    try:
        payload = json.loads(LTP_PERSISTED_WEIGHT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ({}, {})
    variant_payload = payload.get("variants", {}).get(weight_key, {})
    if not isinstance(variant_payload, dict):
        _runtime, arch = parse_ltp_weight_key(weight_key)
        variant_payload = payload.get("arches", {}).get(arch, {})
    if not isinstance(variant_payload, dict):
        return ({}, {})
    legacy_units = variant_payload.get("unit") != "seconds"
    return (
        sanitize_runtime_weight_map(variant_payload.get("case_weights"), legacy_units=legacy_units),
        sanitize_runtime_weight_map(variant_payload.get("point_weights"), legacy_units=legacy_units),
    )


def load_fallback_ltp_case_runtime_weights(weight_key: str) -> tuple[dict[str, int], dict[str, int]]:
    return parse_ltp_case_runtime_weights_for_variant(weight_key, fallback=True)


def choose_ltp_runtime_weight_plan(
    weight_key: str,
    shard_count: int,
    case_names: list[str],
    refreshed_case_weights: dict[str, int],
    refreshed_point_weights: dict[str, int],
) -> tuple[dict[str, int], dict[str, int], str, int, str, int]:
    fallback_case_weights, fallback_point_weights = load_fallback_ltp_case_runtime_weights(weight_key)
    if fallback_case_weights or fallback_point_weights:
        baseline_case_weights = fallback_case_weights
        baseline_point_weights = fallback_point_weights
        baseline_label = "fallback-log"
    else:
        baseline_case_weights, baseline_point_weights = load_persisted_ltp_case_runtime_weights(weight_key)
        baseline_label = "persisted" if (baseline_case_weights or baseline_point_weights) else "static"

    if not refreshed_case_weights and not refreshed_point_weights:
        return (
            baseline_case_weights,
            baseline_point_weights,
            baseline_label,
            0,
            baseline_label,
            0,
        )
    if not (baseline_case_weights or baseline_point_weights):
        refreshed_max = 0
        if shard_count > 1 and case_names:
            _, refreshed_loads = assign_ltp_case_shards(
                case_names, shard_count, refreshed_case_weights, refreshed_point_weights
            )
            refreshed_max = max(refreshed_loads, default=0)
        return (
            refreshed_case_weights,
            refreshed_point_weights,
            "refreshed",
            refreshed_max,
            baseline_label,
            0,
        )

    baseline_max = 0
    refreshed_max = 0
    if shard_count > 1 and case_names:
        _, baseline_loads = assign_ltp_case_shards(
            case_names, shard_count, baseline_case_weights, baseline_point_weights
        )
        _, refreshed_loads = assign_ltp_case_shards(
            case_names, shard_count, refreshed_case_weights, refreshed_point_weights
        )
        baseline_max = max(baseline_loads, default=0)
        refreshed_max = max(refreshed_loads, default=0)

    if refreshed_max <= baseline_max:
        return (
            refreshed_case_weights,
            refreshed_point_weights,
            "refreshed",
            refreshed_max,
            baseline_label,
            baseline_max,
        )
    return (
        baseline_case_weights,
        baseline_point_weights,
        baseline_label,
        baseline_max,
        "refreshed",
        refreshed_max,
    )


def merge_ltp_runtime_weight_maps(*maps: dict[str, int]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for weight_map in maps:
        for case_name, weight in weight_map.items():
            if weight > 0:
                merged[case_name] = max(merged.get(case_name, 0), weight)
    return merged


def persist_ltp_case_runtime_weights(
    weight_key: str,
    case_weights: dict[str, int],
    point_weights: dict[str, int],
) -> None:
    payload: dict[str, object] = {"version": 1, "variants": {}}
    if LTP_PERSISTED_WEIGHT_FILE.exists():
        try:
            loaded = json.loads(LTP_PERSISTED_WEIGHT_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        except (OSError, json.JSONDecodeError):
            payload = {"version": 1, "variants": {}}
    variants = payload.get("variants")
    if not isinstance(variants, dict):
        variants = {}
        payload["variants"] = variants
    source_log = preferred_ltp_runtime_weight_log(weight_key)
    variants[weight_key] = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "unit": "seconds",
        "source_log": str(relative_path(source_log)) if source_log is not None else None,
        "case_weights": dict(sorted(case_weights.items())),
        "point_weights": dict(sorted(point_weights.items())),
    }
    payload["version"] = 1
    payload["updated_at"] = datetime.now(timezone.utc).isoformat()
    LTP_PERSISTED_WEIGHT_FILE.parent.mkdir(parents=True, exist_ok=True)
    LTP_PERSISTED_WEIGHT_FILE.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def refresh_ltp_case_runtime_weight_variant(
    weight_key: str,
    shard_count: int,
    case_names: list[str],
) -> None:
    runtime, arch = parse_ltp_weight_key(weight_key)
    case_weights, point_weights = parse_ltp_case_runtime_weights_for_variant(weight_key)
    (
        chosen_case_weights,
        chosen_point_weights,
        chosen_label,
        chosen_max,
        rejected_label,
        rejected_max,
    ) = choose_ltp_runtime_weight_plan(weight_key, shard_count, case_names, case_weights, point_weights)
    if not case_weights and not point_weights:
        LTP_CASE_RUNTIME_WEIGHT_CACHE[weight_key] = (chosen_case_weights, chosen_point_weights)
        console(
            f"[ltp-weight] {weight_key} skip empty refresh, keep {chosen_label} "
            f"source-cases=0 source-points=0"
        )
        return
    if chosen_label == "refreshed":
        persist_ltp_case_runtime_weights(weight_key, case_weights, point_weights)
    LTP_CASE_RUNTIME_WEIGHT_CACHE[weight_key] = (chosen_case_weights, chosen_point_weights)

    if shard_count <= 1 or not case_names:
        console(
            f"[ltp-weight] {weight_key} choose {chosen_label} over {rejected_label} "
            f"source-cases={len(case_weights)} source-points={len(point_weights)}"
        )
        return

    delta_load = chosen_max - rejected_max
    delta_abs = abs(delta_load)
    delta_pct = (delta_abs / rejected_max * 100.0) if rejected_max else 0.0
    delta_sign = "-" if delta_load < 0 else "+"
    console(
        f"[ltp-weight] {weight_key} choose {chosen_label} over {rejected_label}, "
        f"max-load {rejected_max} -> {chosen_max}, "
        f"est {delta_sign}{format_duration(delta_abs)} "
        f"({delta_sign}{delta_pct:.1f}%) source-cases={len(case_weights)} source-points={len(point_weights)}"
    )


def load_ltp_case_runtime_weights(runtime: str, arch: str) -> tuple[dict[str, int], dict[str, int]]:
    global LTP_CASE_RUNTIME_WEIGHT_CACHE
    weight_key = ltp_weight_key(runtime, arch)
    if weight_key in LTP_CASE_RUNTIME_WEIGHT_CACHE:
        return LTP_CASE_RUNTIME_WEIGHT_CACHE[weight_key]
    if ENABLE_LTP_RUNTIME_WEIGHT_REFRESH and weight_key in LTP_RUNTIME_WEIGHT_REFRESH_VARIANTS:
        case_weights, point_weights = parse_ltp_case_runtime_weights_for_variant(weight_key)
        (
            chosen_case_weights,
            chosen_point_weights,
            chosen_label,
            _chosen_max,
            _rejected_label,
            _rejected_max,
        ) = choose_ltp_runtime_weight_plan(weight_key, 1, [], case_weights, point_weights)
        if case_weights and chosen_label == "refreshed":
            persist_ltp_case_runtime_weights(weight_key, case_weights, point_weights)
        LTP_CASE_RUNTIME_WEIGHT_CACHE[weight_key] = (chosen_case_weights, chosen_point_weights)
        return LTP_CASE_RUNTIME_WEIGHT_CACHE[weight_key]
    persisted_case_weights, persisted_point_weights = load_persisted_ltp_case_runtime_weights(weight_key)
    local_case_weights, local_point_weights = parse_ltp_case_runtime_weights_for_variant(weight_key)
    LTP_CASE_RUNTIME_WEIGHT_CACHE[weight_key] = (
        merge_ltp_runtime_weight_maps(persisted_case_weights, local_case_weights),
        merge_ltp_runtime_weight_maps(persisted_point_weights, local_point_weights),
    )
    return LTP_CASE_RUNTIME_WEIGHT_CACHE[weight_key]


def emit_ltp_shard_weight_projection(runtime: str, arch: str, shard_count: int, case_names: list[str]) -> None:
    if not ENABLE_LTP_RUNTIME_WEIGHT_REFRESH or shard_count <= 1 or not case_names:
        return

    weight_key = ltp_weight_key(runtime, arch)
    baseline_case_weights, baseline_point_weights = load_persisted_ltp_case_runtime_weights(weight_key)
    case_runtime_weights, point_runtime_weights = load_ltp_case_runtime_weights(runtime, arch)
    _, static_loads = assign_ltp_case_shards(case_names, shard_count, baseline_case_weights, baseline_point_weights)
    _, dynamic_loads = assign_ltp_case_shards(case_names, shard_count, case_runtime_weights, point_runtime_weights)
    static_max = max(static_loads, default=0)
    dynamic_max = max(dynamic_loads, default=0)
    delta_load = dynamic_max - static_max
    delta_abs = abs(delta_load)
    delta_pct = (delta_abs / static_max * 100.0) if static_max else 0.0
    baseline_label = "persisted" if (baseline_case_weights or baseline_point_weights) else "static"
    delta_sign = "-" if delta_load < 0 else "+"
    console(
        f"[ltp-weight] {weight_key} {baseline_label} max-load {static_max} -> {dynamic_max}, "
        f"est {delta_sign}{format_duration(delta_abs)} "
        f"({delta_sign}{delta_pct:.1f}%) source-cases={len(case_runtime_weights)} source-points={len(point_runtime_weights)}"
    )


def shard_ltp_case_names(case_names: list[str], shard_count: int, runtime: str, arch: str) -> list[list[str]]:
    case_runtime_weights, point_runtime_weights = load_ltp_case_runtime_weights(runtime, arch)
    shards, _ = assign_ltp_case_shards(case_names, shard_count, case_runtime_weights, point_runtime_weights)
    return shards


def ltp_dynamic_batch_specs(
    case_names: list[str],
    worker_count: int,
    runtime: str,
    arch: str,
) -> list[tuple[int, list[str], int]]:
    if not case_names:
        return []
    case_runtime_weights, point_runtime_weights = load_ltp_case_runtime_weights(runtime, arch)
    weighted_cases = [
        (
            original_index,
            case_name,
            ltp_shard_case_weight(case_name, case_runtime_weights, point_runtime_weights),
        )
        for original_index, case_name in enumerate(case_names)
    ]
    total_weight = sum(weight for _, _, weight in weighted_cases)
    target_batch_count = max(worker_count * 2, worker_count)
    batch_target = max(
        LTP_WARM_CASE_WEIGHT_THRESHOLD,
        math.ceil((total_weight + target_batch_count * LTP_WEIGHT_BATCH_BOOT_SEC) / max(target_batch_count, 1)),
    )
    max_cases_per_batch = max(8, math.ceil(len(case_names) / max(target_batch_count, 1)))

    super_heavy_cases: list[tuple[int, str, int]] = []
    heavy_cases: list[tuple[int, str, int]] = []
    warm_cases: list[tuple[int, str, int]] = []
    regular_cases: list[tuple[int, str, int]] = []
    for item in weighted_cases:
        _original_index, _case_name, weight = item
        if weight >= LTP_HEAVY_CASE_WEIGHT_THRESHOLD:
            super_heavy_cases.append(item)
        elif weight >= LTP_MEDIUM_CASE_WEIGHT_THRESHOLD:
            heavy_cases.append(item)
        elif weight >= LTP_WARM_CASE_WEIGHT_THRESHOLD:
            warm_cases.append(item)
        else:
            regular_cases.append(item)

    batches: list[tuple[list[tuple[int, str, int]], int]] = []
    for item in sorted(super_heavy_cases, key=lambda item: (-item[2], item[0])):
        batches.append(([item], 0))

    def build_tier_batches(
        tier_cases: list[tuple[int, str, int]],
        *,
        tier_rank: int,
        tier_target: int,
        tier_max_cases: int,
    ) -> None:
        if not tier_cases:
            return
        current: list[tuple[int, str, int]] = []
        current_weight = 0
        for item in sorted(tier_cases, key=lambda item: (-item[2], item[0])):
            _original_index, _case_name, weight = item
            current_batch_weight = current_weight + (LTP_WEIGHT_BATCH_BOOT_SEC if not current else 0)
            next_batch_weight = current_batch_weight + weight
            should_close = (
                current
                and (
                    len(current) >= tier_max_cases
                    or (
                        current_batch_weight >= max(LTP_WARM_CASE_WEIGHT_THRESHOLD, tier_target // 2)
                        and next_batch_weight > tier_target
                    )
                )
            )
            if should_close:
                batches.append((current, tier_rank))
                current = []
                current_weight = 0
            current.append(item)
            current_weight += weight
        if current:
            batches.append((current, tier_rank))

    build_tier_batches(
        heavy_cases,
        tier_rank=1,
        tier_target=max(LTP_MEDIUM_CASE_WEIGHT_THRESHOLD, batch_target),
        tier_max_cases=2,
    )
    build_tier_batches(
        warm_cases,
        tier_rank=2,
        tier_target=max(LTP_WARM_CASE_WEIGHT_THRESHOLD, batch_target),
        tier_max_cases=4,
    )
    build_tier_batches(
        regular_cases,
        tier_rank=3,
        tier_target=batch_target,
        tier_max_cases=max_cases_per_batch,
    )

    specs: list[tuple[int, list[str], int]] = []
    ordered_batches = sorted(
        batches,
        key=lambda batch: (
            batch[1],
            -ltp_batch_total_weight(batch[0]),
            batch[0][0][0],
        ),
    )
    for batch_id, (batch, _tier_rank) in enumerate(ordered_batches, start=1):
        specs.append(
            (
                batch_id,
                [case_name for _, case_name, _ in batch],
                ltp_batch_total_weight(batch),
            )
        )
    return specs


def ltp_weighted_case_queue(
    case_names: list[str],
    case_runtime_weights: dict[str, int],
    point_runtime_weights: dict[str, int],
) -> deque[tuple[int, str, int]]:
    weighted_cases = [
        (
            original_index,
            case_name,
            ltp_shard_case_weight(case_name, case_runtime_weights, point_runtime_weights),
        )
        for original_index, case_name in enumerate(case_names)
    ]
    weighted_cases.sort(key=lambda item: (-item[2], item[0], item[1]))
    return deque(weighted_cases)


def order_ltp_queue_cases(cases: list[LtpQueueCase]) -> list[LtpQueueCase]:
    ordered = list(cases)
    ordered.sort(key=lambda case: (-case.weight_sec, case.case_index, case.case_name))
    return ordered


def preview_ltp_queue_cases(cases: list[LtpQueueCase], limit: int = 8) -> str:
    if not cases:
        return "-"
    return ", ".join(f"{case.case_name}={case.weight_sec}s" for case in cases[:limit])


def ltp_queue_cases(
    case_names: list[str],
    case_runtime_weights: dict[str, int],
    point_runtime_weights: dict[str, int],
) -> list[LtpQueueCase]:
    runtest_by_name: dict[str, str] = {}
    for raw in read_ltp_runtest_lines(LTP_RUNTEST_PATH):
        stripped = sanitize_line(raw).strip()
        if not stripped or stripped.startswith("#"):
            continue
        runtest_by_name[stripped.split()[0]] = raw
    queue_cases: list[LtpQueueCase] = []
    for case_index, case_name in enumerate(case_names):
        runtest_line = runtest_by_name.get(case_name)
        if runtest_line is None:
            fail(f"missing runtest line for LTP case: {case_name}")
        queue_cases.append(
            LtpQueueCase(
                case_index=case_index,
                case_name=case_name,
                runtest_line=runtest_line,
                weight_sec=ltp_shard_case_weight(case_name, case_runtime_weights, point_runtime_weights),
            )
        )
    return order_ltp_queue_cases(queue_cases)


def start_ltp_work_stealing_server(queue: LtpWorkStealingQueue) -> tuple[LtpWorkStealingHttpServer, str]:
    token = hashlib.sha1(f"{time.time()}-{os.getpid()}".encode("utf-8")).hexdigest()
    server = LtpWorkStealingHttpServer(("0.0.0.0", 0), queue, token)
    thread = threading.Thread(target=server.serve_forever, name="ltp-work-stealing-server", daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    if not host or host == "0.0.0.0":
        host = LTP_QUEUE_GUEST_HOST
    return server, f"http://{host}:{port}/next?token={token}"


def claim_next_ltp_case_lease(
    pending_cases: deque[tuple[int, str, int]],
) -> tuple[int, list[str], int] | None:
    if not pending_cases:
        return None
    case_index, case_name, weight = pending_cases.popleft()
    return (case_index + 1, [case_name], LTP_WEIGHT_BATCH_BOOT_SEC + weight)


def format_ltp_runtime_mul(value: float) -> str:
    text = f"{value:.3f}".rstrip("0").rstrip(".")
    return text or "1"


def ltp_case_timeout_seconds(runtime_mul: float) -> int:
    return LTP_SINGLE_CASE_TIMEOUT_SEC


def parse_refresh_ltp_shard_weight_variants(chunks: list[str] | None) -> list[str]:
    if not chunks:
        return []
    allowed = set(LTP_RUNTIME_WEIGHT_SAMPLE_BY_VARIANT)
    variants: list[str] = []
    seen: set[str] = set()
    invalid: list[str] = []
    for chunk in chunks:
        for part in chunk.split(","):
            variant = part.strip()
            if not variant:
                continue
            if variant not in allowed:
                invalid.append(variant)
                continue
            if variant not in seen:
                variants.append(variant)
                seen.add(variant)
    if invalid:
        fail(
            "unknown LTP shard weight variants: "
            + ", ".join(invalid)
            + " (expected one of: "
            + ", ".join(sorted(allowed))
            + ")"
        )
    return variants


def ensure_ltp_script_uses_queue(
    rootfs_dir: Path,
    *,
    runtime_mul: float,
    queue_url: str,
    worker_index: int,
) -> None:
    script_path = rootfs_dir / "ltp_testcode.sh"
    script_target_dir = ltp_runtime_target_dir(rootfs_dir)
    script_ltp_root = ltp_runtime_root_path(rootfs_dir)
    script_search_path = ltp_runtime_search_path(rootfs_dir)
    script_library_path = ltp_runtime_library_path(rootfs_dir)
    script_timeout_mul = "10000" if runtime_mul >= 1.0 else format_ltp_runtime_mul(max(min(runtime_mul, 1.0), 0.1))
    script_runtime_mul = format_ltp_runtime_mul(runtime_mul)
    script_heartbeat_interval_sec = str(LTP_HEARTBEAT_INTERVAL_SEC)
    script_case_timeout_sec = str(ltp_case_timeout_seconds(runtime_mul))
    ensure_private_regular_file(script_path)
    script_path.write_text(
        LTP_DYNAMIC_TESTCODE_SCRIPT_TEMPLATE.replace("__OSK_LTP_TARGET_DIR__", script_target_dir)
        .replace("__OSK_LTP_ROOT__", script_ltp_root)
        .replace("__OSK_LTP_SEARCH_PATH__", script_search_path)
        .replace("__OSK_LTP_LIBRARY_PATH__", script_library_path)
        .replace("__OSK_LTP_TIMEOUT_MUL__", script_timeout_mul)
        .replace("__OSK_LTP_RUNTIME_MUL__", script_runtime_mul)
        .replace("__OSK_LTP_CASE_TIMEOUT_SEC__", script_case_timeout_sec)
        .replace("__OSK_LTP_HEARTBEAT_INTERVAL_SEC__", script_heartbeat_interval_sec)
        .replace("__OSK_LTP_QUEUE_URL__", queue_url)
        .replace("__OSK_LTP_WORKER_ID__", str(worker_index + 1)),
        encoding="utf-8",
    )
    script_path.chmod(0o755)


def ensure_ltp_script_uses_stdin_queue(
    rootfs_dir: Path,
    *,
    runtime_mul: float,
) -> None:
    script_path = rootfs_dir / "ltp_testcode.sh"
    script_target_dir = ltp_runtime_target_dir(rootfs_dir)
    script_ltp_root = ltp_runtime_root_path(rootfs_dir)
    script_search_path = ltp_runtime_search_path(rootfs_dir)
    script_library_path = ltp_runtime_library_path(rootfs_dir)
    script_timeout_mul = "10000" if runtime_mul >= 1.0 else format_ltp_runtime_mul(max(min(runtime_mul, 1.0), 0.1))
    script_runtime_mul = format_ltp_runtime_mul(runtime_mul)
    script_heartbeat_interval_sec = str(LTP_HEARTBEAT_INTERVAL_SEC)
    script_case_timeout_sec = str(ltp_case_timeout_seconds(runtime_mul))
    ensure_private_regular_file(script_path)
    script_path.write_text(
        LTP_STDIN_TESTCODE_SCRIPT_TEMPLATE.replace("__OSK_LTP_TARGET_DIR__", script_target_dir)
        .replace("__OSK_LTP_ROOT__", script_ltp_root)
        .replace("__OSK_LTP_SEARCH_PATH__", script_search_path)
        .replace("__OSK_LTP_LIBRARY_PATH__", script_library_path)
        .replace("__OSK_LTP_TIMEOUT_MUL__", script_timeout_mul)
        .replace("__OSK_LTP_RUNTIME_MUL__", script_runtime_mul)
        .replace("__OSK_LTP_CASE_TIMEOUT_SEC__", script_case_timeout_sec)
        .replace("__OSK_LTP_HEARTBEAT_INTERVAL_SEC__", script_heartbeat_interval_sec)
        .replace("__OSK_LTP_STDIN_READY__", LTP_STDIN_TESTCODE_READY_MARKER),
        encoding="utf-8",
    )
    script_path.chmod(0o755)


def ensure_ltp_script_uses_runtest(
    rootfs_dir: Path,
    selected_cases: list[str] | None = None,
    runtime_mul: float = 1.0,
    start_case: str | None = None,
) -> None:
    script_path = rootfs_dir / "ltp_testcode.sh"
    runtest_path = rootfs_dir / "ltp" / "runtest" / "syscalls"
    runtime = ltp_runtime_root_name(rootfs_dir)
    script_runtest_path = f"/{runtime}/ltp/runtest/syscalls" if runtime else "/ltp/runtest/syscalls"
    script_target_dir = ltp_runtime_target_dir(rootfs_dir)
    script_ltp_root = ltp_runtime_root_path(rootfs_dir)
    script_search_path = ltp_runtime_search_path(rootfs_dir)
    script_library_path = ltp_runtime_library_path(rootfs_dir)
    script_timeout_mul = "10000" if runtime_mul >= 1.0 else format_ltp_runtime_mul(max(min(runtime_mul, 1.0), 0.1))
    script_runtime_mul = format_ltp_runtime_mul(runtime_mul)
    script_heartbeat_interval_sec = str(LTP_HEARTBEAT_INTERVAL_SEC)
    script_case_timeout_sec = str(ltp_case_timeout_seconds(runtime_mul))
    src = LTP_RUNTEST_PATH
    if src.exists():
        runtest_path.parent.mkdir(parents=True, exist_ok=True)
        filtered_lines = filter_ltp_runtest_lines(read_ltp_runtest_lines(src), selected_cases, start_case)
        ensure_private_regular_file(runtest_path)
        runtest_path.write_text("\n".join(filtered_lines).rstrip() + "\n", encoding="utf-8")
    if script_path.exists():
        content = script_path.read_text(encoding="utf-8", errors="ignore")
        if (
            script_runtest_path in content
            and f'target_dir="{script_target_dir}"' in content
            and f'ltp_root="{script_ltp_root}"' in content
            and f'PATH="{script_search_path}"' in content
            and f'export LIBRARY_PATH="{script_library_path}"' in content
            and f'export LD_LIBRARY_PATH="{script_library_path}"' in content
            and '[ltp-heartbeat] $case_name' in content
            and f': "${{LTP_TIMEOUT_MUL:={script_timeout_mul}}}"' in content
            and f': "${{LTP_RUNTIME_MUL:={script_runtime_mul}}}"' in content
            and f': "${{LTP_CASE_TIMEOUT_SEC:={script_case_timeout_sec}}}"' in content
            and f'/busybox sleep {script_heartbeat_interval_sec} 2>/dev/null || break' in content
            and 'ltp_ts_now() {' in content
            and 'ltp_emit_log_file() {' in content
            and '  shift' in content
            and '    echo "FAIL LTP CASE $case_name : 0"' in content
            and '  set -- $line' in content
            and '  (cd "$target_dir" && /busybox setsid "$@") >"$log_file" 2>&1 &' in content
            and 'echo "[ltp-case-timeout] $case_name exceeded ${LTP_CASE_TIMEOUT_SEC}s"' in content
            and '  ltp_emit_log_file "$log_file"' in content
            and '  ltp_emit_ts "$case_name" done' in content
            and '  ltp_emit_ts "$name" run' in content
        ):
            return
    ensure_private_regular_file(script_path)
    script_path.write_text(
        LTP_TESTCODE_SCRIPT_TEMPLATE.replace("__OSK_LTP_RUNTEST_PATH__", script_runtest_path)
        .replace("__OSK_LTP_TARGET_DIR__", script_target_dir)
        .replace("__OSK_LTP_ROOT__", script_ltp_root)
        .replace("__OSK_LTP_SEARCH_PATH__", script_search_path)
        .replace("__OSK_LTP_LIBRARY_PATH__", script_library_path)
        .replace("__OSK_LTP_TIMEOUT_MUL__", script_timeout_mul)
        .replace("__OSK_LTP_RUNTIME_MUL__", script_runtime_mul)
        .replace("__OSK_LTP_CASE_TIMEOUT_SEC__", script_case_timeout_sec)
        .replace("__OSK_LTP_HEARTBEAT_INTERVAL_SEC__", script_heartbeat_interval_sec),
        encoding="utf-8",
    )
    script_path.chmod(0o755)


def ltp_raw_script_uses_runtest(runtime_root: Path) -> bool:
    raw_path = runtime_root / f".{SCRIPT_BY_GROUP['ltp']}.raw"
    if not raw_path.exists():
        return False
    content = raw_path.read_text(encoding="utf-8", errors="ignore")
    runtime = ltp_runtime_root_name(runtime_root)
    script_runtest_path = f"/{runtime}/ltp/runtest/syscalls" if runtime else "/ltp/runtest/syscalls"
    script_target_dir = ltp_runtime_target_dir(runtime_root)
    script_ltp_root = ltp_runtime_root_path(runtime_root)
    script_search_path = ltp_runtime_search_path(runtime_root)
    script_library_path = ltp_runtime_library_path(runtime_root)
    return (
        script_runtest_path in content
        and f'target_dir="{script_target_dir}"' in content
        and f'ltp_root="{script_ltp_root}"' in content
        and f'PATH="{script_search_path}"' in content
        and f'export LIBRARY_PATH="{script_library_path}"' in content
        and f'export LD_LIBRARY_PATH="{script_library_path}"' in content
        and '[ltp-heartbeat] $case_name' in content
        and ': "${LTP_TIMEOUT_MUL:=' in content
        and ': "${LTP_RUNTIME_MUL:=' in content
        and ': "${LTP_CASE_TIMEOUT_SEC:=' in content
        and f'/busybox sleep {LTP_HEARTBEAT_INTERVAL_SEC} 2>/dev/null || break' in content
        and 'ltp_ts_now() {' in content
        and 'ltp_emit_log_file() {' in content
        and '  shift' in content
        and '    echo "FAIL LTP CASE $case_name : 0"' in content
        and '  set -- $line' in content
        and '  (cd "$target_dir" && /busybox setsid "$@") >"$log_file" 2>&1 &' in content
        and 'echo "[ltp-case-timeout] $case_name exceeded ${LTP_CASE_TIMEOUT_SEC}s"' in content
        and '  ltp_emit_log_file "$log_file"' in content
        and '  ltp_emit_ts "$case_name" done' in content
        and '  ltp_emit_ts "$name" run' in content
    )


def ltp_runtime_support_is_stale(rootfs_dir: Path) -> bool:
    runtest_path = rootfs_dir / "ltp" / "runtest" / "syscalls"
    testcase_dir = rootfs_dir / "ltp" / "testcases" / "bin"
    clone08_path = testcase_dir / "clone08"
    if not runtest_path.exists():
        return True
    if not testcase_dir.is_dir():
        return True
    if not clone08_path.exists():
        return True
    return False


def prepare_qemu_fw() -> None:
    fw_dir = ROOT / "dev/qemu-la-fw"
    fw_dir.mkdir(parents=True, exist_ok=True)
    src = Path("/usr/share/qemu/qboot.rom")
    if src.exists():
        shutil.copy2(src, fw_dir / "efi-virtio.rom")


def quick_kernel_cache_paths(arch: str) -> list[tuple[Path, str]]:
    if arch == "rv":
        return [
            (ROOT / "kernel-rv", "kernel-rv"),
        ]
    return [
        (ROOT / "kernel-la", "kernel-la"),
        (ROOT / "kernel" / "work" / "la-qemu-bios.bin", "la-qemu-bios.bin"),
        (ROOT / "kernel" / "work" / "la-qemu-bios.elf", "la-qemu-bios.elf"),
    ]


def quick_kernel_cache_key(arch: str) -> str | None:
    token = quick_kernel_revision_token()
    if token is None:
        return None
    return hash_key("quick-kernel", arch, token)


def restore_quick_kernel_cache(arch: str, cache_key: str) -> bool:
    cache_dir = SHARED_CACHE_ROOT / "kernel-quick" / cache_key
    entries = quick_kernel_cache_paths(arch)
    if not all((cache_dir / cache_name).exists() for _dst, cache_name in entries):
        return False
    for dst, cache_name in entries:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cache_dir / cache_name, dst)
    prepare_qemu_fw()
    return True


def update_quick_kernel_cache(arch: str, cache_key: str) -> None:
    cache_dir = SHARED_CACHE_ROOT / "kernel-quick" / cache_key
    cache_dir.mkdir(parents=True, exist_ok=True)
    for src, cache_name in quick_kernel_cache_paths(arch):
        if not src.exists():
            return
    for src, cache_name in quick_kernel_cache_paths(arch):
        shutil.copy2(src, cache_dir / cache_name)


def reuse_prebuilt_quick_kernels_if_available(needed_arches: set[str]) -> bool:
    if os.environ.get("OSK_REUSE_PREBUILT_QUICK_KERNELS") != "1":
        return False
    if not needed_arches:
        return False
    for arch in sorted(needed_arches):
        prebuilt_entries = quick_kernel_cache_paths(arch)
        if not all(path.exists() for path, _cache_name in prebuilt_entries):
            return False
    complete_stage("reuse kernels prebuilt")
    prepare_qemu_fw()
    return True


def prepare_variant_rootfs(
    arch: str,
    runtime: str,
    *,
    rootfs_root: Path,
    stage_logs: Path,
    build_jobs: int,
    rebuild_rootfs: bool,
    effective_build_targets: str | None,
    quick_reuse_only: bool,
) -> tuple[tuple[str, str], Path]:
    out_dir = rootfs_root / f"{arch}-{runtime}"
    marker = out_dir / ".osk_full_rootfs_ready"
    targets_marker = out_dir / ".osk_full_rootfs_targets"
    lock_path = rootfs_root / f".{arch}-{runtime}.lock"
    with FileLock(lock_path):
        stale = variant_rootfs_is_stale(out_dir, runtime, effective_build_targets)
        expected_targets = normalized_build_targets(effective_build_targets)
        needs_rebuild = (
            rebuild_rootfs
            or not marker.exists()
            or marker_text(targets_marker) != expected_targets
            or stale
        )
        if quick_reuse_only and not needs_rebuild:
            complete_stage(f"reuse rootfs {arch}-{runtime}")
        elif needs_rebuild:
            stage_prefix = "build rootfs quick" if quick_reuse_only else "build rootfs"
            require_logged_success(
                f"{stage_prefix} {arch}-{runtime}",
                ["bash", str(ROOT / "tools/build_full_rootfs.sh"), arch, runtime, str(out_dir)],
                cwd=ROOT,
                log_path=stage_logs
                / (f"rootfs-quick-{arch}-{runtime}.log" if quick_reuse_only else f"rootfs-{arch}-{runtime}.log"),
                env={
                    **os.environ,
                    "BUILD_JOBS": str(build_jobs),
                    **({"FULL_SUITE_TARGETS": effective_build_targets} if effective_build_targets else {}),
                },
            )
            targets_marker.write_text(expected_targets + "\n", encoding="utf-8")
            marker.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
        else:
            complete_stage(f"reuse rootfs {arch}-{runtime}")
        ensure_ltp_script_uses_runtest(out_dir)
    return (arch, runtime), out_dir


def ensure_prerequisites(
    build_jobs: int,
    rootfs_variant_jobs: int,
    rebuild_rootfs: bool,
    variants_needed: set[tuple[str, str]],
    build_targets: str | None,
    logs_dir: Path,
    *,
    quick_reuse_only: bool = False,
) -> dict[tuple[str, str], Path]:
    stage_logs = logs_dir / "_stages"
    effective_build_targets = effective_quick_build_targets(build_targets) if quick_reuse_only else build_targets
    if quick_reuse_only:
        needed_arches = {arch for arch, _runtime in variants_needed}
        quick_kernel_cmds: list[tuple[str, list[str]]] = []
        if "rv" in needed_arches:
            quick_kernel_cmds.append(
                ("rv", ["make", f"-j{build_jobs}", "-C", "kernel", "ARCH=riscv", "OUT=../kernel-rv"])
            )
        if "la" in needed_arches:
            quick_kernel_cmds.append(
                ("la", ["make", f"-j{build_jobs}", "-C", "kernel", "ARCH=loongarch", "OUT=../kernel-la"])
            )
            quick_kernel_cmds.append(("la", ["make", f"-j{build_jobs}", "la-bios"]))
        for index, (arch, cmd) in enumerate(quick_kernel_cmds, start=1):
            stage_suffix = f" {index}/{len(quick_kernel_cmds)}" if len(quick_kernel_cmds) > 1 else ""
            if os.environ.get("OSK_REUSE_PREBUILT_QUICK_KERNELS") == "1":
                prebuilt_entries = quick_kernel_cache_paths(arch)
                if all(path.exists() for path, _cache_name in prebuilt_entries):
                    complete_stage(f"reuse kernels quick{stage_suffix}")
                    prepare_qemu_fw()
                    continue
            cache_key = quick_kernel_cache_key(arch)
            if cache_key is not None and restore_quick_kernel_cache(arch, cache_key):
                complete_stage(f"reuse kernels quick{stage_suffix}")
                continue
            stage_name = f"build kernels quick{stage_suffix}"
            require_logged_success(
                stage_name,
                cmd,
                cwd=ROOT,
                log_path=stage_logs / f"kernel-build-quick-{index}.log",
                env={**os.environ, "BUILD_JOBS": str(build_jobs)},
            )
            if cache_key is not None:
                update_quick_kernel_cache(arch, cache_key)
        prepare_qemu_fw()
    else:
        needed_arches = {arch for arch, _runtime in variants_needed}
        if not reuse_prebuilt_quick_kernels_if_available(needed_arches):
            kernel_lock_path = SHARED_CACHE_ROOT / ".kernel-build.lock"
            with FileLock(kernel_lock_path):
                require_logged_success(
                    "build kernels",
                    ["make", f"BUILD_JOBS={build_jobs}", "kernel-rv", "kernel-la", "la-bios"],
                    cwd=ROOT,
                    log_path=stage_logs / "kernel-build.log",
                    env={**os.environ, "BUILD_JOBS": str(build_jobs)},
                )
                prepare_qemu_fw()

    rootfs_root = SHARED_CACHE_ROOT / "rootfs"
    rootfs_root.mkdir(parents=True, exist_ok=True)
    variants: dict[tuple[str, str], Path] = {}
    ordered_variants = sorted(variants_needed)
    worker_count = max(1, min(rootfs_variant_jobs, len(ordered_variants)))
    if worker_count <= 1:
        for arch, runtime in ordered_variants:
            key, out_dir = prepare_variant_rootfs(
                arch,
                runtime,
                rootfs_root=rootfs_root,
                stage_logs=stage_logs,
                build_jobs=build_jobs,
                rebuild_rootfs=rebuild_rootfs,
                effective_build_targets=effective_build_targets,
                quick_reuse_only=quick_reuse_only,
            )
            variants[key] = out_dir
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(
                    prepare_variant_rootfs,
                    arch,
                    runtime,
                    rootfs_root=rootfs_root,
                    stage_logs=stage_logs,
                    build_jobs=build_jobs,
                    rebuild_rootfs=rebuild_rootfs,
                    effective_build_targets=effective_build_targets,
                    quick_reuse_only=quick_reuse_only,
                )
                for arch, runtime in ordered_variants
            ]
            for future in concurrent.futures.as_completed(futures):
                key, out_dir = future.result()
                variants[key] = out_dir
    return variants


def prepare_online_repro_rootfs(
    arch: str,
    arch_samples: list[str],
    *,
    variants: dict[tuple[str, str], Path],
    rebuild_rootfs: bool,
    quick_point_retest: bool,
    ltp_selected_cases: list[str],
    ltp_runtime_mul: float,
    ltp_start_case: str | None,
    kernel_generated_ltp_wrapper: bool = False,
    retry_round: int | None = None,
    prepare_base_image: bool = False,
) -> Path:
    official_rootfs_root = (SHARED_CACHE_ROOT if quick_point_retest else WORK_ROOT) / "rootfs-official"
    official_rootfs_root.mkdir(parents=True, exist_ok=True)
    out_dir = official_rootfs_dir_for_samples(
        official_rootfs_root,
        arch,
        arch_samples,
        ltp_selected_cases,
        ltp_start_case,
    )
    marker = out_dir / ".osk_official_rootfs_ready"
    needs_rebuild = (
        rebuild_rootfs
        or not marker.exists()
        or (bool(ltp_selected_cases) and not quick_point_retest)
        or (bool(ltp_start_case) and not quick_point_retest)
        or official_rootfs_is_stale(
            out_dir,
            arch_samples,
            ltp_selected_cases,
            ltp_start_case,
            kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
        )
    )
    if needs_rebuild:
        stage_name = f"build official rootfs {arch}"
        if retry_round is not None and retry_round > 1:
            stage_name = f"build official rootfs {arch} retry{retry_round}"
        stage_started = begin_stage(stage_name)
        build_official_rootfs_dir(
            arch,
            variants.get((arch, "glibc")),
            variants.get((arch, "musl")),
            out_dir,
            arch_samples,
            ltp_selected_cases,
            ltp_runtime_mul,
            ltp_start_case,
            kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
        )
        assert_official_rootfs_ready(
            out_dir,
            arch_samples,
            ltp_selected_cases,
            ltp_start_case,
            kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
        )
        marker.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
        finish_stage(stage_name, stage_started)
    else:
        refresh_official_rootfs_wrappers(
            out_dir,
            arch_samples,
            ltp_selected_cases,
            ltp_runtime_mul,
            ltp_start_case,
            kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
            arch=arch,
            glibc_rootfs=variants.get((arch, "glibc")),
            musl_rootfs=variants.get((arch, "musl")),
        )
        assert_official_rootfs_ready(
            out_dir,
            arch_samples,
            ltp_selected_cases,
            ltp_start_case,
            kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
        )
        stage_name = f"reuse official rootfs {arch}"
        if retry_round is not None and retry_round > 1:
            stage_name = f"reuse official rootfs {arch} retry{retry_round}"
        complete_stage(stage_name)
    if prepare_base_image:
        stage_name = f"prepare official base image {arch}"
        stage_started = begin_stage(stage_name)
        ensure_official_base_image(out_dir)
        finish_stage(stage_name, stage_started)
    return out_dir


def build_ext4_image(
    base_rootfs: Path,
    image_path: Path,
    *,
    size: str | None = None,
    command: str | None = None,
) -> None:
    with tempfile.TemporaryDirectory(prefix="osk-full-stage.") as stage_tmp:
        stage_dir = Path(stage_tmp) / "root"
        link_copy = subprocess.run(["cp", "-al", str(base_rootfs), str(stage_dir)], check=False, cwd=ROOT)
        if link_copy.returncode != 0:
            if stage_dir.exists():
                shutil.rmtree(stage_dir)
            subprocess.run(["cp", "-a", str(base_rootfs), str(stage_dir)], check=True, cwd=ROOT)
        if command is not None:
            (stage_dir / ".__osk_direct_run__").write_text(command + "\n", encoding="utf-8")
        if size:
            size_arg = size
        else:
            used_kib = int(
                subprocess.check_output(["du", "-sk", str(stage_dir)], text=True, cwd=ROOT).split()[0]
            )
            size_mib = max(128, (used_kib + 1023) // 1024 + OFFICIAL_IMAGE_EXTRA_MIB)
            size_arg = f"{size_mib}M"
        subprocess.run(["truncate", "-s", size_arg, str(image_path)], check=True, cwd=ROOT)
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(stage_dir), str(image_path)], check=True, cwd=ROOT)


def ensure_cached_raw_image(
    cache_dir: Path,
    cache_key: str,
    base_rootfs: Path,
    *,
    size: str | None = None,
    command: str | None = None,
) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    image_path = cache_dir / f"{cache_key}.raw"
    lock_path = cache_dir / f".{cache_key}.lock"
    with FileLock(lock_path):
        if image_path.exists():
            return image_path
        tmp_path = cache_dir / f"{cache_key}.tmp-{os.getpid()}.raw"
        try:
            build_ext4_image(base_rootfs, tmp_path, size=size, command=command)
            os.replace(tmp_path, image_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    return image_path


def ensure_direct_base_image(base_rootfs: Path, command: str) -> Path:
    cache_parts = [
        "direct",
        base_rootfs.name,
        rootfs_ready_token(base_rootfs),
        command,
    ]
    try:
        command_parts = shlex.split(command)
    except ValueError:
        command_parts = []
    ltp_script_arg = next(
        (part for part in reversed(command_parts) if part.endswith("/ltp_testcode.sh")),
        None,
    )
    if ltp_script_arg is not None:
        ltp_script_path = base_rootfs / ltp_script_arg.lstrip("/")
        ltp_runtime_root = ltp_script_path.parent
        cache_parts.extend(
            [
                f"ltp-script:{file_content_token(ltp_script_path)}",
                f"ltp-script-raw:{file_content_token(ltp_runtime_root / '.ltp_testcode.sh.raw')}",
                f"ltp-runtest:{file_content_token(ltp_runtime_root / 'ltp' / 'runtest' / 'syscalls')}",
            ]
        )
    cache_key = hash_key(
        *cache_parts,
    )
    return ensure_cached_raw_image(
        SHARED_CACHE_ROOT / "images" / "direct",
        cache_key,
        base_rootfs,
        size=DIRECT_IMAGE_SIZE,
        command=command,
    )


def ensure_official_base_image(rootfs_dir: Path) -> Path:
    cache_token = hash_key(
        "official",
        rootfs_dir.name,
        marker_text(rootfs_dir / OFFICIAL_CACHE_KEY_FILE) or "missing-cache-key",
        rootfs_ready_token(rootfs_dir),
        f"image-size:{OFFICIAL_IMAGE_SIZE or 'auto'}",
        f"image-extra-mib:{OFFICIAL_IMAGE_EXTRA_MIB}",
    )
    return ensure_cached_raw_image(
        SHARED_CACHE_ROOT / "images" / "official",
        cache_token,
        rootfs_dir,
        size=OFFICIAL_IMAGE_SIZE,
    )


def create_overlay_image(base_image: Path, overlay_path: Path) -> None:
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.unlink(missing_ok=True)
    subprocess.run(
        [
            QEMU_IMG,
            "create",
            "-q",
            "-f",
            "qcow2",
            "-F",
            "raw",
            "-b",
            str(base_image),
            str(overlay_path),
        ],
        check=True,
        cwd=ROOT,
    )


def create_raw_work_image(base_image: Path, image_path: Path) -> None:
    image_path.parent.mkdir(parents=True, exist_ok=True)
    image_path.unlink(missing_ok=True)
    subprocess.run(
        [
            "cp",
            "--reflink=auto",
            "--sparse=always",
            str(base_image),
            str(image_path),
        ],
        check=True,
        cwd=ROOT,
    )


def online_qemu_command(arch: str, image_path: Path, image_format: str = "raw") -> list[str]:
    if arch == "rv":
        return [
            QEMU_SYSTEM_RISCV64,
            "-machine", "virt",
            "-kernel", str(ROOT / "kernel-rv"),
            "-m", "1G",
            "-nographic",
            "-smp", "1",
            "-bios", "default",
            "-drive", f"file={image_path},if=none,format={image_format},id=x0",
            "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
            "-no-reboot",
            "-device", "virtio-net-device,netdev=net",
            "-netdev", "user,id=net",
            "-rtc", "base=utc",
        ]
    return [
        QEMU_SYSTEM_LOONGARCH64,
        "-kernel", str(ROOT / "kernel-la"),
        "-m", "1G",
        "-nographic",
        "-smp", "1",
        "-drive", f"file={image_path},if=none,format={image_format},id=x0",
        "-device", "virtio-blk-pci,drive=x0",
        "-no-reboot",
        "-device", "virtio-net-pci,netdev=net0",
        "-netdev", "user,id=net0",
        "-rtc", "base=utc",
    ]


def qemu_command(arch: str, image_path: Path, image_format: str = "raw") -> list[str]:
    return online_qemu_command(arch, image_path, image_format)


def copy_tree_contents(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    link_copy = subprocess.run(["cp", "-al", f"{src}/.", str(dst)], check=False, cwd=ROOT)
    if link_copy.returncode == 0:
        return
    shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "-a", f"{src}/.", str(dst)], check=True, cwd=ROOT)


def ensure_private_regular_file(path: Path) -> None:
    try:
        st = path.stat()
    except FileNotFoundError:
        return
    if not path.is_file():
        return
    if st.st_nlink <= 1:
        return
    tmp_path = path.with_name(f".{path.name}.osk-private-{os.getpid()}")
    shutil.copy2(path, tmp_path)
    os.replace(tmp_path, path)


def copy_path_if_exists(src_root: Path, dst_root: Path, relative: str) -> None:
    src = src_root / relative
    if not src.exists() and not src.is_symlink():
        return
    dst = dst_root / relative
    if src.is_symlink():
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.unlink(missing_ok=True)
        dst.symlink_to(os.readlink(src))
        return
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, symlinks=True)
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst, follow_symlinks=False)


def official_group_payload_paths(group: str) -> tuple[str, ...]:
    script_name = SCRIPT_BY_GROUP[group]
    payloads = list(OFFICIAL_GROUP_PAYLOADS[group])
    if group != "ltp":
        payloads.append(script_name)
    if group not in {"busybox", "libctest"}:
        payloads.append(f".{script_name}.raw")
    if group == "busybox":
        payloads.append(script_name)
        payloads.append(f".{script_name}.raw")
    if group == "libctest":
        payloads.append(script_name)
        payloads.append(f".{script_name}.raw")
    return tuple(dict.fromkeys(payloads))


def populate_official_runtime_tree(
    src_root: Path | None,
    dst_root: Path,
    runtime: str,
    allowed_groups: set[str],
    *,
    kernel_generated_ltp_wrapper: bool,
) -> None:
    dst_root.mkdir(parents=True, exist_ok=True)
    if not allowed_groups:
        return
    if src_root is None:
        return
    for relative in OFFICIAL_RUNTIME_BASE_ENTRIES:
        copy_path_if_exists(src_root, dst_root, relative)
    if official_preserve_refresh_base_payloads():
        for relative in official_refresh_base_payloads_for_rootfs():
            copy_path_if_exists(src_root, dst_root, relative)
    for group in sorted(allowed_groups):
        for relative in official_group_payload_paths(group):
            if group == "ltp" and kernel_generated_ltp_wrapper and relative in {
                "ltp_testcode.sh",
                ".ltp_testcode.sh.raw",
            }:
                continue
            copy_path_if_exists(src_root, dst_root, relative)


def rewrite_runtime_group_wrapper(runtime_root: Path, runtime: str, group: str) -> None:
    script_name = SCRIPT_BY_GROUP[group]
    script_path = runtime_root / script_name
    if not script_path.exists():
        return
    raw_name = f".{script_name}.raw"
    raw_path = runtime_root / raw_name
    lines = script_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    body = [
        line
        for line in lines
        if "#### OS COMP TEST GROUP START " not in line
        and "#### OS COMP TEST GROUP END " not in line
    ]
    ensure_private_regular_file(raw_path)
    raw_path.write_text("\n".join(body).rstrip() + "\n", encoding="utf-8")
    ensure_private_regular_file(script_path)
    script_path.write_text(
        "\n".join(
            [
                "#!/busybox sh",
                f'/busybox echo "#### OS COMP TEST GROUP START {group}-{runtime} ####"',
                f"/busybox sh /{runtime}/{raw_name}",
                "status=$?",
                f'/busybox echo "#### OS COMP TEST GROUP END {group}-{runtime} ####"',
                "exit $status",
                "",
            ]
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    raw_path.chmod(0o755)


def script_has_runtime_wrapper(script_path: Path, runtime: str, group: str) -> bool:
    if not script_path.exists():
        return False
    text = script_path.read_text(encoding="utf-8", errors="ignore")
    return (
        f"#### OS COMP TEST GROUP START {group}-{runtime} ####" in text
        and f'/busybox echo "#### OS COMP TEST GROUP START {group}-{runtime} ####"' in text
        and f"/busybox sh /{runtime}/.{SCRIPT_BY_GROUP[group]}.raw" in text
        and f'/busybox echo "#### OS COMP TEST GROUP END {group}-{runtime} ####"' in text
        and f"/{runtime}/.{SCRIPT_BY_GROUP[group]}.raw" in text
    )


def refresh_official_rootfs_wrappers(
    rootfs_dir: Path,
    arch_samples: list[str],
    ltp_selected_cases: list[str] | None = None,
    ltp_runtime_mul: float = 1.0,
    ltp_start_case: str | None = None,
    kernel_generated_ltp_wrapper: bool = False,
    arch: str | None = None,
    glibc_rootfs: Path | None = None,
    musl_rootfs: Path | None = None,
) -> None:
    groups_by_runtime = official_runtime_groups_by_runtime(arch_samples)
    allowed = {(group, runtime) for runtime, groups in groups_by_runtime.items() for group in groups}
    for runtime in RUNTIME_ORDER:
        runtime_root = rootfs_dir / runtime
        if not runtime_root.exists():
            continue
        if official_preserve_refresh_base_payloads() and official_wrap_refresh_base_payloads():
            for group in OFFICIAL_REFRESH_BASE_GROUPS:
                script_path = runtime_root / SCRIPT_BY_GROUP[group]
                if script_path.exists():
                    rewrite_runtime_group_wrapper(runtime_root, runtime, group)
        if ("ltp", runtime) in allowed:
            ensure_ltp_script_uses_runtest(runtime_root, ltp_selected_cases, ltp_runtime_mul, ltp_start_case)
            if kernel_generated_ltp_wrapper:
                (runtime_root / SCRIPT_BY_GROUP["ltp"]).unlink(missing_ok=True)
                (runtime_root / f".{SCRIPT_BY_GROUP['ltp']}.raw").unlink(missing_ok=True)
        for group in GROUP_ORDER:
            if (group, runtime) not in allowed:
                continue
            if group == "ltp" and kernel_generated_ltp_wrapper:
                continue
            script_path = runtime_root / SCRIPT_BY_GROUP[group]
            if group == "ltp" and not ltp_raw_script_uses_runtest(runtime_root):
                rewrite_runtime_group_wrapper(runtime_root, runtime, group)
                continue
            if script_has_runtime_wrapper(script_path, runtime, group):
                continue
            rewrite_runtime_group_wrapper(runtime_root, runtime, group)
        if arch is not None:
            apply_official_online_refresh_baseline(arch, runtime, runtime_root)
            stale_official_embedded_refresh_matches(arch, runtime, runtime_root)
    write_official_allowed_runtime_groups(rootfs_dir, arch_samples)
    if arch is not None:
        write_official_rootfs_cache_key(
            rootfs_dir,
            arch,
            arch_samples,
            glibc_rootfs,
            musl_rootfs,
            ltp_selected_cases,
            ltp_runtime_mul,
            ltp_start_case,
            kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
        )


def lmbench_raw_script_has_bench_env(raw_path: Path) -> bool:
    if not raw_path.exists():
        return False
    text = raw_path.read_text(encoding="utf-8", errors="ignore")
    return (
        bool(re.search(r"^export ENOUGH=\d+(?:\.\d+)?$", text, re.MULTILINE))
        and "export TIMING_O=0" in text
        and "export LOOP_O=0" in text
    )


def lmbench_script_has_bench_env(script_path: Path) -> bool:
    if not script_path.exists():
        return False
    text = script_path.read_text(encoding="utf-8", errors="ignore")
    return (
        bool(re.search(r"^export ENOUGH=\d+(?:\.\d+)?$", text, re.MULTILINE))
        and "export TIMING_O=0" in text
        and "export LOOP_O=0" in text
    )


def glibc_runtime_support_is_stale(rootfs_dir: Path) -> bool:
    libgcc_candidates = [
        rootfs_dir / "lib" / "libgcc_s.so.1",
        rootfs_dir / "lib64" / "libgcc_s.so.1",
    ]
    locale_ctype_candidates = [
        rootfs_dir / "usr" / "lib" / "locale" / "C.utf8" / "LC_CTYPE",
        rootfs_dir / "usr" / "lib" / "locale" / "locale-archive",
    ]
    return not any(path.exists() for path in libgcc_candidates) or not any(
        path.exists() for path in locale_ctype_candidates
    )


def official_glibc_runtime_support_is_stale(rootfs_dir: Path) -> bool:
    libgcc_candidates = [
        rootfs_dir / "lib" / "libgcc_s.so.1",
        rootfs_dir / "lib64" / "libgcc_s.so.1",
    ]
    return not any(path.exists() for path in libgcc_candidates)


def file_is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as file:
            return file.read(4) == b"\x7fELF"
    except OSError:
        return False


def musl_loader_candidates(rootfs_dir: Path) -> list[Path]:
    return [
        rootfs_dir / "lib" / "ld-musl-riscv64.so.1",
        rootfs_dir / "lib" / "ld-musl-loongarch64.so.1",
        rootfs_dir / "lib64" / "ld-musl-loongarch-lp64d.so.1",
    ]


def musl_runtime_support_is_stale(rootfs_dir: Path) -> bool:
    libc_candidates = [
        rootfs_dir / "lib" / "libc.so",
        rootfs_dir / "lib64" / "libc.so",
    ]
    libc_path = next((path for path in libc_candidates if path.exists()), None)
    if libc_path is None or not file_is_elf(libc_path):
        return True

    loader_paths = [path for path in musl_loader_candidates(rootfs_dir) if path.exists() or path.is_symlink()]
    if not loader_paths:
        return True
    for loader_path in loader_paths:
        if loader_path.is_symlink():
            target = os.readlink(loader_path)
            if target == "/lib/libc.so":
                return True
        elif not file_is_elf(loader_path):
            return True
    return False


def readelf_defined_symbols(path: Path, symbol_names: set[str]) -> set[str] | None:
    readelf = shutil.which("readelf")
    if readelf is None:
        return None
    try:
        proc = subprocess.run(
            [readelf, "-Ws", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None

    defined: set[str] = set()
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        name = fields[-1]
        ndx = fields[-2]
        if name in symbol_names and ndx != "UND":
            defined.add(name)
    return defined


def musl_cyclictest_sched_shim_is_stale(rootfs_dir: Path) -> bool:
    cyclictest = rootfs_dir / "cyclictest"
    if not cyclictest.exists():
        return True
    required_symbols = {
        "sched_setparam",
        "sched_setscheduler",
        "sched_getscheduler",
        "sched_getparam",
    }
    defined = readelf_defined_symbols(cyclictest, required_symbols)
    if defined is None:
        return False
    return not required_symbols.issubset(defined)


def official_rootfs_is_stale(
    rootfs_dir: Path,
    arch_samples: list[str],
    ltp_selected_cases: list[str] | None = None,
    ltp_start_case: str | None = None,
    *,
    kernel_generated_ltp_wrapper: bool = False,
) -> bool:
    allowed_groups_path = rootfs_dir / OFFICIAL_ALLOWED_GROUPS_FILE
    expected_allowed_groups = official_allowed_runtime_groups(arch_samples)
    if not allowed_groups_path.exists():
        return True
    actual_allowed_groups = [
        line.strip()
        for line in allowed_groups_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]
    if actual_allowed_groups != expected_allowed_groups:
        return True

    groups_by_runtime = official_runtime_groups_by_runtime(arch_samples)

    for runtime, groups in groups_by_runtime.items():
        runtime_root = rootfs_dir / runtime
        for group in GROUP_ORDER:
            script_name = SCRIPT_BY_GROUP[group]
            script_path = runtime_root / script_name
            raw_path = runtime_root / f".{script_name}.raw"
            allowed = group in groups
            if allowed:
                if group == "ltp" and kernel_generated_ltp_wrapper:
                    if script_path.exists() or raw_path.exists():
                        return True
                elif not script_path.exists() or not raw_path.exists():
                    return True
                for relative in OFFICIAL_GROUP_PAYLOADS[group]:
                    payload_path = runtime_root / relative
                    if not payload_path.exists() and not payload_path.is_symlink():
                        return True
                if group == "lmbench" and not lmbench_raw_script_has_bench_env(raw_path):
                    return True
                if group == "ltp":
                    if not kernel_generated_ltp_wrapper and not ltp_raw_script_uses_runtest(runtime_root):
                        return True
                    if ltp_runtime_support_is_stale(runtime_root):
                        return True
                    src = LTP_RUNTEST_PATH
                    runtest_path = runtime_root / "ltp" / "runtest" / "syscalls"
                    if src.exists() and runtest_path.exists():
                        expected_lines = filter_ltp_runtest_lines(
                            read_ltp_runtest_lines(src),
                            ltp_selected_cases,
                            ltp_start_case,
                        )
                        actual_lines = read_ltp_runtest_lines(runtest_path)
                        if actual_lines != expected_lines:
                            return True
                if runtime == "musl" and group == "cyclictest" and musl_cyclictest_sched_shim_is_stale(runtime_root):
                    return True
                continue
            preserve_refresh_base = official_preserve_refresh_base_payloads()
            if script_path.exists() and (
                not preserve_refresh_base or script_name not in OFFICIAL_REFRESH_BASE_PAYLOADS
            ):
                return True
            if raw_path.exists() and (
                not preserve_refresh_base or f".{script_name}.raw" not in OFFICIAL_REFRESH_BASE_PAYLOADS
            ):
                return True
            for relative in official_group_payload_paths(group):
                if preserve_refresh_base and relative in official_refresh_base_payloads_for_rootfs():
                    continue
                payload_path = runtime_root / relative
                if payload_path.exists() or payload_path.is_symlink():
                    return True
        if groups:
            for relative in OFFICIAL_REQUIRED_RUNTIME_BASE_ENTRIES:
                payload_path = runtime_root / relative
                if not payload_path.exists() and not payload_path.is_symlink():
                    return True
            if official_preserve_refresh_base_payloads():
                for relative in official_refresh_base_payloads_for_rootfs():
                    payload_path = runtime_root / relative
                    if not payload_path.exists() and not payload_path.is_symlink():
                        return True
        if runtime == "glibc" and groups and official_glibc_runtime_support_is_stale(runtime_root):
            return True
        if runtime == "musl" and groups and musl_runtime_support_is_stale(runtime_root):
            return True
    return False


def assert_official_rootfs_ready(
    rootfs_dir: Path,
    arch_samples: list[str],
    ltp_selected_cases: list[str] | None = None,
    ltp_start_case: str | None = None,
    *,
    kernel_generated_ltp_wrapper: bool = False,
) -> None:
    if official_rootfs_is_stale(
        rootfs_dir,
        arch_samples,
        ltp_selected_cases,
        ltp_start_case,
        kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
    ):
        raise RuntimeError(f"official rootfs is stale after build/refresh: {rootfs_dir}")


def official_preserve_all_groups() -> bool:
    return os.environ.get("OSK_OFFICIAL_PRESERVE_ALL_GROUPS", "").lower() in {"1", "true", "yes", "on"}


def official_preserve_refresh_base_payloads() -> bool:
    value = os.environ.get("OSK_OFFICIAL_PRESERVE_REFRESH_BASE_PAYLOADS")
    if value is None:
        return True
    return value.lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def official_wrap_refresh_base_payloads() -> bool:
    value = os.environ.get("OSK_OFFICIAL_WRAP_REFRESH_BASE_PAYLOADS")
    if value is None:
        return True
    return value.lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def official_refresh_base_payloads_for_rootfs() -> tuple[str, ...]:
    if official_wrap_refresh_base_payloads():
        return OFFICIAL_REFRESH_BASE_PAYLOADS
    return tuple(relative for relative in OFFICIAL_REFRESH_BASE_PAYLOADS if not relative.startswith("."))


def official_stale_embedded_refresh_matches() -> bool:
    return os.environ.get("OSK_OFFICIAL_STALE_EMBEDDED_REFRESH_MATCHES", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def official_online_refresh_baseline() -> bool:
    return os.environ.get("OSK_OFFICIAL_ONLINE_REFRESH_BASELINE", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def files_match(lhs: Path, rhs: Path) -> bool:
    if not lhs.is_file() or not rhs.is_file():
        return False
    try:
        if lhs.stat().st_size != rhs.stat().st_size:
            return False
        with lhs.open("rb") as lhs_file, rhs.open("rb") as rhs_file:
            while True:
                lhs_chunk = lhs_file.read(1024 * 1024)
                rhs_chunk = rhs_file.read(1024 * 1024)
                if lhs_chunk != rhs_chunk:
                    return False
                if not lhs_chunk:
                    return True
    except OSError:
        return False


def stale_matching_official_file(dst_path: Path, src_path: Path) -> None:
    if not files_match(dst_path, src_path):
        return
    ensure_private_regular_file(dst_path)
    with dst_path.open("ab") as file:
        file.write(b"\nOSK_OFFICIAL_STALE_BASELINE\n")


def apply_official_online_refresh_baseline(arch: str, runtime: str, runtime_root: Path) -> None:
    if not official_online_refresh_baseline():
        return
    refresh_root = ROOT / "kernel/starry-next" / "embedded-runtime-refresh" / arch / runtime
    for relative in OFFICIAL_ONLINE_REFRESH_BASELINE_MISSING.get((arch, runtime), ()):
        path = runtime_root / relative
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    for relative in OFFICIAL_ONLINE_REFRESH_BASELINE_EXACT.get((arch, runtime), ()):
        copy_path_if_exists(refresh_root, runtime_root, relative)


def stale_official_embedded_refresh_matches(arch: str, runtime: str, runtime_root: Path) -> None:
    if not official_stale_embedded_refresh_matches():
        return
    refresh_root = ROOT / "kernel/starry-next" / "embedded-runtime-refresh" / arch / runtime
    if not refresh_root.is_dir():
        return

    relative_paths: set[str] = set()
    for relative in OFFICIAL_REFRESH_BASE_PAYLOADS:
        src_path = refresh_root / relative
        if src_path.is_file():
            relative_paths.add(relative)
            continue
        if not src_path.is_dir():
            continue
        for path in src_path.rglob("*"):
            if path.is_file():
                relative_paths.add(path.relative_to(refresh_root).as_posix())
    if arch == "rv" and runtime == "glibc":
        relative_paths.update(
            {
                "lib/ld-linux-riscv64-lp64d.so.1",
                "lib/libc.so.6",
            }
        )
    if official_online_refresh_baseline():
        relative_paths.difference_update(OFFICIAL_ONLINE_REFRESH_BASELINE_EXACT.get((arch, runtime), ()))
    for relative in sorted(relative_paths):
        src_path = refresh_root / relative
        dst_path = runtime_root / relative
        if not src_path.is_file() or not dst_path.is_file():
            continue
        stale_matching_official_file(dst_path, src_path)


def official_runtime_groups_by_runtime(arch_samples: list[str]) -> dict[str, set[str]]:
    groups_by_runtime: dict[str, set[str]] = {"glibc": set(), "musl": set()}
    for sample in arch_samples:
        group, runtime, _ = parse_sample(sample)
        groups_by_runtime.setdefault(runtime, set()).add(group)
    if official_preserve_all_groups():
        for runtime, groups in list(groups_by_runtime.items()):
            if groups:
                groups_by_runtime[runtime] = set(GROUP_ORDER)
    return groups_by_runtime


def official_allowed_runtime_groups(arch_samples: list[str]) -> list[str]:
    groups_by_runtime = official_runtime_groups_by_runtime(arch_samples)
    return sorted({
        f"{runtime}:{group}"
        for runtime, groups in groups_by_runtime.items()
        for group in groups
    })


def write_official_allowed_runtime_groups(rootfs_dir: Path, arch_samples: list[str]) -> None:
    content = "\n".join(official_allowed_runtime_groups(arch_samples)).rstrip() + "\n"
    (rootfs_dir / OFFICIAL_ALLOWED_GROUPS_FILE).write_text(content, encoding="utf-8")


def official_rootfs_cache_key(
    arch: str,
    arch_samples: list[str],
    glibc_rootfs: Path | None,
    musl_rootfs: Path | None,
    ltp_selected_cases: list[str] | None,
    ltp_runtime_mul: float,
    ltp_start_case: str | None,
    kernel_generated_ltp_wrapper: bool = False,
) -> str:
    cache_key_parts = [
        arch,
        *sorted(arch_samples),
        f"preserve-all-groups:{int(official_preserve_all_groups())}",
        f"preserve-refresh-base:{int(official_preserve_refresh_base_payloads())}",
        f"wrap-refresh-base:{int(official_wrap_refresh_base_payloads())}",
        f"stale-embedded-refresh-matches:{int(official_stale_embedded_refresh_matches())}",
        f"online-refresh-baseline:{int(official_online_refresh_baseline())}",
        f"kernel-generated-ltp-wrapper:{int(kernel_generated_ltp_wrapper)}",
        *[f"allow:{item}" for item in official_allowed_runtime_groups(arch_samples)],
        *[f"ltp:{case}" for case in sorted(ltp_selected_cases or [])],
    ]
    if any(parse_sample(sample)[0] == "ltp" for sample in arch_samples):
        cache_key_parts.append(f"ltp-runtime-mul:{format_ltp_runtime_mul(ltp_runtime_mul)}")
    if ltp_start_case:
        cache_key_parts.append(f"ltp-start:{ltp_start_case}")
    if glibc_rootfs is not None:
        cache_key_parts.append(f"glibc-rootfs:{rootfs_ready_token(glibc_rootfs)}")
    if musl_rootfs is not None:
        cache_key_parts.append(f"musl-rootfs:{rootfs_ready_token(musl_rootfs)}")
    return hash_key(*cache_key_parts)


def write_official_rootfs_cache_key(
    rootfs_dir: Path,
    arch: str,
    arch_samples: list[str],
    glibc_rootfs: Path | None,
    musl_rootfs: Path | None,
    ltp_selected_cases: list[str] | None,
    ltp_runtime_mul: float,
    ltp_start_case: str | None,
    kernel_generated_ltp_wrapper: bool = False,
) -> None:
    (rootfs_dir / OFFICIAL_CACHE_KEY_FILE).write_text(
        official_rootfs_cache_key(
            arch,
            arch_samples,
            glibc_rootfs,
            musl_rootfs,
            ltp_selected_cases,
            ltp_runtime_mul,
            ltp_start_case,
            kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
        ) + "\n",
        encoding="utf-8",
    )


def variant_rootfs_is_stale(rootfs_dir: Path, runtime: str, build_targets: str | None) -> bool:
    target_to_group = {
        "basic": "basic",
        "busybox": "busybox",
        "lua": "lua",
        "iozone": "iozone",
        "iperf": "iperf",
        "libcbench": "libcbench",
        "libc-test": "libctest",
        "lmbench_src": "lmbench",
        "cyclictest": "cyclictest",
        "ltp": "ltp",
        "netperf": "netperf",
    }
    target_required_payloads = {
        "basic": ("basic", "basic_testcode.sh"),
        "busybox": ("busybox", "busybox_cmd.txt", "busybox_testcode.sh"),
        "libc-test": ("libctest_testcode.sh", "entry-static.exe", "entry-dynamic.exe"),
        "cyclictest": ("cyclictest", "hackbench", "cyclictest_testcode.sh"),
    }
    if build_targets is None:
        required_groups = set(GROUP_ORDER)
        required_targets = set(target_to_group)
    else:
        required_groups = {
            group for target, group in target_to_group.items() if target in build_targets.split()
        }
        required_targets = {target for target in target_to_group if target in build_targets.split()}
    for group in required_groups:
        script_path = rootfs_dir / SCRIPT_BY_GROUP[group]
        if not script_path.exists():
            return True
        if group == "lmbench" and not lmbench_script_has_bench_env(script_path):
            return True
        if group == "ltp" and ltp_runtime_support_is_stale(rootfs_dir):
            return True
        if runtime == "musl" and group == "cyclictest" and musl_cyclictest_sched_shim_is_stale(rootfs_dir):
            return True
    for target in required_targets:
        for relative in target_required_payloads.get(target, ()):
            path = rootfs_dir / relative
            if not path.exists() and not path.is_symlink():
                return True
    if runtime == "glibc" and glibc_runtime_support_is_stale(rootfs_dir):
        return True
    if runtime == "musl" and musl_runtime_support_is_stale(rootfs_dir):
        return True
    return False


def build_official_rootfs_dir(
    arch: str,
    glibc_rootfs: Path | None,
    musl_rootfs: Path | None,
    out_dir: Path,
    samples: list[str],
    ltp_selected_cases: list[str] | None = None,
    ltp_runtime_mul: float = 1.0,
    ltp_start_case: str | None = None,
    *,
    kernel_generated_ltp_wrapper: bool = False,
) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    glibc_dir = out_dir / "glibc"
    musl_dir = out_dir / "musl"
    arch_samples = [sample for sample in samples if sample.endswith(f"-{arch}")]
    groups_by_runtime = official_runtime_groups_by_runtime(arch_samples)
    populate_official_runtime_tree(
        glibc_rootfs,
        glibc_dir,
        "glibc",
        groups_by_runtime.get("glibc", set()),
        kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
    )
    populate_official_runtime_tree(
        musl_rootfs,
        musl_dir,
        "musl",
        groups_by_runtime.get("musl", set()),
        kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
    )
    for runtime_root, runtime in ((glibc_dir, "glibc"), (musl_dir, "musl")):
        if official_preserve_refresh_base_payloads() and official_wrap_refresh_base_payloads():
            for group in OFFICIAL_REFRESH_BASE_GROUPS:
                script_path = runtime_root / SCRIPT_BY_GROUP[group]
                if script_path.exists():
                    rewrite_runtime_group_wrapper(runtime_root, runtime, group)
        for group in GROUP_ORDER:
            if group not in groups_by_runtime.get(runtime, set()):
                continue
            if group == "ltp":
                ensure_ltp_script_uses_runtest(runtime_root, ltp_selected_cases, ltp_runtime_mul, ltp_start_case)
                if kernel_generated_ltp_wrapper:
                    (runtime_root / SCRIPT_BY_GROUP[group]).unlink(missing_ok=True)
                    (runtime_root / f".{SCRIPT_BY_GROUP[group]}.raw").unlink(missing_ok=True)
                    continue
            rewrite_runtime_group_wrapper(runtime_root, runtime, group)
        apply_official_online_refresh_baseline(arch, runtime, runtime_root)
        stale_official_embedded_refresh_matches(arch, runtime, runtime_root)
    write_official_allowed_runtime_groups(out_dir, arch_samples)
    sort_src = musl_dir / "sort.src"
    if sort_src.exists() and not (out_dir / "sort.src").exists():
        shutil.copy2(sort_src, out_dir / "sort.src")
    write_official_rootfs_cache_key(
        out_dir,
        arch,
        arch_samples,
        glibc_rootfs,
        musl_rootfs,
        ltp_selected_cases,
        ltp_runtime_mul,
        ltp_start_case,
        kernel_generated_ltp_wrapper=kernel_generated_ltp_wrapper,
    )


def official_rootfs_dir_for_samples(
    root: Path,
    arch: str,
    samples: list[str],
    ltp_selected_cases: list[str] | None = None,
    ltp_start_case: str | None = None,
) -> Path:
    arch_samples = sorted(sample for sample in samples if sample.endswith(f"-{arch}"))
    if not arch_samples or arch_samples == [sample for sample in SAMPLE_ORDER if sample.endswith(f"-{arch}")]:
        if not ltp_selected_cases and not ltp_start_case:
            return root / arch
        digest_parts = [*sorted(ltp_selected_cases or [])]
        if ltp_start_case:
            digest_parts.append(f"start:{ltp_start_case}")
        digest = hashlib.sha1("\n".join(digest_parts).encode("utf-8")).hexdigest()[:12]
        return root / f"{arch}-ltp-{digest}"
    digest_input = arch_samples.copy()
    if ltp_selected_cases:
        digest_input.extend(f"ltp:{case}" for case in sorted(ltp_selected_cases))
    if ltp_start_case:
        digest_input.append(f"ltp-start:{ltp_start_case}")
    digest = hashlib.sha1("\n".join(digest_input).encode("utf-8")).hexdigest()[:12]
    return root / f"{arch}-subset-{digest}"


def official_ltp_worker_rootfs_dir(
    root: Path,
    sample: str,
    worker_count: int,
    worker_index: int,
) -> Path:
    group, runtime, arch = parse_sample(sample)
    assert group == "ltp"
    return root / f"{arch}-{runtime}-ltp-worker{worker_index + 1:02d}-of-{worker_count:02d}"


def official_qemu_command(arch: str, image_path: Path, image_format: str = "raw") -> list[str]:
    return online_qemu_command(arch, image_path, image_format)


def official_use_raw_image() -> bool:
    return os.environ.get("OSK_OFFICIAL_USE_RAW_IMAGE", "").lower() in {"1", "true", "yes", "on"}


ZERO_DETAILS_CACHE: dict[str, list[DetailRow]] = {}


def clone_details(rows: list[DetailRow]) -> list[DetailRow]:
    return [DetailRow(name=row.name, passed=row.passed, total=row.total, status=row.status) for row in rows]


def zero_details_for_group(group: str) -> list[DetailRow]:
    cached = ZERO_DETAILS_CACHE.get(group)
    if cached is not None:
        return clone_details(cached)

    if group == "basic":
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            rows = parse_basic_details(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    elif group == "iozone":
        labels = []
        path = TESTSUITS_ROOT / "scripts/iozone/iozone_testcode.sh"
        for line in read_text(path).splitlines():
            if "./busybox echo " not in line:
                continue
            label = line.split("./busybox echo ", 1)[1].strip().strip('"')
            if label.startswith("####"):
                continue
            labels.append(label)
        rows = [DetailRow(name=label, passed=0, total=1, status="fail") for label in labels]
    elif group == "lmbench":
        rows = [DetailRow(name=name, passed=0, total=1, status="fail") for name in LMBENCH_ZERO_DETAIL_NAMES]
    else:
        parser = DETAIL_PARSERS[group]
        rows = parser([])  # type: ignore[arg-type]
    ZERO_DETAILS_CACHE[group] = clone_details(rows)
    return rows


def write_group_log(full_log: Path, group_name: str, out_path: Path) -> str:
    lines, status = extract_group_with_status(read_text(full_log), group_name)
    if status == "missing":
        out_path.write_text("", encoding="utf-8")
        return status
    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return status


def zero_result_for_missing_group(sample: str, log_path: Path, error: str) -> CaseResult:
    group, runtime, arch = parse_sample(sample)
    result = CaseResult(sample=sample, group=group, runtime=runtime, arch=arch, log_path=log_path)
    result.details = zero_details_for_group(group)
    result.ok = False
    result.error = error
    result.summary = f"{result.passed}/{result.total}"
    return result


def zero_result_for_incomplete_group(
    sample: str,
    log_path: Path,
    error: str,
    *,
    timed_out: bool = False,
    stop_reason: str | None = None,
) -> CaseResult:
    result = zero_result_for_missing_group(sample, log_path, error)
    result.timed_out = timed_out
    result.stop_reason = stop_reason
    return result


def partial_result_for_group(
    sample: str,
    log_path: Path,
    error: str,
    *,
    timed_out: bool = False,
    stop_reason: str | None = None,
    returncode: int | None = None,
) -> CaseResult:
    try:
        result = validate_case(sample, log_path)
    except Exception:
        result = zero_result_for_missing_group(sample, log_path, error)
    result.ok = False
    result.error = error
    result.timed_out = timed_out
    result.stop_reason = stop_reason
    result.returncode = returncode
    result.summary = f"{result.passed}/{result.total}"
    return result


def stopped_before_group_result(
    sample: str,
    log_path: Path,
    group_name: str,
    stop_reason: str | None,
    returncode: int | None,
) -> CaseResult:
    error = f"earlier group stopped before start marker for {group_name}"
    result = zero_result_for_incomplete_group(
        sample,
        log_path,
        error,
        timed_out=True,
        stop_reason=stop_reason or error,
    )
    result.returncode = returncode
    return result


def emit_recovered_official_case(
    arch: str,
    group: str,
    runtime: str,
    started_at: float | None,
    result: CaseResult,
) -> None:
    label = official_case_label(group, runtime, arch)
    if started_at is None:
        console(f"[case] {label} points {result.passed}/{result.total}")
        return
    console(
        f"[case] {label} {format_duration(max(0.0, time.monotonic() - started_at))} "
        f"points {result.passed}/{result.total}"
    )


def emit_live_ltp_case_progress(
    arch: str,
    runtime: str,
    case_name: str,
    elapsed: float,
    case_passed: bool,
    point_totals: dict[str, int],
    point_passed: dict[str, int],
    finished_cases: set[str],
    point_finished_count: dict[str, int],
    reported_points: set[str],
) -> None:
    if case_name in finished_cases:
        return
    finished_cases.add(case_name)
    point = ltp_point_name(case_name)
    if case_passed:
        point_passed[point] = point_passed.get(point, 0) + 1
    point_finished_count[point] = point_finished_count.get(point, 0) + 1
    total = point_totals.get(point, 1)
    if point_finished_count[point] < total or point in reported_points:
        return
    reported_points.add(point)
    passed = point_passed.get(point, 0)
    duration = format_duration(elapsed) if elapsed >= 0 else None
    label = f"{runtime}-{arch}-ltp-{point}"
    if duration is None:
        console(f"[case] {label} points {passed}/{total}")
    else:
        console(f"[case] {label} {duration} points {passed}/{total}")


def should_retry_official_sample(result: CaseResult) -> bool:
    if not result.error:
        return False
    return (
        result.error.startswith("earlier group stopped before start marker for ")
        or result.error.startswith("earlier group watchdog timeout before start marker for ")
        or result.error.startswith("incomplete group markers for ")
        or result.error.startswith("group timed out before end marker for ")
    )


def can_isolate_retry_head(
    pending_samples: list[str],
    arch_results: dict[str, CaseResult],
    retry_samples: list[str],
) -> bool:
    if retry_samples != pending_samples or len(pending_samples) <= 1:
        return False
    head = pending_samples[0]
    head_result = arch_results.get(head)
    if head_result is None or not should_retry_official_sample(head_result):
        return False
    head_error = head_result.error or ""
    if not (
        head_error.startswith("incomplete group markers for ")
        or head_error.startswith("group timed out before end marker for ")
    ):
        return False
    return any(
        (arch_results.get(sample).error or "").startswith("earlier group")
        for sample in pending_samples[1:]
        if arch_results.get(sample) is not None
    )


def run_official_arch(
    arch: str,
    rootfs_dir: Path,
    logs_dir: Path,
    timeout: int,
    samples: list[str],
) -> dict[str, CaseResult]:
    arch_results: dict[str, CaseResult] = {}
    raw_log_path = logs_dir / f"official-{arch}.raw.out"
    use_raw_image = official_use_raw_image()
    image_path = logs_dir / (f"official-{arch}.img" if use_raw_image else f"official-{arch}.qcow2")
    base_image_path = ensure_official_base_image(rootfs_dir)
    image_format = "raw" if use_raw_image else "qcow2"
    if use_raw_image:
        create_raw_work_image(base_image_path, image_path)
    else:
        create_overlay_image(base_image_path, image_path)
    relevant_samples = sorted(
        (sample for sample in samples if sample.endswith(f"-{arch}")),
        key=official_execution_key,
    )
    progress = OfficialProgressReporter(
        arch,
        raw_log_path,
        logs_dir,
    )
    effective_timeout = None if all(parse_sample(sample)[0] == "ltp" for sample in relevant_samples) else timeout
    try:
        returncode, timed_out, stop_reason = run_qemu(
            official_qemu_command(arch, image_path, image_format=image_format),
            raw_log_path,
            effective_timeout,
            silent_idle_timeout=None,
            on_output=progress.consume,
            on_poll=progress.poll,
        )
        if timed_out:
            prior_group_stop_reason: str | None = None
            for sample in relevant_samples:
                if sample in progress.completed_results:
                    result = progress.completed_results[sample]
                    result.returncode = returncode
                    arch_results[sample] = result
                    if result.timed_out:
                        prior_group_stop_reason = result.error or result.stop_reason or stop_reason
                    continue
                group, runtime, _ = parse_sample(sample)
                sample_log_path = logs_dir / f"{sample}.out"
                group_name = f"{group}-{runtime}"
                if prior_group_stop_reason is not None:
                    result = stopped_before_group_result(
                        sample,
                        sample_log_path,
                        group_name,
                        prior_group_stop_reason,
                        returncode,
                    )
                    arch_results[sample] = result
                    continue
                group_log_status = write_group_log(raw_log_path, group_name, sample_log_path)
                if group == "ltp" and group_log_status in {"complete", "partial"}:
                    normalize_ltp_log_file(sample_log_path)
                if group_log_status == "complete":
                    try:
                        result = validate_case(sample, sample_log_path)
                        result.returncode = returncode
                    except Exception as exc:
                        result = zero_result_for_missing_group(sample, sample_log_path, str(exc))
                        result.returncode = returncode
                elif group_log_status == "partial":
                    partial_timed_out = True
                    result = partial_result_for_group(
                        sample,
                        sample_log_path,
                        stop_reason or f"incomplete group markers for {group_name}",
                        timed_out=partial_timed_out,
                        stop_reason=stop_reason,
                        returncode=returncode,
                    )
                    prior_group_stop_reason = result.error or result.stop_reason or stop_reason
                else:
                    result = stopped_before_group_result(
                        sample,
                        sample_log_path,
                        group_name,
                        stop_reason or (
                            f"timeout after {effective_timeout}s" if effective_timeout is not None else "stopped"
                        ),
                        returncode,
                    )
                    prior_group_stop_reason = result.error or result.stop_reason or stop_reason
                arch_results[sample] = result
                if not should_retry_official_sample(result):
                    console(f"[case] {official_case_label(group, runtime, arch)} timeout points {result.passed}/{result.total}")
            return arch_results

        raw_text = read_text(raw_log_path)
        raw_lines = raw_text.splitlines()
        raw_watchdog_reason = find_competition_script_watchdog_reason(raw_text)
        raw_fatal_reason = fatal_log_reason(raw_lines)
        prior_group_stop_reason: str | None = None
        for sample in relevant_samples:
            if sample in progress.completed_results:
                result = progress.completed_results[sample]
                result.returncode = returncode
                arch_results[sample] = result
                if should_retry_official_sample(result):
                    prior_group_stop_reason = result.error or result.stop_reason or prior_group_stop_reason
                continue
            group, runtime, _ = parse_sample(sample)
            started_at = progress.started.pop((group, runtime), None)
            sample_log_path = logs_dir / f"{sample}.out"
            group_name = f"{group}-{runtime}"
            if prior_group_stop_reason is not None:
                result = stopped_before_group_result(
                    sample,
                    sample_log_path,
                    group_name,
                    prior_group_stop_reason,
                    returncode,
                )
                arch_results[sample] = result
                continue
            group_log_status = write_group_log(raw_log_path, group_name, sample_log_path)
            if group == "ltp" and group_log_status in {"complete", "partial"}:
                normalize_ltp_log_file(sample_log_path)
            if group_log_status == "missing":
                if raw_watchdog_reason is not None:
                    error = f"earlier group watchdog timeout before start marker for {group_name}"
                    result = zero_result_for_incomplete_group(
                        sample,
                        sample_log_path,
                        error,
                        timed_out=True,
                        stop_reason=raw_watchdog_reason,
                    )
                    prior_group_stop_reason = raw_watchdog_reason
                elif raw_fatal_reason is not None:
                    result = stopped_before_group_result(
                        sample,
                        sample_log_path,
                        group_name,
                        raw_fatal_reason,
                        returncode,
                    )
                    prior_group_stop_reason = raw_fatal_reason
                else:
                    result = zero_result_for_missing_group(
                        sample,
                        sample_log_path,
                        f"missing group markers for {group_name}",
                    )
                result.returncode = returncode
                arch_results[sample] = result
                continue
            if group_log_status == "partial":
                partial_text = read_text(sample_log_path)
                partial_timed_out = "Competition script watchdog timeout" in partial_text
                error = (
                    f"incomplete group markers for {group_name}"
                    if not partial_timed_out
                    else f"group timed out before end marker for {group_name}"
                )
                result = partial_result_for_group(
                    sample,
                    sample_log_path,
                    error,
                    timed_out=partial_timed_out,
                    returncode=returncode,
                )
                prior_group_stop_reason = result.error or result.stop_reason or error
                arch_results[sample] = result
                emit_recovered_official_case(arch, group, runtime, started_at, result)
                continue
            try:
                result = validate_case(sample, sample_log_path)
                result.returncode = returncode
            except Exception as exc:
                result = zero_result_for_missing_group(sample, sample_log_path, str(exc))
                result.returncode = returncode
            arch_results[sample] = result
            emit_recovered_official_case(arch, group, runtime, started_at, result)
        return arch_results
    finally:
        image_path.unlink(missing_ok=True)


def run_qemu(
    cmd: list[str],
    log_path: Path,
    timeout: int | None,
    *,
    silent_idle_timeout: float | None = SILENT_IDLE_TIMEOUT,
    pre_output_idle_timeout: float | None = None,
    on_output: Callable[[list[str], float], str | None] | None = None,
    on_poll: Callable[[float], str | None] | None = None,
    suppress_live_log: bool = False,
) -> tuple[int | None, bool, str | None]:
    return run_logged_command(
        cmd,
        cwd=ROOT,
        log_path=log_path,
        timeout=timeout,
        fatal_idle_timeout=FATAL_IDLE_TIMEOUT,
        silent_idle_timeout=silent_idle_timeout,
        pre_output_idle_timeout=pre_output_idle_timeout,
        on_output=on_output,
        on_poll=on_poll,
        suppress_live_log=suppress_live_log,
    )


def validate_case(sample: str, log_path: Path, expected_cases_override: list[str] | None = None) -> CaseResult:
    group, runtime, arch = parse_sample(sample)
    result = CaseResult(sample=sample, group=group, runtime=runtime, arch=arch, log_path=log_path)
    text = read_text(log_path)
    try:
        lines = extract_group(text, group)
    except Exception:
        lines = [sanitize_line(line) for line in text.splitlines()]
    if group == "basic":
        details = parse_basic_details(log_path)
    elif group == "ltp" and expected_cases_override is not None:
        details = parse_ltp_details_for_cases(lines, expected_cases_override)
    else:
        parser = DETAIL_PARSERS[group]
        details = parser(lines)
    result.details = details
    result.ok = all(row.passed == row.total for row in details)
    result.summary = f"{result.passed}/{result.total}"
    return result


def run_sample_from_rootfs(
    sample: str,
    rootfs_dir: Path,
    logs_dir: Path,
    timeout: int,
    *,
    command_override: str | None = None,
    expected_cases_override: list[str] | None = None,
    log_stem: str | None = None,
    silent_idle_timeout: float | None = SILENT_IDLE_TIMEOUT,
    pre_output_idle_timeout: float | None = None,
    cleanup_base_image: bool = False,
    on_output: Callable[[list[str], float], str | None] | None = None,
    on_poll: Callable[[float], str | None] | None = None,
    suppress_live_log: bool = False,
    normalize_ltp_log: bool = True,
) -> CaseResult:
    group, runtime, arch = parse_sample(sample)
    stem = log_stem or sample
    log_path = logs_dir / f"{stem}.out"
    image_path = logs_dir / f"{stem}.qcow2"
    command = command_override or f"/busybox sh /{SCRIPT_BY_GROUP[group]}"
    base_image_path = ensure_direct_base_image(rootfs_dir, command)
    create_overlay_image(base_image_path, image_path)
    try:
        cmd = qemu_command(arch, image_path, image_format="qcow2")
        returncode, timed_out, stop_reason = run_qemu(
            cmd,
            log_path,
            timeout,
            silent_idle_timeout=silent_idle_timeout,
            pre_output_idle_timeout=pre_output_idle_timeout,
            on_output=on_output,
            on_poll=on_poll,
            suppress_live_log=suppress_live_log,
        )
        result = CaseResult(
            sample=sample,
            group=group,
            runtime=runtime,
            arch=arch,
            log_path=log_path,
            timed_out=timed_out,
            returncode=returncode,
            stop_reason=stop_reason,
        )
        if timed_out:
            result.error = stop_reason or f"timeout after {timeout}s"
            result.skipped = is_restartable_stall(result.error)
            if group == "ltp" and normalize_ltp_log:
                normalize_ltp_log_file(log_path)
            return result
        if group == "ltp" and normalize_ltp_log:
            normalize_ltp_log_file(log_path)
        validated = validate_case(sample, log_path, expected_cases_override)
        validated.returncode = returncode
        return validated
    except Exception as exc:
        result = CaseResult(sample=sample, group=group, runtime=runtime, arch=arch, log_path=log_path)
        result.error = str(exc)
        return result
    finally:
        if image_path.exists():
            image_path.unlink()
        if cleanup_base_image:
            base_image_path.unlink(missing_ok=True)


def merge_ltp_shard_results(
    sample: str,
    shard_results: list[CaseResult],
    ordered_cases: list[str],
    combined_log_path: Path,
) -> CaseResult:
    group, runtime, arch = parse_sample(sample)
    merged = CaseResult(sample=sample, group=group, runtime=runtime, arch=arch, log_path=combined_log_path)
    row_by_name: dict[str, DetailRow] = {}
    for result in shard_results:
        for row in result.details or []:
            row_by_name[row.name] = DetailRow(name=row.name, passed=row.passed, total=row.total, status=row.status)
    merged.details = [
        row_by_name.get(case_name, DetailRow(name=case_name, passed=0, total=1, status="fail"))
        for case_name in ordered_cases
    ]
    merged.timed_out = any(result.timed_out for result in shard_results)
    merged.returncode = next((result.returncode for result in shard_results if result.returncode), 0)
    errors = [result.error for result in shard_results if result.error]
    stop_reasons = [result.stop_reason for result in shard_results if result.stop_reason]
    merged.error = "; ".join(errors) if errors else None
    merged.stop_reason = "; ".join(stop_reasons) if stop_reasons else None
    merged.skipped = any(result.skipped for result in shard_results)
    merged.ok = all(row.passed == row.total for row in merged.details)
    merged.summary = f"{merged.passed}/{merged.total}"
    return merged


def ltp_shard_completed_and_stalled_cases(
    lines: list[str],
    cases: list[str],
) -> tuple[list[str], str | None]:
    completed: list[str] = []
    pos = 0
    for name in cases:
        run_idx = find_line_index(lines, f"RUN LTP CASE {name}", pos)
        if run_idx < 0:
            break
        search_pos = run_idx + 1
        fail_idx = find_line_with_prefix(lines, f"FAIL LTP CASE {name} : ", search_pos)
        skip_idx = find_line_with_prefix(lines, f"SKIP LTP CASE {name} : ", search_pos)
        next_run_idx = find_line_with_prefix(lines, "RUN LTP CASE ", search_pos)
        terminal_candidates = [idx for idx in (fail_idx, skip_idx) if idx >= 0]
        terminal_idx = min(terminal_candidates) if terminal_candidates else -1
        if next_run_idx >= 0 and (terminal_idx < 0 or next_run_idx < terminal_idx):
            pos = next_run_idx
            completed.append(name)
            continue
        if terminal_idx < 0:
            return completed, name
        pos = terminal_idx + 1
        completed.append(name)
    return completed, None


def mark_ltp_queue_finished_cases(queue: LtpWorkStealingQueue, lines: list[str]) -> None:
    for line in lines:
        match = (
            LTP_PASS_LINE_RE.match(line)
            or LTP_LEGACY_OK_LINE_RE.match(line)
            or LTP_FAIL_LINE_RE.match(line)
            or LTP_SKIP_LINE_RE.match(line)
        )
        if match is not None:
            queue.mark_case_finished(match.group(1))


def run_ltp_persistent_worker(
    sample: str,
    shard_index: int,
    out_dir: Path,
    logs_dir: Path,
    timeout: int,
    *,
    command_override: str,
    ltp_runtime_mul: float,
    runtime: str,
    queue: LtpWorkStealingQueue,
    queue_url: str,
    progress_reporter: LtpShardRuntimeProgressReporter | None = None,
    log_label: str | None = None,
) -> CaseResult:
    group, sample_runtime, arch = parse_sample(sample)
    assert group == "ltp"
    assert sample_runtime == runtime

    row_by_name: dict[str, DetailRow] = {}
    combined_chunks: list[str] = []
    recovered_stalls: list[str] = []
    worker_case_order: list[str] = []
    shard_label = official_case_label(group, runtime, arch)
    shard_log_label = log_label or f"{sample}.worker{shard_index + 1}"
    runtime_root = out_dir / runtime
    terminal_failure: CaseResult | None = None
    attempt = 0

    while True:
        attempt += 1
        queue.set_worker_attempt(shard_index, attempt)
        ensure_ltp_script_uses_queue(
            runtime_root,
            runtime_mul=ltp_runtime_mul,
            queue_url=queue_url,
            worker_index=shard_index,
        )
        if progress_reporter is not None:
            progress_reporter.mark_worker_booting(shard_index, restarting=attempt > 1)

        def on_worker_output(lines: list[str], now: float, *, idx: int = shard_index) -> str | None:
            mark_ltp_queue_finished_cases(queue, lines)
            if progress_reporter is None:
                return None
            return progress_reporter.consume(idx, lines, now)

        result = run_sample_from_rootfs(
            sample,
            out_dir,
            logs_dir,
            timeout,
            command_override=command_override,
            expected_cases_override=None,
            log_stem=f"{shard_log_label}.try{attempt}",
            silent_idle_timeout=SHARDED_LTP_SILENT_IDLE_TIMEOUT,
            pre_output_idle_timeout=SHARDED_LTP_SILENT_IDLE_TIMEOUT,
            cleanup_base_image=True,
            on_output=on_worker_output,
            on_poll=None if progress_reporter is None else progress_reporter.poll,
            suppress_live_log=progress_reporter is not None,
            normalize_ltp_log=False,
        )

        assigned_cases = queue.assigned_case_names(shard_index, attempt)
        for case_name in assigned_cases:
            if case_name not in worker_case_order:
                worker_case_order.append(case_name)
        normalize_ltp_log_file(result.log_path)
        combined_chunks.append(f"===== LTP WORKER {shard_index + 1} ATTEMPT {attempt} =====")
        combined_chunks.append(read_text(result.log_path).rstrip())

        if not result.timed_out:
            if assigned_cases:
                validated = validate_case(sample, result.log_path, assigned_cases)
                validated.returncode = result.returncode
                result = validated
                for row in result.details or []:
                    row_by_name[row.name] = DetailRow(
                        name=row.name,
                        passed=row.passed,
                        total=row.total,
                        status=row.status,
                    )
            terminal_failure = result
            break

        lines = read_text(result.log_path).splitlines()
        completed_cases, stalled_case = ltp_shard_completed_and_stalled_cases(lines, assigned_cases)
        if completed_cases:
            partial = validate_case(sample, result.log_path, completed_cases)
            for row in partial.details or []:
                row_by_name[row.name] = DetailRow(
                    name=row.name,
                    passed=row.passed,
                    total=row.total,
                    status=row.status,
                )

        stalled_lease = queue.mark_worker_stalled(shard_index)
        if stalled_case is None and stalled_lease is not None:
            stalled_case = stalled_lease.case_name

        if stalled_case is None:
            terminal_failure = result
            break

        row_by_name[stalled_case] = DetailRow(name=stalled_case, passed=0, total=1, status="fail")
        recovered_stalls.append(stalled_case)
        if progress_reporter is not None:
            progress_reporter.mark_stalled_case(shard_index, stalled_case)
        console(
            f"[ltp-shard-restart] {shard_label} shard{shard_index + 1} "
            f"mark fail {stalled_case}"
        )
        if not queue.has_pending_cases():
            break

    combined_log_path = logs_dir / f"{shard_log_label}.out"
    combined_log_path.write_text(
        "\n".join(chunk for chunk in combined_chunks if chunk).rstrip() + "\n",
        encoding="utf-8",
    )

    merged = CaseResult(sample=sample, group=group, runtime=runtime, arch=arch, log_path=combined_log_path)
    merged.details = [
        row_by_name[case_name]
        for case_name in worker_case_order
        if case_name in row_by_name
    ]
    merged.ok = all(row.passed == row.total for row in merged.details)
    merged.summary = f"{merged.passed}/{merged.total}"
    if terminal_failure is not None:
        merged.returncode = terminal_failure.returncode
        if terminal_failure.error and not recovered_stalls:
            merged.error = terminal_failure.error
        if terminal_failure.stop_reason and not recovered_stalls:
            merged.stop_reason = terminal_failure.stop_reason
        if terminal_failure.timed_out and not recovered_stalls:
            merged.timed_out = True
            merged.skipped = terminal_failure.skipped
    if recovered_stalls:
        merged.stop_reason = "; ".join(f"recovered stall at {case}" for case in recovered_stalls)
    return merged


def run_ltp_host_lease_worker(
    sample: str,
    shard_index: int,
    out_dir: Path,
    logs_dir: Path,
    timeout: int,
    *,
    command_override: str,
    ltp_runtime_mul: float,
    runtime: str,
    arch: str,
    variants: dict[tuple[str, str], Path],
    queue: LtpWorkStealingQueue,
    progress_reporter: LtpShardRuntimeProgressReporter | None = None,
    log_label: str | None = None,
) -> CaseResult:
    group, sample_runtime, sample_arch = parse_sample(sample)
    assert group == "ltp"
    assert sample_runtime == runtime
    assert sample_arch == arch

    row_by_name: dict[str, DetailRow] = {}
    combined_chunks: list[str] = []
    recovered_stalls: list[str] = []
    worker_case_order: list[str] = []
    shard_label = official_case_label(group, runtime, arch)
    shard_log_label = log_label or f"{sample}.worker{shard_index + 1}"
    lease_index = 0

    while True:
        lease = queue.claim_next(shard_index)
        if lease is None:
            break
        lease_index += 1
        worker_case_order.append(lease.case_name)
        refresh_official_rootfs_wrappers(
            out_dir,
            [sample],
            [lease.case_name],
            ltp_runtime_mul,
            None,
            arch=arch,
            glibc_rootfs=variants.get((arch, "glibc")),
            musl_rootfs=variants.get((arch, "musl")),
        )
        assert_official_rootfs_ready(out_dir, [sample], [lease.case_name], None)
        if progress_reporter is not None:
            progress_reporter.mark_worker_booting(shard_index, restarting=lease_index > 1)

        def on_worker_output(lines: list[str], now: float, *, idx: int = shard_index) -> str | None:
            if progress_reporter is None:
                return None
            return progress_reporter.consume(idx, lines, now)

        result = run_sample_from_rootfs(
            sample,
            out_dir,
            logs_dir,
            timeout,
            command_override=command_override,
            expected_cases_override=[lease.case_name],
            log_stem=f"{shard_log_label}.lease{lease_index}",
            silent_idle_timeout=SHARDED_LTP_SILENT_IDLE_TIMEOUT,
            pre_output_idle_timeout=SHARDED_LTP_SILENT_IDLE_TIMEOUT,
            cleanup_base_image=True,
            on_output=on_worker_output,
            on_poll=None if progress_reporter is None else progress_reporter.poll,
            suppress_live_log=progress_reporter is not None,
            normalize_ltp_log=False,
        )

        normalize_ltp_log_file(result.log_path)
        combined_chunks.append(
            f"===== LTP WORKER {shard_index + 1} LEASE {lease_index} CASE {lease.case_name} ====="
        )
        combined_chunks.append(read_text(result.log_path).rstrip())

        if result.timed_out:
            queue.mark_worker_stalled(shard_index)
            row_by_name[lease.case_name] = DetailRow(name=lease.case_name, passed=0, total=1, status="fail")
            recovered_stalls.append(lease.case_name)
            if progress_reporter is not None:
                progress_reporter.mark_stalled_case(shard_index, lease.case_name)
            console(
                f"[ltp-shard-restart] {shard_label} shard{shard_index + 1} "
                f"mark fail {lease.case_name}"
            )
            continue

        queue.mark_case_finished(lease.case_name)
        if result.details is None:
            validated = validate_case(sample, result.log_path, [lease.case_name])
            validated.returncode = result.returncode
            result = validated
        row = next(
            iter(result.details or [DetailRow(name=lease.case_name, passed=0, total=1, status="fail")]),
            DetailRow(name=lease.case_name, passed=0, total=1, status="fail"),
        )
        row_by_name[lease.case_name] = DetailRow(
            name=row.name,
            passed=row.passed,
            total=row.total,
            status=row.status,
        )
        if progress_reporter is not None:
            progress_reporter.mark_worker_switching(shard_index)

    combined_log_path = logs_dir / f"{shard_log_label}.out"
    combined_log_path.write_text(
        "\n".join(chunk for chunk in combined_chunks if chunk).rstrip() + "\n",
        encoding="utf-8",
    )

    merged = CaseResult(sample=sample, group=group, runtime=runtime, arch=arch, log_path=combined_log_path)
    merged.details = [row_by_name[case_name] for case_name in worker_case_order if case_name in row_by_name]
    merged.ok = all(row.passed == row.total for row in merged.details)
    merged.summary = f"{merged.passed}/{merged.total}"
    if recovered_stalls:
        merged.stop_reason = "; ".join(f"recovered stall at {case}" for case in recovered_stalls)
    return merged


def run_ltp_stdin_persistent_worker(
    sample: str,
    shard_index: int,
    out_dir: Path,
    logs_dir: Path,
    timeout: int,
    *,
    command_override: str,
    ltp_runtime_mul: float,
    runtime: str,
    queue: LtpWorkStealingQueue,
    progress_reporter: LtpShardRuntimeProgressReporter | None = None,
    log_label: str | None = None,
) -> CaseResult:
    group, sample_runtime, arch = parse_sample(sample)
    assert group == "ltp"
    assert sample_runtime == runtime

    row_by_name: dict[str, DetailRow] = {}
    combined_chunks: list[str] = []
    recovered_stalls: list[str] = []
    worker_case_order: list[str] = []
    shard_label = official_case_label(group, runtime, arch)
    shard_log_label = log_label or f"{sample}.worker{shard_index + 1}"
    runtime_root = out_dir / runtime
    terminal_failure: CaseResult | None = None
    attempt = 0

    while True:
        attempt += 1
        queue.set_worker_attempt(shard_index, attempt)
        ensure_ltp_script_uses_stdin_queue(
            runtime_root,
            runtime_mul=ltp_runtime_mul,
        )
        if progress_reporter is not None:
            progress_reporter.mark_worker_booting(shard_index, restarting=attempt > 1)

        log_path = logs_dir / f"{shard_log_label}.try{attempt}.out"
        image_path = logs_dir / f"{shard_log_label}.try{attempt}.qcow2"
        base_image_path = ensure_direct_base_image(out_dir, command_override)
        create_overlay_image(base_image_path, image_path)
        tty_state = capture_tty_state()
        ready_pending = 0
        done_sent = False
        read_offset = 0
        partial_line = ""
        fatal_seen_at: float | None = None
        fatal_reason: str | None = None
        last_progress_at = time.monotonic()
        start = last_progress_at
        returncode: int | None = None
        timed_out = False
        stop_reason: str | None = None

        with log_path.open("w", encoding="utf-8", errors="ignore") as log_file:
            proc = subprocess.Popen(
                qemu_command(arch, image_path, image_format="qcow2"),
                cwd=ROOT,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                start_new_session=True,
                text=True,
            )
            register_active_child_proc(proc)
            try:
                while True:
                    polled = proc.poll()
                    if progress_reporter is None:
                        refresh_live_line(log_path)
                    try:
                        size = log_path.stat().st_size
                    except FileNotFoundError:
                        size = 0
                    if size != read_offset:
                        now = time.monotonic()
                        last_progress_at = now
                        read_offset, partial_line, new_lines = read_appended_log_lines(log_path, read_offset, partial_line)
                        if new_lines:
                            mark_ltp_queue_finished_cases(queue, new_lines)
                            ready_pending += sum(1 for line in new_lines if line == LTP_STDIN_TESTCODE_READY_MARKER)
                            if progress_reporter is not None:
                                progress_reporter.consume(shard_index, new_lines, now)
                            reason = fatal_log_reason(read_recent_log_lines(log_path))
                            if reason is not None:
                                fatal_seen_at = now
                                fatal_reason = reason
                    while ready_pending > 0 and proc.stdin is not None and not proc.stdin.closed:
                        lease = queue.claim_next(shard_index)
                        if lease is None:
                            if not done_sent:
                                proc.stdin.write(LTP_QUEUE_DONE_SENTINEL + "\n")
                                proc.stdin.flush()
                                done_sent = True
                            ready_pending = 0
                            break
                        worker_case_order.append(lease.case_name)
                        proc.stdin.write(lease.runtest_line + "\n")
                        proc.stdin.flush()
                        ready_pending -= 1
                    if polled is not None:
                        returncode = polled
                        read_offset, partial_line, new_lines = read_appended_log_lines(log_path, read_offset, partial_line)
                        if partial_line:
                            new_lines.append(sanitize_line(partial_line))
                        if new_lines:
                            mark_ltp_queue_finished_cases(queue, new_lines)
                            if progress_reporter is not None:
                                progress_reporter.consume(shard_index, new_lines, time.monotonic())
                        break
                    if timeout is not None and time.monotonic() - start > timeout:
                        timed_out = True
                        stop_reason = f"timeout after {timeout}s"
                        terminate_process_group(proc)
                        break
                    snapshot_now = time.monotonic()
                    if (
                        SHARDED_LTP_SILENT_IDLE_TIMEOUT is not None
                        and size == 0
                        and snapshot_now - start > SHARDED_LTP_SILENT_IDLE_TIMEOUT
                    ):
                        timed_out = True
                        stop_reason = (
                            f"silent boot stall after {SHARDED_LTP_SILENT_IDLE_TIMEOUT:.0f}s "
                            "before first log line"
                        )
                        terminate_process_group(proc)
                        break
                    if (
                        SHARDED_LTP_SILENT_IDLE_TIMEOUT is not None
                        and size > 0
                        and snapshot_now - last_progress_at > SHARDED_LTP_SILENT_IDLE_TIMEOUT
                    ):
                        timed_out = True
                        stop_reason = f"silent log stall after {SHARDED_LTP_SILENT_IDLE_TIMEOUT:.0f}s idle"
                        terminate_process_group(proc)
                        break
                    if (
                        FATAL_IDLE_TIMEOUT is not None
                        and fatal_seen_at is not None
                        and snapshot_now - last_progress_at > FATAL_IDLE_TIMEOUT
                    ):
                        timed_out = True
                        stop_reason = f"fatal log stall after {fatal_reason} ({FATAL_IDLE_TIMEOUT:.0f}s idle)"
                        terminate_process_group(proc)
                        break
                    if progress_reporter is not None:
                        progress_reporter.poll(snapshot_now)
                    time.sleep(LIVE_POLL_INTERVAL)
            finally:
                clear_live_line()
                restore_tty_state(tty_state)
                unregister_active_child_proc(proc)
                try:
                    if proc.stdin is not None:
                        proc.stdin.close()
                except Exception:
                    pass
                if proc.poll() is None:
                    terminate_process_group(proc)
        image_path.unlink(missing_ok=True)
        base_image_path.unlink(missing_ok=True)

        for case_name in queue.assigned_case_names(shard_index, attempt):
            if case_name not in worker_case_order:
                worker_case_order.append(case_name)
        normalize_ltp_log_file(log_path)
        combined_chunks.append(f"===== LTP WORKER {shard_index + 1} ATTEMPT {attempt} =====")
        combined_chunks.append(read_text(log_path).rstrip())

        result = CaseResult(
            sample=sample,
            group=group,
            runtime=runtime,
            arch=arch,
            log_path=log_path,
            timed_out=timed_out,
            returncode=returncode,
            stop_reason=stop_reason,
        )

        assigned_cases = queue.assigned_case_names(shard_index, attempt)
        if not timed_out:
            if assigned_cases:
                validated = validate_case(sample, log_path, assigned_cases)
                validated.returncode = returncode
                result = validated
                for row in result.details or []:
                    row_by_name[row.name] = DetailRow(
                        name=row.name,
                        passed=row.passed,
                        total=row.total,
                        status=row.status,
                    )
            terminal_failure = result
            break

        lines = read_text(log_path).splitlines()
        completed_cases, stalled_case = ltp_shard_completed_and_stalled_cases(lines, assigned_cases)
        if completed_cases:
            partial = validate_case(sample, log_path, completed_cases)
            for row in partial.details or []:
                row_by_name[row.name] = DetailRow(
                    name=row.name,
                    passed=row.passed,
                    total=row.total,
                    status=row.status,
                )

        stalled_lease = queue.mark_worker_stalled(shard_index)
        if stalled_case is None and stalled_lease is not None:
            stalled_case = stalled_lease.case_name

        if stalled_case is None:
            terminal_failure = result
            break

        row_by_name[stalled_case] = DetailRow(name=stalled_case, passed=0, total=1, status="fail")
        recovered_stalls.append(stalled_case)
        if progress_reporter is not None:
            progress_reporter.mark_stalled_case(shard_index, stalled_case)
        console(
            f"[ltp-shard-restart] {shard_label} shard{shard_index + 1} "
            f"mark fail {stalled_case}"
        )
        if not queue.has_pending_cases():
            break

    combined_log_path = logs_dir / f"{shard_log_label}.out"
    combined_log_path.write_text(
        "\n".join(chunk for chunk in combined_chunks if chunk).rstrip() + "\n",
        encoding="utf-8",
    )

    merged = CaseResult(sample=sample, group=group, runtime=runtime, arch=arch, log_path=combined_log_path)
    merged.details = [
        row_by_name[case_name]
        for case_name in worker_case_order
        if case_name in row_by_name
    ]
    merged.ok = all(row.passed == row.total for row in merged.details)
    merged.summary = f"{merged.passed}/{merged.total}"
    if terminal_failure is not None:
        merged.returncode = terminal_failure.returncode
        if terminal_failure.error and not recovered_stalls:
            merged.error = terminal_failure.error
        if terminal_failure.stop_reason and not recovered_stalls:
            merged.stop_reason = terminal_failure.stop_reason
        if terminal_failure.timed_out and not recovered_stalls:
            merged.timed_out = True
            merged.skipped = terminal_failure.skipped
    if recovered_stalls:
        merged.stop_reason = "; ".join(f"recovered stall at {case}" for case in recovered_stalls)
    return merged


def run_ltp_shard_with_restarts(
    sample: str,
    shard_index: int,
    shard_cases: list[str],
    out_dir: Path,
    logs_dir: Path,
    timeout: int,
    *,
    command_override: str,
    ltp_runtime_mul: float,
    arch: str,
    variants: dict[tuple[str, str], Path],
    progress_reporter: LtpShardRuntimeProgressReporter | None = None,
    log_label: str | None = None,
) -> CaseResult:
    group, runtime, sample_arch = parse_sample(sample)
    assert group == "ltp"
    assert sample_arch == arch

    remaining_cases = list(shard_cases)
    row_by_name: dict[str, DetailRow] = {}
    combined_chunks: list[str] = []
    recovered_stalls: list[str] = []
    shard_label = official_case_label(group, runtime, arch)
    shard_log_label = log_label or f"{sample}.shard{shard_index}"
    attempt = 0
    terminal_failure: CaseResult | None = None

    while remaining_cases:
        attempt += 1
        if progress_reporter is not None:
            if attempt > 1:
                progress_reporter.mark_worker_switching(shard_index, restarting=True)
            else:
                progress_reporter.mark_worker_booting(shard_index)
        refresh_official_rootfs_wrappers(
            out_dir,
            [sample],
            remaining_cases,
            ltp_runtime_mul,
            None,
            arch=arch,
            glibc_rootfs=variants.get((arch, "glibc")),
            musl_rootfs=variants.get((arch, "musl")),
        )
        assert_official_rootfs_ready(out_dir, [sample], remaining_cases, None)

        if progress_reporter is not None:
            progress_reporter.mark_worker_booting(shard_index, restarting=attempt > 1)
        result = run_sample_from_rootfs(
            sample,
            out_dir,
            logs_dir,
            timeout,
            command_override=command_override,
            expected_cases_override=remaining_cases,
            log_stem=f"{shard_log_label}.try{attempt}",
            silent_idle_timeout=SHARDED_LTP_SILENT_IDLE_TIMEOUT,
            pre_output_idle_timeout=SHARDED_LTP_SILENT_IDLE_TIMEOUT,
            cleanup_base_image=True,
            on_output=(
                None
                if progress_reporter is None
                else lambda lines, now, idx=shard_index: progress_reporter.consume(idx, lines, now)
            ),
            on_poll=None if progress_reporter is None else progress_reporter.poll,
            suppress_live_log=progress_reporter is not None,
            normalize_ltp_log=False,
        )

        if not result.timed_out and result.details is not None:
            returncode = result.returncode
            normalize_ltp_log_file(result.log_path)
            result = validate_case(sample, result.log_path, remaining_cases)
            result.returncode = returncode
            for row in result.details:
                row_by_name[row.name] = DetailRow(
                    name=row.name,
                    passed=row.passed,
                    total=row.total,
                    status=row.status,
                )
            terminal_failure = result
            combined_chunks.append(f"===== LTP SHARD {shard_index + 1} ATTEMPT {attempt} =====")
            combined_chunks.append(read_text(result.log_path).rstrip())
            if progress_reporter is not None:
                progress_reporter.mark_worker_switching(shard_index)
            break

        lines = read_text(result.log_path).splitlines()
        completed_cases, stalled_case = ltp_shard_completed_and_stalled_cases(lines, remaining_cases)
        if completed_cases:
            partial = validate_case(sample, result.log_path, completed_cases)
            for row in partial.details or []:
                row_by_name[row.name] = DetailRow(
                    name=row.name,
                    passed=row.passed,
                    total=row.total,
                    status=row.status,
                )

        if stalled_case is None:
            terminal_failure = result
            normalize_ltp_log_file(result.log_path)
            combined_chunks.append(f"===== LTP SHARD {shard_index + 1} ATTEMPT {attempt} =====")
            combined_chunks.append(read_text(result.log_path).rstrip())
            if progress_reporter is not None:
                progress_reporter.mark_worker_switching(shard_index)
            break

        row_by_name[stalled_case] = DetailRow(name=stalled_case, passed=0, total=1, status="fail")
        recovered_stalls.append(stalled_case)
        if progress_reporter is not None:
            progress_reporter.mark_stalled_case(shard_index, stalled_case)
        stalled_index = remaining_cases.index(stalled_case)
        remaining_cases = remaining_cases[stalled_index + 1 :]
        console(
            f"[ltp-shard-restart] {shard_label} shard{shard_index + 1} "
            f"mark fail {stalled_case}, remaining {len(remaining_cases)}"
        )
        normalize_ltp_log_file(result.log_path)
        combined_chunks.append(f"===== LTP SHARD {shard_index + 1} ATTEMPT {attempt} =====")
        combined_chunks.append(read_text(result.log_path).rstrip())

    combined_log_path = logs_dir / f"{shard_log_label}.out"
    combined_log_path.write_text(
        "\n".join(chunk for chunk in combined_chunks if chunk).rstrip() + "\n",
        encoding="utf-8",
    )

    merged = CaseResult(sample=sample, group=group, runtime=runtime, arch=arch, log_path=combined_log_path)
    merged.details = [
        row_by_name.get(case_name, DetailRow(name=case_name, passed=0, total=1, status="fail"))
        for case_name in shard_cases
    ]
    merged.ok = all(row.passed == row.total for row in merged.details)
    merged.summary = f"{merged.passed}/{merged.total}"
    if terminal_failure is not None:
        merged.returncode = terminal_failure.returncode
        if terminal_failure.error and not recovered_stalls:
            merged.error = terminal_failure.error
        if terminal_failure.stop_reason and not recovered_stalls:
            merged.stop_reason = terminal_failure.stop_reason
        if terminal_failure.timed_out and not recovered_stalls:
            merged.timed_out = True
            merged.skipped = terminal_failure.skipped
    if recovered_stalls:
        merged.stop_reason = "; ".join(f"recovered stall at {case}" for case in recovered_stalls)
    return merged


def run_ltp_sharded_sample(
    sample: str,
    logs_dir: Path,
    timeout: int,
    *,
    rebuild_rootfs: bool,
    variants: dict[tuple[str, str], Path],
    ltp_runtime_mul: float,
    ltp_start_case: str | None,
    shard_count: int,
) -> CaseResult:
    group, runtime, arch = parse_sample(sample)
    assert group == "ltp"
    ordered_cases = ltp_case_names(start_case=ltp_start_case)
    worker_count = max(1, min(shard_count, len(ordered_cases)))
    case_runtime_weights, point_runtime_weights = load_ltp_case_runtime_weights(runtime, arch)
    weighted_queue_preview = order_ltp_queue_cases(
        [
            LtpQueueCase(
                case_index=case_index,
                case_name=case_name,
                runtest_line="",
                weight_sec=ltp_shard_case_weight(case_name, case_runtime_weights, point_runtime_weights),
            )
            for case_index, case_name in enumerate(ordered_cases)
        ]
    )
    heavy_cases = [
        (case.case_name, case.weight_sec)
        for case in weighted_queue_preview
        if case.weight_sec >= LTP_HEAVY_CASE_WEIGHT_THRESHOLD
    ]
    queue_preview = preview_ltp_queue_cases(weighted_queue_preview)
    if heavy_cases:
        heavy_summary = ", ".join(
            f"{case_name}={weight}s"
            for case_name, weight in sorted(heavy_cases, key=lambda item: (-item[1], item[0]))[:8]
        )
        console(
            f"[ltp-schedule] {official_case_label(group, runtime, arch)} "
            f"work-stealing=weighted-per-case "
            f"heavy-cases={len(heavy_cases)} threshold={LTP_HEAVY_CASE_WEIGHT_THRESHOLD}s "
            f"weights=case:{len(case_runtime_weights)} point:{len(point_runtime_weights)} "
            f"top={heavy_summary} frontload={queue_preview}"
        )
    else:
        console(
            f"[ltp-schedule] {official_case_label(group, runtime, arch)} "
            f"work-stealing=weighted-per-case "
            f"weights=case:{len(case_runtime_weights)} point:{len(point_runtime_weights)} "
            f"frontload={queue_preview}"
        )
    worker_rootfs_specs: list[tuple[int, Path]] = []
    official_rootfs_root = WORK_ROOT / "rootfs-official"
    official_rootfs_root.mkdir(parents=True, exist_ok=True)
    rootfs_stage_started = time.monotonic()
    rootfs_progress_stage = f"prepare official rootfs {arch} {runtime} ltp shards"
    built_workers = 0
    reused_workers = 0
    update_stage_progress(rootfs_progress_stage, 0, worker_count, rootfs_stage_started)
    for index in range(worker_count):
        out_dir = official_ltp_worker_rootfs_dir(official_rootfs_root, sample, worker_count, index)
        marker = out_dir / ".osk_official_rootfs_ready"
        needs_rebuild = (
            rebuild_rootfs
            or not marker.exists()
            or official_rootfs_is_stale(out_dir, [sample], ordered_cases, None)
        )
        if needs_rebuild:
            update_stage_progress(
                rootfs_progress_stage,
                index,
                worker_count,
                rootfs_stage_started,
                detail=f"building shard{index + 1}/{worker_count}",
            )
            build_official_rootfs_dir(
                arch,
                variants.get((arch, "glibc")),
                variants.get((arch, "musl")),
                out_dir,
                [sample],
                ordered_cases,
                ltp_runtime_mul,
                None,
            )
            assert_official_rootfs_ready(out_dir, [sample], ordered_cases, None)
            marker.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
            built_workers += 1
        else:
            refresh_official_rootfs_wrappers(
                out_dir,
                [sample],
                ordered_cases,
                ltp_runtime_mul,
                None,
                arch=arch,
                glibc_rootfs=variants.get((arch, "glibc")),
                musl_rootfs=variants.get((arch, "musl")),
            )
            assert_official_rootfs_ready(out_dir, [sample], ordered_cases, None)
            reused_workers += 1
        worker_rootfs_specs.append((index, out_dir))
        update_stage_progress(
            rootfs_progress_stage,
            index + 1,
            worker_count,
            rootfs_stage_started,
            detail=f"reuse={reused_workers} build={built_workers}",
        )

    if built_workers == 0:
        rootfs_final_stage = f"reuse official rootfs {arch} {runtime} ltp shards"
    elif reused_workers == 0:
        rootfs_final_stage = f"build official rootfs {arch} {runtime} ltp shards"
    else:
        rootfs_final_stage = rootfs_progress_stage
    finish_stage_progress(
        rootfs_final_stage,
        worker_count,
        worker_count,
        rootfs_stage_started,
        detail=f"reuse={reused_workers} build={built_workers}",
    )

    command_override = f"/busybox sh /{runtime}/{SCRIPT_BY_GROUP[group]}"
    shard_label = official_case_label(group, runtime, arch)
    runtime_progress = LtpShardRuntimeProgressReporter(shard_label, worker_count, len(ordered_cases))
    runtime_progress.poll(time.monotonic())
    shard_run_started = time.monotonic()
    completed_shard_count = 0
    completed_shard_passed = 0
    completed_shard_total = 0
    update_ltp_shard_progress(
        shard_label,
        completed_shard_count,
        worker_count,
        shard_run_started,
        completed_shard_passed,
        completed_shard_total,
    )
    queue_cases = ltp_queue_cases(ordered_cases, case_runtime_weights, point_runtime_weights)
    work_queue = LtpWorkStealingQueue(queue_cases)
    use_guest_queue = arch == "rv"
    use_stdin_queue = arch == "la"
    queue_server: LtpWorkStealingHttpServer | None = None
    queue_url: str | None = None
    if use_guest_queue:
        queue_server, queue_url = start_ltp_work_stealing_server(work_queue)

    def flattened_completed_results() -> list[CaseResult]:
        return [result for result in worker_results if result is not None]

    def write_combined_ltp_log(results_to_merge: list[CaseResult]) -> Path:
        combined_log_path = logs_dir / f"{sample}.out"
        combined_chunks: list[str] = []
        for index, result in enumerate(results_to_merge, start=1):
            combined_chunks.append(f"===== LTP SHARD LEASE {index}/{len(results_to_merge)} =====")
            combined_chunks.append(read_text(result.log_path).rstrip())
        combined_log_path.write_text(
            "\n".join(chunk for chunk in combined_chunks if chunk).rstrip() + "\n",
            encoding="utf-8",
        )
        return combined_log_path

    def worker_loop(worker_index: int, out_dir: Path) -> CaseResult:
        if use_guest_queue:
            assert queue_url is not None
            return run_ltp_persistent_worker(
                sample,
                worker_index,
                out_dir,
                logs_dir,
                timeout,
                command_override=command_override,
                ltp_runtime_mul=ltp_runtime_mul,
                runtime=runtime,
                queue=work_queue,
                queue_url=queue_url,
                progress_reporter=runtime_progress,
                log_label=f"{sample}.worker{worker_index + 1}",
            )
        if use_stdin_queue:
            return run_ltp_stdin_persistent_worker(
                sample,
                worker_index,
                out_dir,
                logs_dir,
                timeout,
                command_override=command_override,
                ltp_runtime_mul=ltp_runtime_mul,
                runtime=runtime,
                queue=work_queue,
                progress_reporter=runtime_progress,
                log_label=f"{sample}.worker{worker_index + 1}",
            )
        return run_ltp_host_lease_worker(
            sample,
            worker_index,
            out_dir,
            logs_dir,
            timeout,
            command_override=command_override,
            ltp_runtime_mul=ltp_runtime_mul,
            runtime=runtime,
            arch=arch,
            variants=variants,
            queue=work_queue,
            progress_reporter=runtime_progress,
            log_label=f"{sample}.worker{worker_index + 1}",
        )

    worker_results: list[CaseResult | None] = [None] * worker_count
    try:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_map = {
                    executor.submit(worker_loop, index, out_dir): index
                    for index, out_dir in worker_rootfs_specs
                }
                for future in concurrent.futures.as_completed(future_map):
                    index = future_map[future]
                    worker_result = future.result()
                    worker_results[index] = worker_result
                    runtime_progress.mark_shard_completed(index)
                    completed_shard_count += 1
                    completed_shard_passed += worker_result.passed
                    completed_shard_total += worker_result.total
                    update_ltp_shard_progress(
                        shard_label,
                        completed_shard_count,
                        worker_count,
                        shard_run_started,
                        completed_shard_passed,
                        completed_shard_total,
                        detail=f"last=shard{index + 1}",
                    )
        except KeyboardInterrupt:
            terminate_all_active_child_procs()
            raise
    finally:
        if queue_server is not None:
            queue_server.shutdown()
            queue_server.server_close()
        runtime_progress.clear()
        completed_partial_results = flattened_completed_results()
        if completed_partial_results:
            try:
                write_combined_ltp_log(completed_partial_results)
            except Exception:
                pass
        for _, out_dir in worker_rootfs_specs:
            try:
                refresh_official_rootfs_wrappers(
                    out_dir,
                    [sample],
                    ordered_cases,
                    ltp_runtime_mul,
                    None,
                    arch=arch,
                    glibc_rootfs=variants.get((arch, "glibc")),
                    musl_rootfs=variants.get((arch, "musl")),
                )
                assert_official_rootfs_ready(out_dir, [sample], ordered_cases, None)
            except Exception:
                pass
    finish_ltp_shard_progress(
        shard_label,
        completed_shard_count,
        worker_count,
        shard_run_started,
        completed_shard_passed,
        completed_shard_total,
    )

    completed_shards = flattened_completed_results()
    combined_log_path = write_combined_ltp_log(completed_shards)
    merged = merge_ltp_shard_results(sample, completed_shards, ordered_cases, combined_log_path)
    merged.shard_timing_lines = runtime_progress.snapshot_timing_lines()
    parallel_elapsed_sec = max(0.0, time.monotonic() - shard_run_started)
    single_boot_estimate = estimate_ltp_single_boot_runtime(
        ordered_cases,
        runtime,
        arch,
        observed_log_path=combined_log_path,
    )
    source_label = (
        "current-shards"
        if single_boot_estimate.history_case_count == 0 and single_boot_estimate.startup_source == "current"
        else (
            "current+history"
            if (single_boot_estimate.exact_case_count > 0 or single_boot_estimate.point_case_count > 0)
            else single_boot_estimate.startup_source
        )
    )
    console(
        f"[ltp-estimate] {shard_label} parallel={format_duration(parallel_elapsed_sec)} "
        f"single-boot≈{format_duration(single_boot_estimate.total_sec)} "
        f"(startup≈{format_duration(single_boot_estimate.startup_sec)} "
        f"+ cases≈{format_duration(single_boot_estimate.case_sec)}) "
        f"workers={worker_count} source={source_label} "
        f"observed={single_boot_estimate.exact_case_count}/{single_boot_estimate.total_case_count} "
        f"point-fallback={single_boot_estimate.point_case_count} "
        f"history-fallback={single_boot_estimate.history_case_count}"
    )
    return merged


def run_sample(sample: str, rootfs_dir: Path, logs_dir: Path, timeout: int) -> CaseResult:
    return run_sample_from_rootfs(sample, rootfs_dir, logs_dir, timeout)


def requested_targets(samples: list[str] | None) -> str | None:
    if not samples:
        return None
    groups = {parse_sample(sample)[0] for sample in samples}
    mapping = {
        "basic": "basic",
        "busybox": "busybox",
        "lua": "lua",
        "iozone": "iozone",
        "iperf": "iperf",
        "libcbench": "libcbench",
        "libctest": "libc-test",
        "lmbench": "lmbench_src",
        "ltp": "ltp",
        "cyclictest": "cyclictest",
        "netperf": "netperf",
    }
    targets = {"busybox"}
    for group in groups:
        targets.add(mapping[group])
    ordered = [
        "basic",
        "busybox",
        "lua",
        "libc-test",
        "iozone",
        "iperf",
        "libcbench",
        "lmbench_src",
        "cyclictest",
        "ltp",
        "netperf",
    ]
    filtered = [target for target in ordered if target in targets]
    return " ".join(filtered)


def official_repro_build_targets(samples: list[str] | None, online_repro: bool) -> str | None:
    targets = requested_targets(samples)
    if not online_repro or not samples:
        return targets
    return merge_build_targets(targets, OFFICIAL_REFRESH_BASE_TARGETS)


def aggregate_group_runtime(results: dict[str, CaseResult], group: str, runtime: str) -> list[DetailRow]:
    merged: dict[str, DetailRow] = {}
    for arch in ["rv", "la"]:
        sample = f"{group}-{runtime}-{arch}"
        result = results.get(sample)
        if not result or not result.details:
            continue
        for row in result.details:
            merged.setdefault(row.name, DetailRow(name=row.name, passed=0, total=0, status=""))
            merged[row.name].passed += row.passed
            merged[row.name].total += row.total
    return list(merged.values())


def format_top_summary(results: dict[str, CaseResult]) -> list[str]:
    lines = ["得分详情", "测试点\tglibc-la\tglibc-rv\tmusl-la\tmusl-rv\t总计"]
    total_pass = total_all = 0
    for group in GROUP_ORDER:
        cells = []
        group_pass = group_all = 0
        for runtime, arch in [("glibc", "la"), ("glibc", "rv"), ("musl", "la"), ("musl", "rv")]:
            sample = f"{group}-{runtime}-{arch}"
            result = results.get(sample)
            cell = "-"
            if result:
                if result.details is not None:
                    cell = f"{result.passed}/{result.total}"
                    group_pass += result.passed
                    group_all += result.total
                elif result.skipped:
                    cell = "SKIP"
                elif result.timed_out:
                    cell = "TIMEOUT"
                else:
                    cell = "ERR"
            cells.append(cell)
        total_pass += group_pass
        total_all += group_all
        lines.append(f"{group}\t{cells[0]}\t{cells[1]}\t{cells[2]}\t{cells[3]}\t{group_pass}/{group_all}")
    lines.append(
        "总计\t{}\t{}\t{}\t{}\t{}/{}".format(
            results.get("basic-glibc-la", CaseResult("", "", "", "", Path(""))).cell if False else "",
            "",
            "",
            "",
            total_pass,
            total_all,
        )
    )

    glibc_la = sum(results[s].passed for s in results if s.endswith("glibc-la") and results[s].details is not None)
    glibc_la_all = sum(results[s].total for s in results if s.endswith("glibc-la") and results[s].details is not None)
    glibc_rv = sum(results[s].passed for s in results if s.endswith("glibc-rv") and results[s].details is not None)
    glibc_rv_all = sum(results[s].total for s in results if s.endswith("glibc-rv") and results[s].details is not None)
    musl_la = sum(results[s].passed for s in results if s.endswith("musl-la") and results[s].details is not None)
    musl_la_all = sum(results[s].total for s in results if s.endswith("musl-la") and results[s].details is not None)
    musl_rv = sum(results[s].passed for s in results if s.endswith("musl-rv") and results[s].details is not None)
    musl_rv_all = sum(results[s].total for s in results if s.endswith("musl-rv") and results[s].details is not None)
    lines[-1] = (
        f"总计\t{glibc_la}/{glibc_la_all}\t{glibc_rv}/{glibc_rv_all}\t"
        f"{musl_la}/{musl_la_all}\t{musl_rv}/{musl_rv_all}\t{total_pass}/{total_all}"
    )
    return lines


def format_group_sections(results: dict[str, CaseResult]) -> list[str]:
    lines: list[str] = []
    for group in GROUP_ORDER:
        for runtime in RUNTIME_ORDER:
            title = f"{group}-{runtime}"
            lines.append(title)
            lines.append("测试点\trv\t\t\tla\t\t\t总计")
            lines.append("pass\tall\tstatus\tpass\tall\tstatus")
            names: list[str] = []
            for arch in ["rv", "la"]:
                sample = f"{group}-{runtime}-{arch}"
                result = results.get(sample)
                if result and result.details:
                    for row in result.details:
                        if row.name not in names:
                            names.append(row.name)
            rv_total_pass = rv_total_all = la_total_pass = la_total_all = 0
            for name in names:
                rv_row = next((row for row in (results.get(f"{group}-{runtime}-rv").details or []) if row.name == name), None) if results.get(f"{group}-{runtime}-rv") else None
                la_row = next((row for row in (results.get(f"{group}-{runtime}-la").details or []) if row.name == name), None) if results.get(f"{group}-{runtime}-la") else None
                rv_pass = rv_row.passed if rv_row else 0
                rv_all = rv_row.total if rv_row else 0
                rv_status = rv_row.status if rv_row else "-"
                la_pass = la_row.passed if la_row else 0
                la_all = la_row.total if la_row else 0
                la_status = la_row.status if la_row else "-"
                rv_total_pass += rv_pass
                rv_total_all += rv_all
                la_total_pass += la_pass
                la_total_all += la_all
                lines.append(
                    f"{name}\t{rv_pass}\t{rv_all}\t{rv_status}\t{la_pass}\t{la_all}\t{la_status}\t{rv_pass + la_pass}/{rv_all + la_all}"
                )
            lines.append(f"总计\t\t{rv_total_pass}/{rv_total_all}\t\t\t{la_total_pass}/{la_total_all}\t{rv_total_pass + la_total_pass}/{rv_total_all + la_total_all}")
            lines.append("")
    return lines


def format_case_summary(results: dict[str, CaseResult]) -> list[str]:
    lines = ["样例执行结果", "样例\t状态\t明细\t日志"]
    for sample in SAMPLE_ORDER:
        result = results.get(sample)
        if result is None:
            lines.append(f"{sample}\tNOT_RUN\t-\t{relative_path(WORK_ROOT / 'logs' / f'{sample}.out')}")
            continue
        status = "PASS" if result.ok else "FAIL"
        if result.skipped:
            status = "SKIP"
        elif result.timed_out:
            status = "TIMEOUT"
        elif result.details is None:
            status = "ERROR"
        detail = result.summary or result.error or "-"
        rel_log = relative_path(result.log_path)
        lines.append(f"{sample}\t{status}\t{detail}\t{rel_log}")
    return lines


def format_ltp_shard_timing_summary(results: dict[str, CaseResult]) -> list[str]:
    lines = ["LTP shard timing summary"]
    emitted = False
    for sample in SAMPLE_ORDER:
        result = results.get(sample)
        if result is None or not result.shard_timing_lines:
            continue
        emitted = True
        lines.append(sample)
        lines.extend(result.shard_timing_lines)
        lines.append("")
    if not emitted:
        lines.append("[info] 本次运行未生成多 shard LTP timing 数据。")
    return lines


def write_report(path: Path, results: dict[str, CaseResult], started_at: datetime, finished_at: datetime, stop_reason: str | None) -> None:
    lines = [
        f"本地完整测试时间：{finished_at.astimezone(timezone.utc).isoformat()}",
        "",
        "本地官方口径全量测试",
        "",
        "评测完成" if stop_reason is None else f"评测中止：{stop_reason}",
        f"开始时间：{started_at.astimezone(timezone.utc).isoformat()}",
        f"结束时间：{finished_at.astimezone(timezone.utc).isoformat()}",
        "",
    ]
    lines.extend(format_top_summary(results))
    lines.append("")
    lines.extend(format_case_summary(results))
    lines.append("")
    lines.extend(format_ltp_shard_timing_summary(results))
    lines.append("")
    lines.extend(format_group_sections(results))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def flush_report(path: Path, results: dict[str, CaseResult], started_at: datetime, stop_reason: str | None) -> None:
    write_report(path, results, started_at, datetime.now(timezone.utc), stop_reason)


LOCAL_EXPORT_DIR = ROOT / "logs"
LOCAL_REPORT_EXPORT_NAME = "local_score.txt"
LOCAL_ARCH_EXPORT_NAMES = {
    "rv": ["local_Riscv输出.txt"],
    "la": ["local_LoongArch输出.txt"],
}
LOCAL_ARCH_LABELS = {
    "rv": "RISC-V",
    "la": "LoongArch",
}


def copy_export_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.resolve() == dst.resolve():
        return
    shutil.copyfile(src, dst)


def arch_samples_for_run(samples: list[str], arch: str) -> list[str]:
    return [sample for sample in samples if sample.endswith(f"-{arch}")]


def raw_arch_log_generated_this_run(path: Path, started_at: datetime) -> bool:
    if not path.exists():
        return False
    return path.stat().st_mtime >= started_at.timestamp() - 1.0


def should_export_raw_arch_log(
    arch: str,
    raw_log_path: Path,
    selected_samples: list[str],
    results: dict[str, CaseResult],
    started_at: datetime,
) -> bool:
    if not arch_samples_for_run(selected_samples, arch):
        return False
    if not raw_arch_log_generated_this_run(raw_log_path, started_at):
        return False
    completed_samples = [
        sample
        for sample in SAMPLE_ORDER
        if sample in selected_samples and sample.endswith(f"-{arch}") and sample in results and results[sample].log_path.exists()
    ]
    if not completed_samples:
        return False
    return all(results[sample].log_path == raw_log_path for sample in completed_samples)


def render_arch_export_text(
    arch: str,
    selected_samples: list[str],
    results: dict[str, CaseResult],
) -> str:
    arch_samples = [sample for sample in SAMPLE_ORDER if sample in selected_samples and sample.endswith(f"-{arch}")]
    if not arch_samples:
        return f"[info] 本次运行未选择 {LOCAL_ARCH_LABELS[arch]} 样例。\n"
    completed_samples = [
        sample for sample in arch_samples
        if sample in results and results[sample].log_path.exists()
    ]
    if not completed_samples:
        return f"[info] 本次运行未生成 {LOCAL_ARCH_LABELS[arch]} 输出日志。\n"
    chunks: list[str] = []
    for sample in completed_samples:
        chunks.append(f"===== SAMPLE {sample} =====")
        chunks.append(read_text(results[sample].log_path).rstrip())
    return "\n".join(chunk for chunk in chunks if chunk).rstrip() + "\n"


def sync_local_named_outputs(
    report_path: Path,
    logs_dir: Path,
    selected_samples: list[str],
    results: dict[str, CaseResult],
    started_at: datetime,
) -> None:
    LOCAL_EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    copy_export_file(report_path, LOCAL_EXPORT_DIR / LOCAL_REPORT_EXPORT_NAME)
    for arch in ARCH_ORDER:
        raw_log_path = logs_dir / f"official-{arch}.raw.out"
        export_targets = [LOCAL_EXPORT_DIR / name for name in LOCAL_ARCH_EXPORT_NAMES[arch]]
        if should_export_raw_arch_log(arch, raw_log_path, selected_samples, results, started_at):
            for export_target in export_targets:
                copy_export_file(raw_log_path, export_target)
            continue
        export_text = render_arch_export_text(arch, selected_samples, results)
        for export_target in export_targets:
            export_target.parent.mkdir(parents=True, exist_ok=True)
            export_target.write_text(export_text, encoding="utf-8")


def is_failed_result(result: CaseResult) -> bool:
    return result.timed_out or result.skipped or result.details is None or not result.ok


def main() -> int:
    global ENABLE_LTP_RUNTIME_WEIGHT_REFRESH, LTP_CASE_RUNTIME_WEIGHT_CACHE, LTP_RUNTIME_WEIGHT_REFRESH_VARIANTS
    global LTP_EXPECTED_CASES_OVERRIDE, SHARED_CACHE_ROOT, TRANSCRIPT_LOG_PATH, WORK_ROOT
    parser = argparse.ArgumentParser(description="Run the local full OSKernel suite in an official-style boot flow.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-arch timeout in seconds.")
    parser.add_argument(
        "--build-jobs",
        type=int,
        default=DEFAULT_BUILD_JOBS,
        help="Build parallelism for rootfs generation.",
    )
    parser.add_argument(
        "--rootfs-variant-jobs",
        type=int,
        default=DEFAULT_ROOTFS_VARIANT_JOBS,
        help="Maximum parallel rootfs-variant builds during prerequisite preparation.",
    )
    parser.add_argument("--rebuild-rootfs", action="store_true", help="Force rebuilding cached rootfs variants.")
    parser.add_argument("--subset", nargs="*", help="Run only a subset of sample names.")
    parser.add_argument("--report", default="dev/full-suite/score.txt", help="Report output path.")
    parser.add_argument(
        "--work-root",
        default=str(default_work_root()),
        help="Per-job working directory for logs, isolated official rootfs, and overlays.",
    )
    parser.add_argument(
        "--shared-cache-root",
        default=str(default_shared_cache_root()),
        help="Shared readonly cache root for reusable rootfs variants and base images.",
    )
    parser.add_argument("--resume-log", help="Append output to this transcript log and skip samples already completed there.")
    parser.add_argument("--ltp-case", action="append", default=[], help="Run only the named LTP case. May be repeated or comma-separated.")
    parser.add_argument("--ltp-start-case", help="Run LTP starting from the named case in runtest/syscalls.")
    parser.add_argument(
        "--ltp-runtime-mul",
        type=float,
        help=f"Override LTP_RUNTIME_MUL for generated ltp_testcode.sh. Defaults to {DEDICATED_LTP_RUNTIME_MUL:g} for dedicated ltp-* subsets, 0.45 for other --ltp-case runs, and 1.0 otherwise.",
    )
    parser.add_argument(
        "--ltp-shards",
        type=int,
        help=f"Split dedicated pure ltp-* subsets into N parallel shards before aggregating results. Defaults to {DEDICATED_LTP_SHARDS} for pure dedicated ltp-* subsets, and 1 otherwise.",
    )
    parser.add_argument(
        "--skip-ltp",
        action="store_true",
        help="Run all selected samples except the four ltp-* variants.",
    )
    parser.add_argument(
        "--online-repro",
        action="store_true",
        help="Run each arch in one official single boot with no retry of later groups.",
    )
    parser.add_argument(
        "--quick-point-retest",
        action="store_true",
        help="Rebuild only the needed arch kernel, reuse cached rootfs, and reuse shared official rootfs for fast single-point retests.",
    )
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Only prepare/reuse prerequisite kernels and rootfs for the selected samples, and under --online-repro also warm official rootfs/base images, then exit without running cases.",
    )
    parser.add_argument(
        "--refresh-ltp-shard-weights",
        action="append",
        default=[],
        metavar="VARIANT[,VARIANT...]",
        help=(
            "Refresh and persist LTP shard runtime weights for one or more variants "
            "(supports repeated flags and comma-separated values, e.g. glibc-rv,musl-rv) "
            f"from current detailed LTP logs (with local exports only as fallback). "
            f"Allowed: {', '.join(sorted(LTP_RUNTIME_WEIGHT_SAMPLE_BY_VARIANT))}."
        ),
    )
    args = parser.parse_args()

    started_at = datetime.now(timezone.utc)
    WORK_ROOT = resolve_repo_path(args.work_root)
    SHARED_CACHE_ROOT = resolve_repo_path(args.shared_cache_root)
    try:
        refresh_ltp_shard_weight_variants = parse_refresh_ltp_shard_weight_variants(
            args.refresh_ltp_shard_weights
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    ENABLE_LTP_RUNTIME_WEIGHT_REFRESH = bool(refresh_ltp_shard_weight_variants)
    LTP_RUNTIME_WEIGHT_REFRESH_VARIANTS = set(refresh_ltp_shard_weight_variants)
    LTP_CASE_RUNTIME_WEIGHT_CACHE = {}
    report_path = resolve_repo_path(args.report)
    logs_dir = WORK_ROOT / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, CaseResult] = {}
    stop_reason: str | None = None

    samples = select_samples(args.subset, skip_ltp=args.skip_ltp)
    requested_samples = list(samples)
    ltp_selected_cases = [case for chunk in args.ltp_case for case in chunk.split(",") if case]
    ltp_start_case = args.ltp_start_case
    if args.skip_ltp and (ltp_selected_cases or ltp_start_case):
        print("--skip-ltp cannot be used together with --ltp-case or --ltp-start-case", file=sys.stderr)
        return 2
    if ltp_selected_cases and ltp_start_case:
        print("--ltp-case cannot be used together with --ltp-start-case", file=sys.stderr)
        return 2
    if args.ltp_runtime_mul is not None and args.ltp_runtime_mul <= 0:
        print("--ltp-runtime-mul must be > 0", file=sys.stderr)
        return 2
    if args.ltp_shards is not None and args.ltp_shards <= 0:
        print("--ltp-shards must be > 0", file=sys.stderr)
        return 2
    if args.rootfs_variant_jobs <= 0:
        print("--rootfs-variant-jobs must be > 0", file=sys.stderr)
        return 2
    pure_ltp_subset = bool(samples) and all(parse_sample(sample)[0] == "ltp" for sample in samples)
    ltp_runtime_mul = args.ltp_runtime_mul if args.ltp_runtime_mul is not None else (
        DEDICATED_LTP_RUNTIME_MUL if pure_ltp_subset else (0.45 if ltp_selected_cases else 1.0)
    )
    ltp_shards = args.ltp_shards if args.ltp_shards is not None else (
        DEDICATED_LTP_SHARDS if pure_ltp_subset and not ltp_selected_cases and not ltp_start_case else 1
    )
    LTP_EXPECTED_CASES_OVERRIDE = ltp_selected_cases or None
    for sample in samples:
        if sample not in SAMPLE_ORDER:
            print(f"unknown sample: {sample}", file=sys.stderr)
            return 2
    if refresh_ltp_shard_weight_variants:
        refresh_case_names = ltp_case_names(selected_cases=ltp_selected_cases or None, start_case=ltp_start_case)
        for variant in refresh_ltp_shard_weight_variants:
            refresh_ltp_case_runtime_weight_variant(
                variant,
                ltp_shards,
                refresh_case_names,
            )

    if args.resume_log:
        resume_log_path = Path(args.resume_log)
        if not resume_log_path.is_absolute():
            resume_log_path = ROOT / resume_log_path
        completed_candidates = parse_completed_samples_from_resume_log(resume_log_path)
        resumed_results = load_validated_results(
            [sample for sample in samples if sample in completed_candidates],
            logs_dir,
        )
        completed_samples = set(resumed_results)
        samples = [sample for sample in samples if sample not in completed_samples]
        init_transcript_log(resume_log_path)
        append_transcript_line(
            "# " + " ".join(shlex.quote(part) for part in [sys.executable, *sys.argv])
        )
        console(
            f"[resume] loaded {len(completed_samples)} completed samples, remaining {len(samples)}",
            err=False,
        )
        results.update(resumed_results)
    else:
        TRANSCRIPT_LOG_PATH = None

    variants_needed = {(parse_sample(sample)[2], parse_sample(sample)[1]) for sample in samples}
    exit_code = 0
    variants: dict[tuple[str, str], Path] | None = None
    try:
        if samples:
            try:
                variants = ensure_prerequisites(
                    args.build_jobs,
                    args.rootfs_variant_jobs,
                    args.rebuild_rootfs,
                    variants_needed,
                    official_repro_build_targets(samples, args.online_repro),
                    logs_dir,
                    quick_reuse_only=args.quick_point_retest,
                )
            except Exception as exc:
                stop_reason = str(exc)
                console(f"[fail] {stop_reason}", err=True)
                exit_code = 1
            else:
                if args.prepare_only:
                    if args.online_repro:
                        for arch in ARCH_ORDER:
                            arch_samples = [sample for sample in samples if sample.endswith(f"-{arch}")]
                            if not arch_samples:
                                continue
                            prepare_online_repro_rootfs(
                                arch,
                                arch_samples,
                                variants=variants,
                                rebuild_rootfs=args.rebuild_rootfs,
                                quick_point_retest=args.quick_point_retest,
                                ltp_selected_cases=ltp_selected_cases,
                                ltp_runtime_mul=ltp_runtime_mul,
                                ltp_start_case=ltp_start_case,
                                kernel_generated_ltp_wrapper=True,
                                prepare_base_image=True,
                            )
                    console("[prepare-only] prerequisites ready")
                    samples = []

        if variants is not None and samples:
            parallel_ltp_shard_mode = (
                ltp_shards > 1
                and pure_ltp_subset
                and not ltp_selected_cases
                and not ltp_start_case
            )
            isolated_ltp_point_mode = bool(ltp_selected_cases) and all(
                parse_sample(sample)[0] == "ltp" for sample in samples
            )
            if parallel_ltp_shard_mode:
                for arch in ARCH_ORDER:
                    arch_samples = [sample for sample in samples if sample.endswith(f"-{arch}")]
                    if not arch_samples:
                        continue
                    for sample in sorted(arch_samples, key=official_execution_key):
                        group, runtime, sample_arch = parse_sample(sample)
                        started = time.monotonic()
                        result = run_ltp_sharded_sample(
                            sample,
                            logs_dir,
                            args.timeout,
                            rebuild_rootfs=args.rebuild_rootfs,
                            variants=variants,
                            ltp_runtime_mul=ltp_runtime_mul,
                            ltp_start_case=ltp_start_case,
                            shard_count=ltp_shards,
                        )
                        results[sample] = result
                        console(
                            f"[case] {official_case_label(group, runtime, sample_arch)} "
                            f"{format_duration(max(0.0, time.monotonic() - started))} "
                            f"points {result.passed}/{result.total}"
                        )
                        if result.timed_out:
                            console(
                                f"[timeout] {sample}: {result.error or result.stop_reason or f'exceeded {args.timeout}s'}",
                                err=True,
                            )
                            emit_log_tail(sample, result.log_path)
                            exit_code = max(exit_code, 124)
                        elif not result.ok:
                            console(f"[fail] {sample}: {result.summary} ({result.error or 'failed'})", err=True)
                        flush_report(report_path, results, started_at, stop_reason)
            elif isolated_ltp_point_mode:
                for arch in ARCH_ORDER:
                    arch_samples = [sample for sample in samples if sample.endswith(f"-{arch}")]
                    if not arch_samples:
                        continue
                    out_dir = prepare_online_repro_rootfs(
                        arch,
                        arch_samples,
                        variants=variants,
                        rebuild_rootfs=args.rebuild_rootfs,
                        quick_point_retest=args.quick_point_retest,
                        ltp_selected_cases=ltp_selected_cases,
                        ltp_runtime_mul=ltp_runtime_mul,
                        ltp_start_case=ltp_start_case,
                    )

                    for sample in sorted(arch_samples, key=official_execution_key):
                        group, runtime, sample_arch = parse_sample(sample)
                        started = time.monotonic()
                        result = run_sample_from_rootfs(
                            sample,
                            out_dir,
                            logs_dir,
                            args.timeout,
                            command_override=f"/busybox sh /{runtime}/{SCRIPT_BY_GROUP[group]}",
                        )
                        results[sample] = result
                        console(
                            f"[case] {official_case_label(group, runtime, sample_arch)} "
                            f"{format_duration(max(0.0, time.monotonic() - started))} "
                            f"points {result.passed}/{result.total}"
                        )
                        if result.timed_out:
                            console(
                                f"[timeout] {sample}: {result.error or result.stop_reason or f'exceeded {args.timeout}s'}",
                                err=True,
                            )
                            emit_log_tail(sample, result.log_path)
                            exit_code = max(exit_code, 124)
                        elif not result.ok:
                            console(f"[fail] {sample}: {result.summary} ({result.error or 'failed'})", err=True)
                        flush_report(report_path, results, started_at, stop_reason)
            else:
                for arch in ARCH_ORDER:
                    arch_samples = [sample for sample in samples if sample.endswith(f"-{arch}")]
                    if not arch_samples:
                        continue
                    pending_arch_samples = sorted(arch_samples, key=official_execution_key)
                    retry_round = 0
                    while pending_arch_samples:
                        retry_round += 1
                        out_dir = prepare_online_repro_rootfs(
                            arch,
                            pending_arch_samples,
                            variants=variants,
                            rebuild_rootfs=args.rebuild_rootfs,
                            quick_point_retest=args.quick_point_retest,
                            ltp_selected_cases=ltp_selected_cases,
                            ltp_runtime_mul=ltp_runtime_mul,
                            ltp_start_case=ltp_start_case,
                            kernel_generated_ltp_wrapper=args.online_repro,
                            retry_round=retry_round,
                        )

                        arch_results = run_official_arch(arch, out_dir, logs_dir, args.timeout, pending_arch_samples)
                        raw_log_path = logs_dir / f"official-{arch}.raw.out"
                        if args.online_repro:
                            results.update(arch_results)
                            for sample in pending_arch_samples:
                                result = arch_results[sample]
                                if result.timed_out:
                                    console(
                                        f"[timeout] official-{arch}/{sample}: {result.error or result.stop_reason or f'exceeded {args.timeout}s'}",
                                        err=True,
                                    )
                            break
                        retry_samples = [
                            sample
                            for sample in pending_arch_samples
                            if should_retry_official_sample(arch_results[sample])
                        ]
                        for sample, result in arch_results.items():
                            if sample not in retry_samples:
                                results[sample] = result

                        batch_had_timeout = any(result.timed_out for result in arch_results.values())
                        for sample in pending_arch_samples:
                            result = arch_results[sample]
                            if result.timed_out and not should_retry_official_sample(result):
                                console(
                                    f"[timeout] official-{arch}/{sample}: {result.error or result.stop_reason or f'exceeded {args.timeout}s'}",
                                    err=True,
                                )
                                emit_log_tail(f"official-{arch}", raw_log_path)
                                exit_code = max(exit_code, 124)
                            elif not result.ok and not should_retry_official_sample(result):
                                console(f"[fail] {sample}: {result.summary} ({result.error or 'failed'})", err=True)

                        flush_report(report_path, results, started_at, stop_reason)

                        if not retry_samples:
                            break
                        if retry_samples == pending_arch_samples:
                            if can_isolate_retry_head(pending_arch_samples, arch_results, retry_samples):
                                blocker = pending_arch_samples[0]
                                results[blocker] = arch_results[blocker]
                                pending_arch_samples = pending_arch_samples[1:]
                                console(
                                    f"[retry] official-{arch}: isolate blocker {blocker}, continue remaining {len(pending_arch_samples)} samples",
                                    err=False,
                                )
                                flush_report(report_path, results, started_at, stop_reason)
                                continue
                            results.update(arch_results)
                            console(
                                f"[timeout] official-{arch}: no progress before stop, cannot isolate remaining samples",
                                err=True,
                            )
                            exit_code = max(exit_code, 124)
                            break
                        if batch_had_timeout:
                            console(
                                f"[retry] official-{arch}: restarting remaining {len(retry_samples)} samples after earlier stop",
                                err=False,
                            )
                        pending_arch_samples = retry_samples
        elif not samples:
            console("[resume] no remaining samples to run")
    except KeyboardInterrupt:
        terminate_all_active_child_procs()
        stop_reason = "interrupted by user (Ctrl+C)"
        console(f"[stop] {stop_reason}", err=True)
        exit_code = 130
    finally:
        flush_report(report_path, results, started_at, stop_reason)
        sync_local_named_outputs(report_path, logs_dir, requested_samples, results, started_at)
        console(f"[logs] report: {relative_path(report_path)}")
        console(f"[logs] logs: {relative_path(logs_dir)}")
        console(f"[logs] local report: {relative_path(LOCAL_EXPORT_DIR / LOCAL_REPORT_EXPORT_NAME)}")
        console(f"[logs] local riscv: {relative_path(LOCAL_EXPORT_DIR / 'local_Riscv输出.txt')}")
        console(f"[logs] local loongarch: {relative_path(LOCAL_EXPORT_DIR / 'local_LoongArch输出.txt')}")

    sample_pass = sum(1 for result in results.values() if result.ok)
    sample_fail = sum(1 for result in results.values() if result.details is not None and not result.ok and not result.timed_out and not result.skipped)
    sample_error = sum(1 for result in results.values() if result.details is None and not result.timed_out and not result.skipped)
    sample_timeout = sum(1 for result in results.values() if result.timed_out and not result.skipped)
    sample_skip = sum(1 for result in results.values() if result.skipped)
    point_pass = sum(result.passed for result in results.values() if result.details is not None)
    point_total = sum(result.total for result in results.values() if result.details is not None)
    console(f"[summary] samples pass={sample_pass} fail={sample_fail} error={sample_error} timeout={sample_timeout} skip={sample_skip}")
    console(f"[summary] points {point_pass}/{point_total}")

    if stop_reason:
        console(f"[stop] {stop_reason}", err=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
