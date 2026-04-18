#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTSUITS_ROOT = Path(os.environ.get("TESTSUITS_ROOT", ROOT / "testsuits-for-oskernel-pre-2025"))
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
GROUPS = [
    "unixbench",
    "iperf",
    "libcbench",
    "lmbench",
    "netperf",
    "cyclictest",
    "ltp",
]

LMBENCH_HEADERS = [
    "latency measurements",
    "file system latency",
    "Bandwidth measurements",
    "context switch overhead",
]

LMBENCH_RULES = [
    ("Simple syscall:", 0.0757, 2.0),
    ("Simple read:", 0.1, 2.2),
    ("Simple write:", 0.1, 2.2),
    ("Simple stat:", 0.5, 2.1),
    ("Simple fstat:", 0.15, 2.0),
    ("Simple open/close:", 1.0, 3.0),
    ("Select on file:", 0.5, 2.7),
    ("Signal handler installation:", 0.1, 2.3),
    ("Signal handler overhead:", 0.8, 2.0),
    ("Protection fault:", 0.3, 2.5),
    ("Pipe latency:", 4.0, 20.0),
    ("Process fork+exit:", 94.0, 200.0),
    ("Process fork+execve:", 101.0, 300.0),
    ("Process fork+/bin/sh -c:", 300.0, 2000.0),
    ("File /var/tmp/XXX write bandwidth:", 3000.0, 200000.0),
    ("Pagefaults on /var/tmp/XXX:", 0.1, 3.2),
    ("Mmap latency:", 0.3, 10.0),
    ("Pipe bandwidth:", 1000.0, 10000.0),
    ("File system create+delete:", 100000.0, 300000.0),
    ("File /var/tmp/XXX read bandwidth:", 0.5, 2.0),
    ("File /var/tmp/XXX read open2close bandwidth:", 0.5, 2.2),
    ("Mmap read bandwidth:", 0.5, 3.0),
    ("Mmap read open2close bandwidth:", 0.5, 3.0),
    ("96p/32K ctxsw:", 1.0, 5.0),
]


def fail(message: str) -> None:
    raise ValueError(message)


def sanitize_line(raw: str) -> str:
    return ANSI_ESCAPE_RE.sub("", raw.rstrip("\n").rstrip("\r"))


def read_text(path: Path) -> str:
    return "\n".join(
        sanitize_line(line)
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
    )


def extract_group(full_text: str, group: str) -> list[str]:
    start = f"#### OS COMP TEST GROUP START {group} ####"
    end = f"#### OS COMP TEST GROUP END {group} ####"
    inside = False
    lines: list[str] = []
    for raw in full_text.split("\n"):
        line = sanitize_line(raw)
        if not inside:
            if start in line:
                inside = True
            continue
        if end in line:
            return lines
        lines.append(line)
    fail(f"missing group markers for {group}")


def expected_unixbench_labels() -> list[str]:
    path = TESTSUITS_ROOT / "scripts/unixbench/unixbench_testcode.sh"
    labels: list[str] = []
    for line in read_text(path).splitlines():
        if "Unixbench " not in line:
            continue
        match = re.search(r'print "([^"]+)"\$0', line)
        if match:
            labels.append(match.group(1))
    return labels


def expected_shell_cases(path: Path, func_name: str) -> list[str]:
    cases: list[str] = []
    pattern = re.compile(rf'^\s*{re.escape(func_name)}\s+"?([A-Z0-9_]+)"?')
    for line in read_text(path).splitlines():
        match = pattern.match(line)
        if match:
            cases.append(match.group(1))
    return cases


def expected_libcbench_labels() -> list[str]:
    path = TESTSUITS_ROOT / "libc-bench/main.c"
    labels: list[str] = []
    pattern = re.compile(r'^\s*RUN\(([^,]+),\s*(.+)\);\s*$')
    for line in read_text(path).splitlines():
        match = pattern.match(line)
        if not match:
            continue
        name = match.group(1).strip()
        arg = match.group(2).strip()
        labels.append(f"{name} ({arg})")
    return labels


def expected_ltp_cases() -> list[str]:
    path = TESTSUITS_ROOT / "ltp-full-20240524/runtest/syscalls"
    cases: list[str] = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cases.append(stripped.split()[0])
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
    match = re.search(r'(-?\d+(?:\.\d+)?)', line)
    if not match:
        fail(f"missing numeric value in line: {line}")
    return float(match.group(1))


def validate_unixbench(lines: list[str]) -> str:
    labels = expected_unixbench_labels()
    if not labels:
        fail("unixbench expected label list is empty")
    pos = 0
    for label in labels:
        idx = find_line_with_prefix(lines, label, pos)
        if idx < 0:
            fail(f"unixbench missing line: {label}")
        value_text = lines[idx][len(label):].strip()
        if not re.fullmatch(r'-?\d+(?:\.\d+)?', value_text):
            fail(f"unixbench malformed value for {label}: {lines[idx]}")
        pos = idx + 1
    return f"{len(labels)} metrics"


def validate_iperf(lines: list[str]) -> str:
    tests = expected_shell_cases(
        TESTSUITS_ROOT / "scripts/iperf/iperf_testcode.sh",
        "run_iperf",
    )
    pos = 0
    for name in tests:
        begin = f"====== iperf {name} begin ======"
        end = f"====== iperf {name} end: success ======"
        begin_idx = find_line_index(lines, begin, pos)
        if begin_idx < 0:
            fail(f"iperf missing begin marker for {name}")
        end_idx = find_line_index(lines, end, begin_idx + 1)
        if end_idx < 0:
            fail(f"iperf missing success marker for {name}")
        if not any(line.startswith("[") for line in lines[begin_idx + 1:end_idx]):
            fail(f"iperf missing throughput body for {name}")
        pos = end_idx + 1
    return f"{len(tests)} scenarios"


def validate_libcbench(lines: list[str]) -> str:
    labels = expected_libcbench_labels()
    pos = 0
    for label in labels:
        idx = find_line_index(lines, label, pos)
        if idx < 0:
            fail(f"libcbench missing label: {label}")
        time_idx = find_line_with_prefix(lines, "  time:", idx + 1)
        if time_idx < 0:
            fail(f"libcbench missing time line for {label}")
        pos = time_idx + 1
    return f"{len(labels)} benchmark blocks"


def validate_lmbench(lines: list[str]) -> str:
    pos = 0
    for header in LMBENCH_HEADERS:
        idx = find_line_index(lines, header, pos)
        if idx < 0:
            fail(f"lmbench missing section header: {header}")
        pos = idx + 1
    matched = 0
    for prefix, lower, upper in LMBENCH_RULES:
        idx = find_line_with_prefix(lines, prefix)
        if idx < 0:
            fail(f"lmbench missing metric: {prefix}")
        value = parse_first_number(lines[idx][len(prefix):])
        if value < lower or value > upper:
            fail(
                f"lmbench metric out of range for {prefix} {value} not in [{lower}, {upper}]"
            )
        matched += 1
    return f"{matched} metrics in expected ranges"


def validate_netperf(lines: list[str]) -> str:
    tests = expected_shell_cases(
        TESTSUITS_ROOT / "scripts/netperf/netperf_testcode.sh",
        "run_netperf",
    )
    pos = 0
    for name in tests:
        begin = f"====== netperf {name} begin ======"
        end = f"====== netperf {name} end: success ======"
        begin_idx = find_line_index(lines, begin, pos)
        if begin_idx < 0:
            fail(f"netperf missing begin marker for {name}")
        end_idx = find_line_index(lines, end, begin_idx + 1)
        if end_idx < 0:
            fail(f"netperf missing success marker for {name}")
        if not any("Throughput" in line for line in lines[begin_idx + 1:end_idx]):
            fail(f"netperf missing throughput body for {name}")
        pos = end_idx + 1
    return f"{len(tests)} scenarios"


def validate_cyclictest(lines: list[str]) -> str:
    tests = expected_shell_cases(
        TESTSUITS_ROOT / "scripts/cyclictest/cyclictest_testcode.sh",
        "run_cyclictest",
    )
    pos = 0
    for name in tests:
        begin = f"====== cyclictest {name} begin ======"
        end = f"====== cyclictest {name} end: success ======"
        begin_idx = find_line_index(lines, begin, pos)
        if begin_idx < 0:
            fail(f"cyclictest missing begin marker for {name}")
        end_idx = find_line_index(lines, end, begin_idx + 1)
        if end_idx < 0:
            fail(f"cyclictest missing success marker for {name}")
        thread_lines = [line for line in lines[begin_idx + 1:end_idx] if line.startswith("T:")]
        minimum = 8 if name.endswith("P8") else 1
        if len(thread_lines) < minimum:
            fail(f"cyclictest insufficient summary lines for {name}")
        pos = end_idx + 1
    if find_line_index(lines, "====== start hackbench ======") < 0:
        fail("cyclictest missing hackbench start marker")
    if find_line_index(lines, "====== kill hackbench: success ======") < 0:
        fail("cyclictest missing successful hackbench shutdown")
    return f"{len(tests)} scenarios plus hackbench lifecycle"


def validate_ltp(lines: list[str]) -> str:
    cases = expected_ltp_cases()
    pos = 0
    for name in cases:
        run_line = f"RUN LTP CASE {name}"
        pass_line = f"PASS LTP CASE {name} : 0"
        legacy_ok_line = f"FAIL LTP CASE {name} : 0"
        run_idx = find_line_index(lines, run_line, pos)
        if run_idx < 0:
            fail(f"ltp missing case start: {name}")
        pass_idx = find_line_index(lines, pass_line, run_idx + 1)
        legacy_ok_idx = find_line_index(lines, legacy_ok_line, run_idx + 1)
        ok_idx = pass_idx if pass_idx >= 0 else legacy_ok_idx
        if ok_idx < 0:
            fail(f"ltp missing zero-exit result: {name}")
        pos = ok_idx + 1
    return f"{len(cases)} syscall cases"


VALIDATORS = {
    "unixbench": validate_unixbench,
    "iperf": validate_iperf,
    "libcbench": validate_libcbench,
    "lmbench": validate_lmbench,
    "netperf": validate_netperf,
    "cyclictest": validate_cyclictest,
    "ltp": validate_ltp,
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_remaining_groups.py <full-log>", file=sys.stderr)
        return 2

    full_log = Path(sys.argv[1])
    text = read_text(full_log)

    for group in GROUPS:
        lines = extract_group(text, group)
        detail = VALIDATORS[group](lines)
        print(f"[ok] {group}: {detail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
