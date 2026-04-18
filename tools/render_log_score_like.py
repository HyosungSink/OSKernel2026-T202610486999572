#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


CASE_RE = re.compile(
    r"^\[case\] (?P<runtime>glibc|musl)-(?P<arch>rv|la)-(?P<group>[a-z0-9]+)\s+"
    r"(?:(?P<duration>\S+)\s+)?points\s+(?P<passed>\d+)/(?P<total>\d+)$"
)
CASE_TIMEOUT_RE = re.compile(
    r"^\[case\] (?P<runtime>glibc|musl)-(?P<arch>rv|la)-(?P<group>[a-z0-9]+)\s+"
    r"timeout\s+points\s+(?P<passed>\d+)/(?P<total>\d+)$"
)
FAIL_RE = re.compile(
    r"^\[fail\] (?P<group>[a-z0-9]+)-(?P<runtime>glibc|musl)-(?P<arch>rv|la): "
    r"(?P<passed>\d+)/(?P<total>\d+) \((?P<reason>.+)\)$"
)
TIMEOUT_RE = re.compile(
    r"^\[timeout\] official-(?P<arch>rv|la)/(?P<group>[a-z0-9]+)-(?P<runtime>glibc|musl)-"
    r"(?P<arch2>rv|la): (?P<reason>.+)$"
)
SUMMARY_SAMPLES_RE = re.compile(
    r"^\[summary\] samples pass=(?P<pass>\d+) fail=(?P<fail>\d+) error=(?P<error>\d+) "
    r"timeout=(?P<timeout>\d+) skip=(?P<skip>\d+)$"
)
SUMMARY_POINTS_RE = re.compile(r"^\[summary\] points (?P<passed>\d+)/(?P<total>\d+)$")

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
RUNTIME_ARCH_ORDER = [("glibc", "la"), ("glibc", "rv"), ("musl", "la"), ("musl", "rv")]
SAMPLE_ORDER = [(group, runtime, arch) for group in GROUP_ORDER for runtime in ("glibc", "musl") for arch in ("la", "rv")]


@dataclass
class SampleResult:
    group: str
    runtime: str
    arch: str
    passed: int
    total: int
    duration: str | None = None
    status: str = "PASS"
    reason: str | None = None

    @property
    def sample_label(self) -> str:
        return f"{self.group}-{self.runtime}-{self.arch}"

    @property
    def log_path(self) -> str:
        return f"dev/full-suite/logs/{self.sample_label}.out"

    @property
    def detail(self) -> str:
        return f"{self.passed}/{self.total}"


def load_results(log_path: Path) -> tuple[dict[tuple[str, str, str], SampleResult], dict[str, int] | None, tuple[int, int] | None]:
    results: dict[tuple[str, str, str], SampleResult] = {}
    summary_counts: dict[str, int] | None = None
    summary_points: tuple[int, int] | None = None

    for raw_line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if match := CASE_RE.match(line):
            key = (match.group("group"), match.group("runtime"), match.group("arch"))
            results[key] = SampleResult(
                group=match.group("group"),
                runtime=match.group("runtime"),
                arch=match.group("arch"),
                passed=int(match.group("passed")),
                total=int(match.group("total")),
                duration=match.group("duration"),
                status="PASS",
            )
            continue
        if match := CASE_TIMEOUT_RE.match(line):
            key = (match.group("group"), match.group("runtime"), match.group("arch"))
            results[key] = SampleResult(
                group=match.group("group"),
                runtime=match.group("runtime"),
                arch=match.group("arch"),
                passed=int(match.group("passed")),
                total=int(match.group("total")),
                duration=None,
                status="TIMEOUT",
            )
            continue
        if match := FAIL_RE.match(line):
            key = (match.group("group"), match.group("runtime"), match.group("arch"))
            result = results.get(key)
            if result is None:
                result = SampleResult(
                    group=match.group("group"),
                    runtime=match.group("runtime"),
                    arch=match.group("arch"),
                    passed=int(match.group("passed")),
                    total=int(match.group("total")),
                    status="FAIL",
                )
                results[key] = result
            result.status = "FAIL"
            result.reason = match.group("reason")
            continue
        if match := TIMEOUT_RE.match(line):
            key = (match.group("group"), match.group("runtime"), match.group("arch"))
            result = results.get(key)
            if result is None:
                result = SampleResult(
                    group=match.group("group"),
                    runtime=match.group("runtime"),
                    arch=match.group("arch"),
                    passed=0,
                    total=0,
                    status="TIMEOUT",
                )
                results[key] = result
            result.status = "TIMEOUT"
            result.reason = match.group("reason")
            continue
        if match := SUMMARY_SAMPLES_RE.match(line):
            summary_counts = {k: int(v) for k, v in match.groupdict().items()}
            continue
        if match := SUMMARY_POINTS_RE.match(line):
            summary_points = (int(match.group("passed")), int(match.group("total")))

    return results, summary_counts, summary_points


def render(log_path: Path, out_path: Path) -> None:
    results, summary_counts, summary_points = load_results(log_path)

    by_group: dict[str, dict[tuple[str, str], SampleResult]] = defaultdict(dict)
    totals_by_runtime_arch: dict[tuple[str, str], tuple[int, int]] = {}
    for key, result in results.items():
        by_group[result.group][(result.runtime, result.arch)] = result
    for runtime, arch in RUNTIME_ARCH_ORDER:
        passed = sum(
            r.passed for r in results.values() if r.runtime == runtime and r.arch == arch
        )
        total = sum(
            r.total for r in results.values() if r.runtime == runtime and r.arch == arch
        )
        totals_by_runtime_arch[(runtime, arch)] = (passed, total)

    lines: list[str] = []
    now = datetime.now(timezone.utc).isoformat()
    lines.append(f"本地完整测试时间：{now}")
    lines.append("")
    lines.append("根据 log.txt 整理的 score 风格结果")
    lines.append("")
    lines.append("评测完成")
    lines.append(f"原始日志：{log_path}")
    lines.append("")
    lines.append("得分详情")
    lines.append("测试点\tglibc-la\tglibc-rv\tmusl-la\tmusl-rv\t总计")
    for group in GROUP_ORDER:
        row = [group]
        group_passed = 0
        group_total = 0
        for runtime, arch in RUNTIME_ARCH_ORDER:
            result = by_group.get(group, {}).get((runtime, arch))
            if result is None:
                row.append("-")
            else:
                row.append(f"{result.passed}/{result.total}")
                group_passed += result.passed
                group_total += result.total
        row.append(f"{group_passed}/{group_total}")
        lines.append("\t".join(row))
    total_passed = sum(p for p, _ in totals_by_runtime_arch.values())
    total_all = sum(t for _, t in totals_by_runtime_arch.values())
    lines.append(
        "\t".join(
            [
                "总计",
                *(f"{totals_by_runtime_arch[(runtime, arch)][0]}/{totals_by_runtime_arch[(runtime, arch)][1]}"
                  for runtime, arch in RUNTIME_ARCH_ORDER),
                f"{total_passed}/{total_all}",
            ]
        )
    )
    lines.append("")
    lines.append("样例执行结果")
    lines.append("样例\t状态\t明细\t日志")
    for group, runtime, arch in SAMPLE_ORDER:
        result = results.get((group, runtime, arch))
        if result is None:
            continue
        lines.append(
            "\t".join(
                [
                    result.sample_label,
                    result.status,
                    result.detail,
                    result.log_path,
                ]
            )
        )

    failure_results = [
        result for result in results.values() if result.status in {"FAIL", "TIMEOUT"} and result.reason
    ]
    if failure_results:
        lines.append("")
        lines.append("失败与超时原因")
        lines.append("样例\t状态\t原因")
        for group, runtime, arch in SAMPLE_ORDER:
            result = results.get((group, runtime, arch))
            if result is None or result.status not in {"FAIL", "TIMEOUT"} or not result.reason:
                continue
            lines.append(
                "\t".join([result.sample_label, result.status, result.reason])
            )

    if summary_counts is not None:
        lines.append("")
        lines.append("样例统计")
        lines.append("项目\t数量")
        for key in ["pass", "fail", "error", "timeout", "skip"]:
            lines.append(f"{key}\t{summary_counts[key]}")
    if summary_points is not None:
        lines.append("")
        lines.append("总分统计")
        lines.append(f"points\t{summary_points[0]}/{summary_points[1]}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Render log.txt into a score.txt-like summary.")
    parser.add_argument("log", nargs="?", default="log.txt", help="Source log file.")
    parser.add_argument(
        "-o",
        "--output",
        default="log.score.txt",
        help="Output txt path.",
    )
    args = parser.parse_args()
    render(Path(args.log), Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
