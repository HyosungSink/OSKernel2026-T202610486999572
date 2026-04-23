#!/usr/bin/env python3

from __future__ import annotations

import argparse
import concurrent.futures
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools/run_full_local_suite.py"
TESTSUITS_ROOT = Path(os.environ.get("TESTSUITS_ROOT", ROOT / "testsuits-for-oskernel-pre-2025"))
LTP_RUNTEST_PATH = TESTSUITS_ROOT / "ltp-full-20240524" / "runtest" / "syscalls"
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass
class JobResult:
    case: str
    returncode: int
    work_root: Path
    report_path: Path
    transcript_path: Path
    sample_status: str
    sample_detail: str


def resolve_repo_path(path: str) -> Path:
    resolved = Path(path)
    if not resolved.is_absolute():
        resolved = ROOT / resolved
    return resolved


def sanitize_name(name: str) -> str:
    safe = SAFE_NAME_RE.sub("-", name).strip("-.")
    return safe or "case"


def load_all_ltp_cases() -> list[str]:
    if not LTP_RUNTEST_PATH.exists():
        raise SystemExit(f"missing LTP runtest file: {LTP_RUNTEST_PATH}")
    cases: list[str] = []
    for raw in LTP_RUNTEST_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cases.append(stripped.split()[0])
    if not cases:
        raise SystemExit(f"no LTP cases found in {LTP_RUNTEST_PATH}")
    return cases


def load_cases(args: argparse.Namespace) -> list[str]:
    cases: list[str] = []
    for chunk in args.case:
        cases.extend(part for part in chunk.split(",") if part)
    if args.case_file:
        for raw in resolve_repo_path(args.case_file).read_text(encoding="utf-8").splitlines():
            stripped = raw.strip()
            if stripped and not stripped.startswith("#"):
                cases.append(stripped)
    deduped: list[str] = []
    seen: set[str] = set()
    for case in cases:
        if case not in seen:
            deduped.append(case)
            seen.add(case)
    if not deduped:
        return load_all_ltp_cases()
    return deduped


def load_sample_status(report_path: Path, sample: str) -> tuple[str, str]:
    if not report_path.exists():
        return "ERROR", "missing report"
    for raw in report_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not raw.startswith(sample + "\t"):
            continue
        parts = raw.split("\t")
        if len(parts) >= 3:
            return parts[1], parts[2]
        break
    return "ERROR", "missing sample row"


def run_case(
    case: str,
    *,
    arch: str,
    runtime: str,
    timeout: int,
    work_root_base: Path,
    shared_cache_root: Path,
    report_dir: Path,
    extra_args: list[str],
) -> JobResult:
    safe_case = sanitize_name(case)
    work_root = work_root_base / f"{arch}-{runtime}-{safe_case}"
    report_path = report_dir / f"{arch}-{runtime}-{safe_case}.txt"
    transcript_path = report_dir / f"{arch}-{runtime}-{safe_case}.log"
    work_root.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(RUNNER),
        "--timeout",
        str(timeout),
        "--work-root",
        str(work_root),
        "--shared-cache-root",
        str(shared_cache_root),
        "--report",
        str(report_path),
        "--subset",
        f"ltp-{runtime}-{arch}",
        "--ltp-case",
        case,
        *extra_args,
    ]

    with transcript_path.open("w", encoding="utf-8") as transcript:
        transcript.write("# " + " ".join(shlex.quote(part) for part in cmd) + "\n")
        transcript.flush()
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            stdout=transcript,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    sample_status, sample_detail = load_sample_status(report_path, f"ltp-{runtime}-{arch}")

    return JobResult(
        case=case,
        returncode=completed.returncode,
        work_root=work_root,
        report_path=report_path,
        transcript_path=transcript_path,
        sample_status=sample_status,
        sample_detail=sample_detail,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely run LTP points in parallel with isolated work roots and shared read-only caches."
    )
    parser.add_argument("--arch", choices=["rv", "la"], required=True)
    parser.add_argument("--runtime", choices=["glibc", "musl"], required=True)
    parser.add_argument("--jobs", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--case", action="append", default=[], help="LTP case name. May be repeated or comma-separated. Defaults to all LTP syscalls cases when omitted.")
    parser.add_argument("--case-file", help="Path to a newline-separated case list.")
    parser.add_argument("--work-root-base", default="dev/full-suite/parallel-ltp", help="Base directory for per-case work roots.")
    parser.add_argument("--shared-cache-root", default="dev/full-suite", help="Shared readonly cache root reused by all jobs.")
    parser.add_argument("--report-dir", default="dev/full-suite/parallel-ltp-reports", help="Directory for per-case reports and transcripts.")
    args, extra_args = parser.parse_known_args()

    cases = load_cases(args)
    work_root_base = resolve_repo_path(args.work_root_base)
    shared_cache_root = resolve_repo_path(args.shared_cache_root)
    report_dir = resolve_repo_path(args.report_dir)

    print(
        f"[parallel-ltp] arch={args.arch} runtime={args.runtime} jobs={args.jobs} cases={len(cases)}",
        flush=True,
    )

    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        future_map = {
            executor.submit(
                run_case,
                case,
                arch=args.arch,
                runtime=args.runtime,
                timeout=args.timeout,
                work_root_base=work_root_base,
                shared_cache_root=shared_cache_root,
                report_dir=report_dir,
                extra_args=extra_args,
            ): case
            for case in cases
        }
        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            status = result.sample_status
            if result.returncode != 0:
                status = f"{status}/rc={result.returncode}"
            print(
                f"[parallel-ltp] case={result.case} status={status} detail={result.sample_detail} report={result.report_path.relative_to(ROOT)} log={result.transcript_path.relative_to(ROOT)}",
                flush=True,
            )
            if result.returncode != 0 or result.sample_status != "PASS":
                failures += 1

    if failures:
        print(f"[parallel-ltp] failures={failures}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
