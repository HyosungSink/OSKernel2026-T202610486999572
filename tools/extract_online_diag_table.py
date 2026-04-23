#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


ONLINE_DIAG_RE = re.compile(
    r"\[online-diag\] kind=(?P<kind>\S+) phase=(?P<phase>\S+) name=(?P<name>\S+) "
    r"seq=(?P<seq>\d+) now_ms=(?P<now_ms>\d+) "
    r"available_pages=(?P<available_pages>\d+).*?"
    r"live_tasks=(?P<live_tasks>\d+).*?"
    r"live_exited_tasks=(?P<live_exited_tasks>\d+).*?"
    r"process_leaders=(?P<process_leaders>\d+).*?"
    r"zombie_processes=(?P<zombie_processes>\d+).*?"
    r"script_tagged_tasks=(?P<script_tagged_tasks>\d+).*?"
    r"script_tagged_exited_tasks=(?P<script_tagged_exited_tasks>\d+)"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    log_path = Path(args.log)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "lineno\tkind\tphase\tname\tseq\tnow_ms\tavailable_pages\tlive_tasks\tlive_exited_tasks\tprocess_leaders\tzombie_processes\tscript_tagged_tasks\tscript_tagged_exited_tasks"
    ]
    with log_path.open(encoding="utf-8", errors="replace") as file:
        for lineno, line in enumerate(file, 1):
            match = ONLINE_DIAG_RE.search(line)
            if not match:
                continue
            item = match.groupdict()
            lines.append(
                "\t".join(
                    [
                        str(lineno),
                        item["kind"],
                        item["phase"],
                        item["name"],
                        item["seq"],
                        item["now_ms"],
                        item["available_pages"],
                        item["live_tasks"],
                        item["live_exited_tasks"],
                        item["process_leaders"],
                        item["zombie_processes"],
                        item["script_tagged_tasks"],
                        item["script_tagged_exited_tasks"],
                    ]
                )
            )

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
