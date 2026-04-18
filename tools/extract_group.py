#!/usr/bin/env python3

import re
import sys

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def sanitize_line(raw: str) -> str:
    line = raw.rstrip("\n")
    line = line.rstrip("\r")
    return ANSI_ESCAPE_RE.sub("", line)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extract_group.py <group> <log>", file=sys.stderr)
        return 2

    group = sys.argv[1]
    path = sys.argv[2]
    start = f"#### OS COMP TEST GROUP START {group} ####"
    end = f"#### OS COMP TEST GROUP END {group} ####"

    inside = False
    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
        for raw in fp:
            line = sanitize_line(raw)
            if not inside:
                if start in line:
                    inside = True
                continue
            if end in line:
                return 0
            print(line)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
