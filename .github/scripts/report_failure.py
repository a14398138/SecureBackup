#!/usr/bin/env python3
"""Extract the actionable error from a Gradle build log and surface it as
GitHub Actions annotations + step summary, so the failure cause is visible
from the API (annotations) without opening the raw log."""
import os
import re
import sys

LOG = "build.log"


def sanitize(s: str) -> str:
    # workflow commands treat some characters specially; keep annotations safe
    return s.replace("\r", "").strip()[:700]


def main() -> int:
    try:
        log = open(LOG, encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"::error::could not read build.log ({e})")
        return 1

    out = []

    # 1) Gradle's "What went wrong:" section (most actionable)
    m = re.search(r"What went wrong:\r?\n(.*?)(?:\r?\n\r?\n\* Try:|\Z)", log, re.S)
    if m:
        out.append(m.group(1).strip())

    # 2) error-ish lines anywhere (AAPT/kotlinc/javac messages)
    err_lines = [
        ln for ln in log.splitlines()
        if re.search(r"\berror:|\bFAILED\b|Caused by:|Execution failed", ln)
    ]
    if err_lines:
        out.append("\n".join(err_lines[:40]))

    if not out:
        out.append(log[-1500:])

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    emitted = 0
    for section in out:
        for line in section.splitlines():
            line = sanitize(line)
            if not line:
                continue
            if emitted < 20:
                print(f"::error title=Build failure::{line}")
                emitted += 1
            if summary_path:
                with open(summary_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")

    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("\n<details><summary>build.log tail</summary>\n\n```\n"
                    + log[-4000:] + "\n```\n</details>\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
