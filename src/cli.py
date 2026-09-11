"""Offline CLI for synthetic web security assessments."""
from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import load_assessment
from .report import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic OWASP lab evidence")
    parser.add_argument("input", help="Path to assessment JSON")
    parser.add_argument("--report", help="Optional Markdown output path")
    args = parser.parse_args()

    assessment = load_assessment(args.input)
    output = render_markdown(assessment)
    if args.report:
        Path(args.report).write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
